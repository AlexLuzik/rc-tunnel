"""Internal PKI (SPEC §13). Standard X.509 / mTLS.

The master runs its own CA. It issues:
  * a server certificate for the mTLS control listener (EKU serverAuth);
  * agent certificates by signing CSRs the agents generate locally (EKU clientAuth).

Agent private keys never leave the agent — only the CSR (public key) is sent.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CA_VALID_DAYS = 3650
_SERVER_VALID_DAYS = 825
_RENEW_BEFORE_DAYS = 30   # re-issue the server cert this long before it expires


def cert_days_left(crt_path: Path) -> int | None:
    """Days until the cert at crt_path expires, or None if it can't be read."""
    try:
        crt = x509.load_pem_x509_certificate(crt_path.read_bytes())
    except Exception:  # noqa: BLE001
        return None
    return (crt.not_valid_after_utc - _utcnow()).days


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for n in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            entries.append(x509.DNSName(n))
    return x509.SubjectAlternativeName(entries)


def _write(path: Path, data: bytes, *, private: bool) -> None:
    path.write_bytes(data)
    path.chmod(0o600 if private else 0o644)


# --------------------------------------------------------------------------- CA


class CA:
    """Loads (or creates) the panel CA and issues certificates."""

    def __init__(self, pki_dir: str | Path) -> None:
        self.dir = Path(pki_dir)
        self.ca_key_path = self.dir / "ca.key"
        self.ca_crt_path = self.dir / "ca.crt"
        self._key: ec.EllipticCurvePrivateKey | None = None
        self._crt: x509.Certificate | None = None

    # -- bootstrap ----------------------------------------------------------

    def ensure(self) -> None:
        """Create the CA on first run; load it otherwise (idempotent)."""
        self.dir.mkdir(parents=True, exist_ok=True)
        if self.ca_key_path.exists() and self.ca_crt_path.exists():
            self._load()
            return
        self._create()

    def _create(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RC-Tunnel Root CA")])
        now = _utcnow()
        crt = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=_CA_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        _write(self.ca_key_path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ), private=True)
        _write(self.ca_crt_path, crt.public_bytes(serialization.Encoding.PEM), private=False)
        self._key, self._crt = key, crt

    def _load(self) -> None:
        self._key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        self._crt = x509.load_pem_x509_certificate(self.ca_crt_path.read_bytes())

    @property
    def cert_pem(self) -> bytes:
        assert self._crt is not None
        return self._crt.public_bytes(serialization.Encoding.PEM)

    # -- issuance -----------------------------------------------------------

    def sign_csr(self, csr_pem: bytes, *, identity: str, days: int, client: bool) -> bytes:
        """Sign an agent/server CSR. Identity overrides subject CN and SAN.

        Returns the signed certificate as PEM. The CSR's public key is used as-is;
        its private key never touches the master.
        """
        assert self._key is not None and self._crt is not None
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("CSR self-signature invalid")
        eku = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        now = _utcnow()
        crt = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)]))
            .issuer_name(self._crt.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_san([identity]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        return crt.public_bytes(serialization.Encoding.PEM)

    def ensure_server_cert(self, sans: list[str]) -> tuple[Path, Path]:
        """Issue/renew the control-listener server cert+key. Re-issues when the
        existing cert is missing or within _RENEW_BEFORE_DAYS of expiry, so the
        mTLS server cert rotates automatically. Returns (crt, key) paths."""
        crt_path, key_path = self.dir / "server.crt", self.dir / "server.key"
        if crt_path.exists() and key_path.exists():
            left = cert_days_left(crt_path)
            if left is not None and left > _RENEW_BEFORE_DAYS:
                return crt_path, key_path  # still fresh
        assert self._key is not None and self._crt is not None
        key = ec.generate_private_key(ec.SECP256R1())
        now = _utcnow()
        crt = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
            .issuer_name(self._crt.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=_SERVER_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_san(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        _write(key_path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ), private=True)
        _write(crt_path, crt.public_bytes(serialization.Encoding.PEM), private=False)
        return crt_path, key_path
