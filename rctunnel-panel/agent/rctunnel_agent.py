"""rctunnel-agent — supervisor over the rctunnel-engine client (rctc).

Lifecycle (SPEC §4, §13):
  1. Enroll: generate keypair locally, send CSR + bootstrap token over public
     HTTPS, receive signed agent cert + CA cert. Private key never leaves this host.
     The cert auto-renews before expiry.
  2. Connect to the master control plane over mTLS WebSocket (client cert auth).
  3. Receive desired config, render rctc.json (resolving 'auto' localIP locally),
     (re)start/reload the rctc subprocess, report APPLIED, heartbeat.
  4. Reconnect with backoff. Update itself via OTA when the panel publishes a newer version.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import hashlib
import logging
import os
import platform
import re
import shutil
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from localip import resolve

log = logging.getLogger("rctunnel_panel-agent")

AGENT_VERSION = "0.9.0"   # bump on every agent change → triggers OTA on older agents

HEARTBEAT_SECS = 15
WATCHDOG_SECS = 10
RECONNECT_MAX = 30
CERT_RENEW_DAYS = 30      # renew the agent mTLS cert this long before it expires
CERT_CHECK_SECS = 12 * 3600
_SAFE_ARTIFACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")   # no '/', '\', or '..' traversal


def _vtuple(s: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in str(s).split("."))
    except ValueError:
        return (0,)


class Agent:
    def __init__(self, args: argparse.Namespace) -> None:
        self.master_url = args.master_url.rstrip("/")
        self.token = args.token
        self.work = Path(args.work_dir).expanduser()
        self.work.mkdir(parents=True, exist_ok=True)
        self.rctc_bin = args.rctc
        self.control_url = args.control_url or self._derive_control_url(args.control_port)
        self.proc: subprocess.Popen | None = None
        self.last_generation = -1
        # cert material paths
        self.key_path = self.work / "agent.key"
        self.crt_path = self.work / "agent.crt"
        self.ca_path = self.work / "ca.crt"
        self.rctc_json = self.work / "rctc.json"
        self._active_cfg = self.rctc_json
        self.node: dict | None = None
        self._lock = asyncio.Lock()   # serialize rctc (re)starts across apply + watchdog
        self._upgraded = False
        self._artifacts: dict = {}       # trusted SHA-256 of /dl files, from the mTLS welcome
        self._renew_key: bytes | None = None   # staged key for an in-flight cert renewal
        self._ca_refresh_tried = False   # guard: re-enroll once per process on a TLS verify failure
        self.install_dir = Path(__file__).resolve().parent   # where agent code lives (OTA target)

    def _derive_control_url(self, control_port: int) -> str:
        host = urlparse(self.master_url).hostname
        return f"wss://{host}:{control_port}/agent-ws"

    # -- enrollment ---------------------------------------------------------

    def _cert_days_left(self) -> int | None:
        """Days until the local agent cert expires, or None if unreadable."""
        try:
            crt = x509.load_pem_x509_certificate(self.crt_path.read_bytes())
            return (crt.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days
        except Exception:  # noqa: BLE001
            return None

    def ensure_enrolled(self) -> None:
        # The bootstrap token is single-use (first enrollment only). If we already
        # hold a cert we never touch the token again — renewal happens over the
        # mTLS control plane, even if the cert is close to expiry.
        if self.crt_path.exists() and self.key_path.exists() and self.ca_path.exists():
            left = self._cert_days_left()
            self._load_cached_node()
            if left is not None and left <= CERT_RENEW_DAYS:
                log.info("agent cert expires in %s days — will renew over the control plane", left)
            else:
                log.info("already enrolled (cert valid %s more days)", left)
            return
        self._enroll()

    def _enroll(self) -> None:
        """First-time enrollment: generate a key+CSR and sign it with the panel CA
        via the single-use bootstrap token. The server assigns the identity (CN
        agent.<id>); the token is burned after this. Renewals use _request_renew."""
        log.info("enrolling with master ...")
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
            .sign(key, hashes.SHA256())
        )
        payload = json.dumps({
            "bootstrap_token": self.token,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "os": platform.system().lower(),
            "arch": platform.machine().lower(),
        }).encode()
        req = urllib.request.Request(
            f"{self.master_url}/api/agents/enroll", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:  # system CA verifies LE cert
            data = json.load(resp)

        self.key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        self.crt_path.write_text(data["agent_cert_pem"])
        self.ca_path.write_text(data["ca_cert_pem"])
        self.node = data["node"] | {"token": data.get("node_token")}
        (self.work / "node.json").write_text(json.dumps(self.node))
        log.info("enrolled as agent.%s", data["agent_id"])

    async def _renew_loop(self, ws) -> None:
        """Over the live mTLS link, ask for a fresh cert before expiry — no token."""
        while True:
            await asyncio.sleep(CERT_CHECK_SECS)
            await self._maybe_request_renew(ws)

    async def _maybe_request_renew(self, ws) -> None:
        left = self._cert_days_left()
        if (left is not None and left > CERT_RENEW_DAYS) or self._renew_key is not None:
            return
        log.info("cert expires in %s days — requesting renewal over the control plane", left)
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
               .sign(key, hashes.SHA256()))
        # stage the new key in memory; only written if/when the signed cert arrives
        self._renew_key = key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
        await ws.send(json.dumps({"type": "renew",
                                  "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}))

    def _install_renewed(self, msg: dict) -> None:
        if not self._renew_key:
            return
        self.key_path.write_bytes(self._renew_key)
        self.key_path.chmod(0o600)
        self.crt_path.write_text(msg["agent_cert_pem"])
        if msg.get("ca_cert_pem"):
            self.ca_path.write_text(msg["ca_cert_pem"])
        self._renew_key = None
        log.info("cert renewed over control plane; restarting to load it")
        self.shutdown()
        os.execv(sys.executable, [sys.executable] + sys.argv)

    def _load_cached_node(self) -> None:
        p = self.work / "node.json"
        if p.exists():
            self.node = json.loads(p.read_text())

    # -- mTLS connection ----------------------------------------------------

    def _client_ssl(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(self.crt_path, self.key_path)
        ctx.load_verify_locations(self.ca_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    async def run(self) -> None:
        self.ensure_enrolled()
        asyncio.create_task(self._watchdog())   # keep rctc alive regardless of control link
        # cert renewal now happens over the live mTLS link (see _renew_loop in _session)
        backoff = 1
        while True:
            try:
                await self._session()
                backoff = 1
            except Exception as e:  # noqa: BLE001
                # A TLS verify failure means our cached CA no longer matches the
                # server's cert (e.g. the panel's PKI was reset). Re-enroll once to
                # pull the current CA + cert, then restart so the data plane (rctc)
                # reloads them too. Bad/expired token -> _enroll raises, we keep retrying.
                if self._is_cert_verify_error(e) and not self._ca_refresh_tried:
                    self._ca_refresh_tried = True
                    log.warning("control TLS verify failed — re-enrolling to refresh cert/CA")
                    try:
                        self._enroll()
                        log.info("re-enrolled; restarting to load new cert/CA")
                        self.shutdown()
                        await asyncio.sleep(1)
                        os.execv(sys.executable, [sys.executable] + sys.argv)
                    except Exception as ee:  # noqa: BLE001
                        log.warning("re-enroll failed: %s; will keep retrying", ee)
                log.warning("control connection lost: %s; retrying in %ss", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX)

    @staticmethod
    def _is_cert_verify_error(e: BaseException) -> bool:
        return isinstance(e, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(e)

    async def _session(self) -> None:
        host = urlparse(self.control_url).hostname
        async with websockets.connect(self.control_url, ssl=self._client_ssl(), server_hostname=host) as ws:
            log.info("connected to control plane")
            self._ca_refresh_tried = False   # healthy link: allow a future CA refresh if it breaks again
            # healthy boot: clear the crash-loop counter so normal restarts/OTAs
            # never trigger a rollback (only a never-connecting loop does).
            try:
                (self.install_dir / ".boot_attempts").unlink()
            except Exception:  # noqa: BLE001
                pass
            await ws.send(json.dumps({
                "type": "hello",
                "os": platform.system().lower(),
                "arch": platform.machine().lower(),
                "agent_version": AGENT_VERSION,
                "detected_ip": resolve("auto"),
            }))
            await self._maybe_request_renew(ws)   # renew now if the cert is already near expiry
            hb = asyncio.create_task(self._heartbeat(ws))
            rn = asyncio.create_task(self._renew_loop(ws))
            try:
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("type") == "config":
                        await self._apply_config(ws, msg)
                    elif msg.get("type") == "renewed":
                        self._install_renewed(msg)
                    elif msg.get("type") == "welcome":
                        self.node = msg.get("node", self.node)
                        if isinstance(msg.get("artifacts"), dict):
                            self._artifacts = msg["artifacts"]   # trusted SHA-256 of /dl files
                    elif msg.get("type") == "upgrade":
                        self._self_upgrade(msg)
            finally:
                hb.cancel()
                rn.cancel()

    @staticmethod
    def _fetch_retry(url: str, tries: int = 3) -> bytes:
        """Download with bounded retry; logs the exact URL on each failure so a
        transient 404/network blip is diagnosable and doesn't kill the upgrade."""
        last: Exception | None = None
        for i in range(tries):
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    data = r.read()
                if not data:
                    raise ValueError("empty response")
                return data
            except Exception as e:  # noqa: BLE001
                last = e
                log.warning("OTA: fetch %s failed (attempt %d/%d): %s", url, i + 1, tries, e)
                time.sleep(1.5 * (i + 1))
        raise last if last else RuntimeError("download failed")

    def _self_upgrade(self, msg: dict) -> None:
        """OTA: fetch newer agent code, verify its SHA-256 against the trusted
        (mTLS-delivered) manifest, then atomically swap (keeping a .bak for
        rollback) and re-exec. Any download/verify failure leaves us untouched."""
        if self._upgraded:
            return
        target = msg.get("version", "")
        if _vtuple(target) <= _vtuple(AGENT_VERSION):
            return
        # Always fetch from our own configured master, never a URL from the message,
        # and only fetch simple filenames (no path traversal into the install dir).
        base = f"{self.master_url}/dl"
        files = msg.get("files") or ["rctunnel_agent.py", "localip.py"]
        hashes = msg.get("sha256") or {}
        log.info("OTA: upgrading %s -> %s", AGENT_VERSION, target)
        staged: dict[str, bytes] = {}
        try:
            for f in files:
                if not _SAFE_ARTIFACT.match(f):
                    raise ValueError(f"unsafe artifact name: {f!r}")
                want = hashes.get(f)
                if not want:
                    raise ValueError(f"no trusted hash for {f} — refusing OTA")
                data = self._fetch_retry(f"{base}/{f}")
                if hashlib.sha256(data).hexdigest() != want:
                    raise ValueError(f"hash mismatch for {f} — refusing OTA")
                if f.endswith(".py"):
                    compile(data, f, "exec")           # refuse to install broken code
                staged[f] = data
        except Exception as e:  # noqa: BLE001
            log.warning("OTA aborted (download/verify failed: %s); staying on %s", e, AGENT_VERSION)
            return
        for f, data in staged.items():
            dest = self.install_dir / f
            if dest.exists():
                try:
                    shutil.copy2(dest, dest.with_name(dest.name + ".bak"))  # rollback copy
                except Exception:  # noqa: BLE001
                    pass
            tmp = dest.with_name(dest.name + ".new")
            tmp.write_bytes(data)
            os.replace(tmp, dest)                       # atomic swap
        self._upgraded = True
        log.info("OTA: installed %s; restarting", target)
        self.shutdown()                                 # stop engine child (avoid orphan)
        os.execv(sys.executable, [sys.executable] + sys.argv)  # re-exec into new code

    async def _heartbeat(self, ws) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_SECS)
            # include cert lifetime + current LAN IP so the panel reflects an IP
            # change live (without waiting for a reconnect)
            await ws.send(json.dumps({"type": "heartbeat",
                                      "cert_days_left": self._cert_days_left(),
                                      "detected_ip": resolve("auto")}))

    async def _watchdog(self) -> None:
        """Restart rctc if it has exited (crash or node restart)."""
        while True:
            await asyncio.sleep(WATCHDOG_SECS)
            async with self._lock:
                if self.proc is not None and self.proc.poll() is not None and self._active_cfg.exists():
                    log.warning("watchdog: engine exited (code %s); restarting", self.proc.returncode)
                    self._restart_engine()

    # -- desired-state application -----------------------------------------

    async def _apply_config(self, ws, msg: dict) -> None:
        gen = msg.get("generation", -1)
        node = msg.get("node") or self.node
        tunnels, visitors = msg.get("tunnels", []), msg.get("visitors", [])
        cfg = self._render_rctc(node, tunnels, msg.get("grant", ""))
        changed = (not self.rctc_json.exists()) or self.rctc_json.read_text() != cfg
        self.rctc_json.write_text(cfg)
        self.rctc_json.chmod(0o600)   # holds the node token + grant — keep it root-only
        async with self._lock:
            if self.proc is None or self.proc.poll() is not None:
                self._restart_engine()
            elif changed:
                # graceful reload — don't drop existing tunnels for one proxy change
                self._reload_engine()
        self.last_generation = gen
        await ws.send(json.dumps({
            "type": "applied", "generation": gen, "engine": "rctunnel",
            "ok": True, "rctc_pid": self.proc.pid if self.proc else None,
        }))
        log.info("applied generation %s (%d tunnels, %d visitors)", gen, len(tunnels), len(visitors))

    def _render_rctc(self, node: dict, tunnels: list[dict], grant: str = "") -> str:
        """Render the rctc JSON config (our own engine). Only tcp/udp/http/https
        are supported; other proxy types are skipped."""
        proxies = []
        for t in tunnels:
            typ = t["type"]
            if typ not in ("tcp", "udp", "http", "https"):
                continue
            spec = {
                "name": t.get("proxy_name") or t["name"],
                "type": typ,
                "localAddr": f'{resolve(t.get("local_ip", "auto"))}:{t["local_port"]}',
            }
            if typ in ("tcp", "udp") and t.get("remote_port"):
                spec["remotePort"] = t["remote_port"]
            if typ in ("http", "https"):
                if t.get("custom_domains"):
                    spec["customDomains"] = [d.strip() for d in t["custom_domains"].split(",") if d.strip()]
                if t.get("subdomain"):
                    spec["subdomain"] = t["subdomain"]
            proxies.append(spec)
        cfg = {
            "controlAddr": f'{node["server_addr"]}:{node["server_port"]}',
            "workConnAddr": f'{node["server_addr"]}:{node.get("workconn_port", 7001)}',
            "token": node.get("token"),
            "grant": grant,
            "ca": str(self.ca_path),
            "cert": str(self.crt_path),
            "key": str(self.key_path),
            "serverName": node["server_addr"],
            "proxies": proxies,
        }
        return json.dumps(cfg, indent=2) + "\n"

    def _ensure_rctc(self) -> None:
        """Ensure a current rctc engine client exists locally. The binary is
        version-pinned to AGENT_VERSION (marker file): re-downloaded from /dl
        whenever the agent upgrades, so OTA also refreshes the engine client."""
        target = self.work / "rctc"
        marker = self.work / "rctc.version"
        have = marker.read_text().strip() if marker.exists() else ""
        if target.exists() and have == AGENT_VERSION:
            self.rctc_bin = str(target)
            return
        m = platform.machine().lower()
        arch = "arm64" if m in ("aarch64", "arm64") else "amd64"
        name = f"rctc-{arch}"
        url = f"{self.master_url}/dl/{name}"
        try:
            # Fail closed: require a trusted (mTLS-delivered) hash before installing a
            # native binary. Without one, keep whatever binary we already have.
            want = self._artifacts.get(name)
            if not want:
                raise ValueError(f"no trusted hash for {name} — refusing to (re)install")
            with urllib.request.urlopen(url, timeout=60) as r:  # system CA verifies LE cert
                data = r.read()
            if hashlib.sha256(data).hexdigest() != want:
                raise ValueError("rctc hash mismatch — refusing to install")
            target.write_bytes(data)
            target.chmod(0o755)
            marker.write_text(AGENT_VERSION)
            self.rctc_bin = str(target)
            log.info("fetched rctc %s (%d bytes, verified) -> %s", AGENT_VERSION, len(data), target)
        except Exception as e:  # noqa: BLE001
            log.error("failed to fetch rctc: %s", e)
            if target.exists():
                self.rctc_bin = str(target)  # fall back to whatever we have

    def _restart_engine(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._ensure_rctc()
        log.info("starting rctc")
        self.proc = subprocess.Popen([self.rctc_bin, "-config", str(self.rctc_json)])

    def _reload_engine(self) -> None:
        """Graceful reload: signal rctc to re-read its config (SIGHUP) so it
        re-syncs proxies without dropping existing tunnels."""
        try:
            self.proc.send_signal(signal.SIGHUP)
            log.info("reloaded rctc (SIGHUP)")
        except Exception as e:  # noqa: BLE001
            log.warning("reload failed (%s); restarting", e)
            self._restart_engine()

    def shutdown(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="rctunnel-agent")
    p.add_argument("--master-url", default=os.environ.get("RCTUNNEL_MASTER_URL", "https://rc-tunnel.com"))
    p.add_argument("--token", default=os.environ.get("RCTUNNEL_AGENT_TOKEN", ""))
    p.add_argument("--work-dir", default=os.environ.get("RCTUNNEL_AGENT_DIR", "~/.rctunnel"))
    # accepted but ignored — kept so already-deployed systemd units that still
    # pass --frpc (from older installers) don't crash the agent on startup.
    p.add_argument("--frpc", default=None, help=argparse.SUPPRESS)
    p.add_argument("--rctc", default=os.environ.get("RCTUNNEL_RCTC", "rctc"))
    p.add_argument("--control-url", default=os.environ.get("RCTUNNEL_CONTROL_URL", ""))
    p.add_argument("--control-port", type=int, default=int(os.environ.get("RCTUNNEL_CONTROL_PORT", "8001")))
    return p.parse_args()


async def _amain(agent: Agent) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    runner = asyncio.create_task(agent.run())
    done, _ = await asyncio.wait({runner, asyncio.create_task(stop.wait())},
                                 return_when=asyncio.FIRST_COMPLETED)
    runner.cancel()
    try:
        await runner
    except asyncio.CancelledError:
        pass


def _boot_guard() -> None:
    """Crash-loop rollback. Runs FIRST, before arg parsing, so even a startup
    crash is recovered: if the process has (re)started too many times in a short
    window and OTA .bak files exist, restore the previous code and re-exec into
    it. The marker is cleared once the agent successfully connects (in _session),
    so normal restarts/upgrades never trip it — only a real crash-loop does."""
    install_dir = Path(__file__).resolve().parent
    marker = install_dir / ".boot_attempts"
    now = time.time()
    try:
        attempts = [float(x) for x in marker.read_text().split()]
    except Exception:  # noqa: BLE001
        attempts = []
    attempts = [t for t in attempts if now - t < 120][-10:] + [now]
    baks = list(install_dir.glob("*.bak"))
    if len(attempts) >= 5 and baks:
        log.error("crash-loop detected (%d boots/120s) — rolling back OTA", len(attempts))
        for bak in baks:
            try:
                if bak.name.endswith(".py.bak"):
                    compile(bak.read_bytes(), bak.name, "exec")   # don't restore a corrupt .bak
                shutil.copy2(bak, bak.with_suffix(""))   # foo.py.bak -> foo.py
            except Exception:  # noqa: BLE001
                pass
        try:
            marker.unlink()
        except Exception:  # noqa: BLE001
            pass
        os.execv(sys.executable, [sys.executable] + sys.argv)
    try:
        marker.write_text(" ".join(str(t) for t in attempts))
    except Exception:  # noqa: BLE001
        pass


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _boot_guard()
    agent = Agent(parse_args())
    try:
        asyncio.run(_amain(agent))
    finally:
        agent.shutdown()


if __name__ == "__main__":
    main()
