"""Populate the /dl directory: agent code + installer + OTA manifest.

    python -m scripts.publish [--dir DIR]

The rctc engine binary is built from the rctunnel-engine repo and copied into
the same dir separately (it is not part of this Python package).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

from rctunnel_panel.config import get_settings

REPO = Path(__file__).resolve().parent.parent


def main() -> None:
    s = get_settings()
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=s.download_dir)
    args = ap.parse_args()

    dest = Path(args.dir)
    dest.mkdir(parents=True, exist_ok=True)

    for name, src in [
        ("rctunnel_agent.py", REPO / "agent" / "rctunnel_agent.py"),
        ("localip.py", REPO / "agent" / "localip.py"),
        ("install.sh", REPO / "deploy" / "install.sh"),
    ]:
        shutil.copy2(src, dest / name)
        print(f"[publish] copied {name}")

    # manifest for OTA: the version + files agents compare against / fetch
    src = (REPO / "agent" / "rctunnel_agent.py").read_text()
    m = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', src)
    version = m.group(1) if m else "0.0.0"
    # SHA-256 of every published artifact (agent code + rctc binaries). The panel
    # ships these hashes to agents over the authenticated mTLS control channel, so
    # an agent can verify a /dl download even if that HTTPS leg is tampered with.
    sha256 = {}
    for p in sorted(dest.iterdir()):
        if p.is_file() and p.name != "manifest.json":
            sha256[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    # Agents fail closed when a hash is missing, so a published rctc with no hash
    # would simply never (re)install. Warn loudly if the binaries aren't here yet.
    if not any(n.startswith("rctc-") for n in sha256):
        print("[publish] WARNING: no rctc-<arch> binary in the dir — agents can't verify/update "
              "the engine client until you copy it in and re-run publish.")
    (dest / "manifest.json").write_text(json.dumps(
        {"agent_version": version, "files": ["rctunnel_agent.py", "localip.py"], "sha256": sha256}))
    print(f"[publish] manifest agent_version={version} ({len(sha256)} hashed artifacts)")
    print(f"[publish] done -> {dest}")


if __name__ == "__main__":
    main()
