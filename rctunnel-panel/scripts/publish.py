"""Populate the /dl directory: agent code + installer + OTA manifest.

    python -m scripts.publish [--dir DIR]

The rctc engine binary is built from the rctunnel-engine repo and copied into
the same dir separately (it is not part of this Python package).
"""

from __future__ import annotations

import argparse
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
    (dest / "manifest.json").write_text(json.dumps(
        {"agent_version": version, "files": ["rctunnel_agent.py", "localip.py"]}))
    print(f"[publish] manifest agent_version={version}")
    print(f"[publish] done -> {dest}")


if __name__ == "__main__":
    main()
