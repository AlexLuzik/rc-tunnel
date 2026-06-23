"""OTA: master decides to upgrade old agents; agent self-updates + re-execs."""

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

DL = tempfile.mkdtemp()
os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "o" * 40
os.environ["RCTUNNEL_DOWNLOAD_DIR"] = DL
os.environ["RCTUNNEL_PUBLIC_BASE_URL"] = "https://rc-tunnel.com"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

REPO = Path(__file__).resolve().parent.parent


def test_master_decides_upgrade():
    # publish manifest with current agent version
    Path(DL, "manifest.json").write_text(json.dumps({"agent_version": "0.2.0", "files": ["rctunnel_agent.py"]}))
    from rctunnel_panel.control.server import _maybe_upgrade

    sent = []
    async def send(m): sent.append(m)

    asyncio.run(_maybe_upgrade(send, {"agent_version": "0.1.0"}))
    assert sent and sent[0]["type"] == "upgrade" and sent[0]["version"] == "0.2.0"
    assert sent[0]["base_url"] == "https://rc-tunnel.com/dl"

    sent.clear()
    asyncio.run(_maybe_upgrade(send, {"agent_version": "0.2.0"}))   # already current
    assert not sent
    print("master decision OK")


def test_agent_self_upgrade():
    import rctunnel_agent as A

    install = Path(tempfile.mkdtemp())
    (install / "rctunnel_agent.py").write_text('AGENT_VERSION = "0.1.0"\n')   # old code
    (install / "localip.py").write_text("# old\n")

    # source of new files (valid python = the real repo files, version 0.2.0)
    srcdir = Path(tempfile.mkdtemp())
    shutil.copy2(REPO / "agent" / "rctunnel_agent.py", srcdir / "rctunnel_agent.py")
    shutil.copy2(REPO / "agent" / "localip.py", srcdir / "localip.py")

    ag = A.Agent.__new__(A.Agent)
    ag.master_url = "https://rc-tunnel.com"
    ag._upgraded = False
    ag.install_dir = install
    ag.shutdown = lambda: None

    execd = {}
    def fake_execv(exe, argv):
        execd["exe"], execd["argv"] = exe, argv
        raise SystemExit("re-exec")
    A.os.execv = fake_execv

    try:
        # target far above the running AGENT_VERSION → upgrade proceeds regardless
        # of the current version (robust to future bumps)
        ag._self_upgrade({"version": "99.0.0", "base_url": f"file://{srcdir}",
                          "files": ["rctunnel_agent.py", "localip.py"]})
    except SystemExit:
        pass

    # files replaced with the fetched code + execv attempted
    assert 'AGENT_VERSION' in (install / "rctunnel_agent.py").read_text()
    assert "resolve" in (install / "localip.py").read_text()   # real localip, not the old stub
    assert execd.get("exe") == sys.executable
    assert ag._upgraded

    # no-op guard: target not newer than current does nothing
    ag._upgraded = False
    execd.clear()
    ag._self_upgrade({"version": "0.0.1", "base_url": f"file://{srcdir}"})
    assert not execd
    print("agent self-upgrade OK")


if __name__ == "__main__":
    test_master_decides_upgrade()
    test_agent_self_upgrade()
    print("OTA OK")
