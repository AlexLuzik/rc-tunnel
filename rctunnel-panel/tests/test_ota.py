"""OTA: master decides to upgrade old agents; agent self-updates + re-execs."""

import asyncio
import hashlib
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

    files = ["rctunnel_agent.py", "localip.py"]
    sha = {f: hashlib.sha256((srcdir / f).read_bytes()).hexdigest() for f in files}

    ag = A.Agent.__new__(A.Agent)
    ag.master_url = "https://rc-tunnel.com"
    ag._upgraded = False
    ag._artifacts = {}
    ag.install_dir = install
    ag.shutdown = lambda: None
    # stub the download: serve the staged src files by name (OS-independent)
    ag._fetch_retry = lambda url, tries=3: (srcdir / url.rsplit("/", 1)[1]).read_bytes()

    execd = {}
    def fake_execv(exe, argv):
        execd["exe"], execd["argv"] = exe, argv
        raise SystemExit("re-exec")
    A.os.execv = fake_execv

    try:
        # base_url in the message is IGNORED now (anti-redirect); hashes are required
        ag._self_upgrade({"version": "99.0.0", "base_url": "file:///evil",
                          "files": files, "sha256": sha})
    except SystemExit:
        pass

    # files replaced with the fetched code + execv attempted
    assert 'AGENT_VERSION' in (install / "rctunnel_agent.py").read_text()
    assert "resolve" in (install / "localip.py").read_text()   # real localip, not the old stub
    assert execd.get("exe") == sys.executable
    assert ag._upgraded

    # integrity: a wrong/absent hash must abort the upgrade, leaving files untouched
    ag._upgraded = False
    execd.clear()
    (install / "localip.py").write_text("# untouched\n")
    ag._self_upgrade({"version": "99.0.0", "files": files,
                      "sha256": {**sha, "localip.py": "deadbeef"}})
    assert not execd and not ag._upgraded
    assert (install / "localip.py").read_text() == "# untouched\n"
    # missing hash entirely → also refused
    ag._self_upgrade({"version": "99.0.0", "files": files, "sha256": {}})
    assert not execd

    # path-traversal filename is rejected
    ag._self_upgrade({"version": "99.0.0", "files": ["../evil.py"], "sha256": {"../evil.py": "x"}})
    assert not execd

    # no-op guard: target not newer than current does nothing
    ag._upgraded = False
    execd.clear()
    ag._self_upgrade({"version": "0.0.1"})
    assert not execd
    print("agent self-upgrade OK")


if __name__ == "__main__":
    test_master_decides_upgrade()
    test_agent_self_upgrade()
    print("OTA OK")
