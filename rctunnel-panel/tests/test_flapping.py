"""Flapping detection raises a (rate-limited) audit alert on frequent reconnects."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "F" * 40

from rctunnel_panel.control import server as S  # noqa: E402


def test_flapping():
    aid = 4242
    S._flap_hist.pop(aid, None)
    S._flap_last_alert.pop(aid, None)

    # under the threshold -> no alert
    for _ in range(S._FLAP_MAX):
        S._note_connect(aid, "edge", None)
    assert aid not in S._flap_last_alert, "must not alert below threshold"

    # crossing the threshold -> exactly one alert (rate-limited afterwards)
    S._note_connect(aid, "edge", None)
    assert aid in S._flap_last_alert
    first = S._flap_last_alert[aid]
    for _ in range(5):
        S._note_connect(aid, "edge", None)
    assert S._flap_last_alert[aid] == first, "alert must be rate-limited (cooldown)"

    print("FLAPPING OK")


if __name__ == "__main__":
    test_flapping()
