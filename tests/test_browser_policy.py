"""Browser navigation security regression coverage."""

from app.tools.browser.policy import BrowserPolicy


def test_browser_blocks_localhost_by_default():
    decision = BrowserPolicy().authorize_navigation("https://localhost/")
    assert not decision.allowed
    assert decision.reason == "private_or_local_ip_blocked"


def test_browser_blocks_legacy_numeric_loopback():
    for host in ("2130706433", "0x7f000001"):
        decision = BrowserPolicy().authorize_navigation(f"https://{host}/")
        assert not decision.allowed
        assert decision.reason == "private_or_local_ip_blocked"


def test_browser_blocks_link_local_metadata_address():
    decision = BrowserPolicy().authorize_navigation(
        "http://169.254.169.254/latest/meta-data/"
    )
    assert not decision.allowed


def test_browser_private_ip_override_is_explicit():
    policy = BrowserPolicy(
        allow_http=True,
        allow_private_ips=True,
    )
    decision = policy.authorize_navigation("http://127.0.0.1/")
    assert decision.allowed
