import pytest

from app.api.tenant import _validate_webhook_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/hook",
        "https://user:pass@example.com/hook",
        "https://localhost/hook",
        "http://127.0.0.1/hook",
        "http://10.0.0.10/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/hook",
    ],
)
def test_webhook_destination_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        _validate_webhook_url(url)


def test_webhook_destination_accepts_public_https_host():
    assert (
        _validate_webhook_url("https://hooks.example.com/agent")
        == "https://hooks.example.com/agent"
    )
