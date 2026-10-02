from app.config import settings
from app.middleware.ratelimit import _client_ip


def test_forwarded_client_ip_is_not_trusted_from_unknown_peer(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")
    scope = {"client": ("192.168.1.20", 12345)}
    headers = {"x-agentshield-client-ip": "203.0.113.9"}
    assert _client_ip(scope, headers) == "192.168.1.20"


def test_forwarded_client_ip_is_trusted_from_configured_proxy(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")
    scope = {"client": ("10.1.2.3", 12345)}
    headers = {"x-agentshield-client-ip": "203.0.113.9"}
    assert _client_ip(scope, headers) == "203.0.113.9"
