"""Webhook destination hardening tests."""

from app.api import tenant as tenant_api


def test_production_webhooks_require_https(monkeypatch):
    monkeypatch.setattr(tenant_api._settings, "ENV", "prod")

    try:
        try:
            tenant_api._validate_webhook_url("http://hooks.example.com/callback")
        except ValueError as exc:
            assert str(exc) == "webhook_url_https_required_in_prod"
        else:
            raise AssertionError("production webhook URL must require HTTPS")
    finally:
        monkeypatch.setattr(tenant_api._settings, "ENV", "dev")
