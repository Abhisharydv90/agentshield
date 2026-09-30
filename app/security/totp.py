"""
TOTP (Time-based One-Time Password) authentication.

Compatible with Google Authenticator, Authy, 1Password, and any RFC 6238 client.
"""

from __future__ import annotations

import base64
import io
import secrets

import pyotp
import qrcode


def generate_secret() -> str:
    """Return a base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str, issuer: str = "AgentShield") -> str:
    """Return the otpauth:// URI that authenticator apps scan."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def qr_code_data_url(uri: str) -> str:
    """Return a base64 data URL of the QR code for the URI."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit code with a ±30 second window."""
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)
    except Exception:
        return False


def generate_recovery_codes(count: int = 8) -> list[str]:
    """Generate one-time recovery codes."""
    return [secrets.token_hex(5).upper() for _ in range(count)]