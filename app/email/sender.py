"""
Email sender — Resend in prod, console print in dev.

If RESEND_API_KEY is unset, print the email to the backend console and
pretend it succeeded. This lets the whole flow be tested without an email
account, and a missing key degrades gracefully instead of silently failing.
"""

from __future__ import annotations

import logging

from app.config import settings

log = logging.getLogger("agentshield.email")


def send_email(
    to: str,
    subject: str,
    html: str,
    text: str | None = None,
) -> bool:
    """
    Send an email. Returns True on success (or dev fallback), False on hard
    failure. Never raises — auth flows must not fail if email fails.
    """
    if not settings.RESEND_API_KEY:
        log.warning("RESEND_API_KEY unset — printing email instead")
        print(
            "\n" + "=" * 68 + "\n"
            f"[DEV EMAIL] to={to}\n"
            f"[DEV EMAIL] subject={subject}\n"
            f"[DEV EMAIL] body:\n{text or html}\n"
            + "=" * 68 + "\n"
        )
        return True

    try:
        import resend

        resend.api_key = settings.RESEND_API_KEY
        resend.Emails.send({
            "from": settings.RESEND_FROM,
            "to": to,
            "subject": subject,
            "html": html,
            "text": text or "",
        })
        log.info("Email sent · to=%s · subject=%s", to, subject)
        return True
    except Exception as e:
        log.exception("Email send failed · to=%s · %s", to, e)
        return False