"""
HTML + plaintext email templates. Dark + minimal to match the dashboard.
Inline styles only — email clients strip <style> blocks.
"""

from __future__ import annotations


_BASE_STYLE = (
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
    "'Helvetica Neue',Arial,sans-serif;"
)


def _shell(title: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#000000;{_BASE_STYLE}">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="background:#000000;padding:40px 20px;">
    <tr><td align="center">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0"
             style="background:#0a0a0a;border:1px solid rgba(16,185,129,0.2);max-width:520px;">
        <tr><td style="padding:28px 32px 12px 32px;">
          <div style="color:#10b981;font-size:11px;letter-spacing:0.28em;
                      text-transform:uppercase;font-weight:600;">
            AGENTSHIELD
          </div>
          <div style="color:#475569;font-size:9px;letter-spacing:0.3em;
                      text-transform:uppercase;margin-top:2px;">
            Autonomous Agent Firewall
          </div>
        </td></tr>
        <tr><td style="padding:8px 32px 32px 32px;">
          <h1 style="color:#e2e8f0;font-size:18px;font-weight:600;margin:16px 0 14px 0;
                     letter-spacing:0.02em;">
            {title}
          </h1>
          {body_html}
        </td></tr>
        <tr><td style="padding:0 32px 28px 32px;border-top:1px solid rgba(16,185,129,0.1);">
          <div style="color:#475569;font-size:10px;line-height:1.6;padding-top:16px;">
            If you didn't request this, you can safely ignore this email.
            Your account is unchanged.
          </div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _button(url: str, label: str) -> str:
    return (
        f'<a href="{url}" '
        f'style="display:inline-block;background:rgba(16,185,129,0.15);'
        f'border:1px solid rgba(16,185,129,0.6);color:#34d399;'
        f'padding:12px 24px;text-decoration:none;font-size:12px;'
        f'letter-spacing:0.2em;text-transform:uppercase;font-weight:600;'
        f'margin:8px 0 16px 0;">{label}</a>'
    )


def _link_fallback(url: str) -> str:
    return (
        f'<div style="color:#64748b;font-size:10px;line-height:1.6;'
        f'word-break:break-all;margin-top:8px;">'
        f'Or paste this link into your browser:<br>'
        f'<span style="color:#94a3b8;">{url}</span></div>'
    )


def password_reset_email(name: str, reset_url: str) -> tuple[str, str]:
    title = "Reset your password"
    body_html = f"""
      <p style="color:#94a3b8;font-size:13px;line-height:1.7;margin:0 0 12px 0;">
        Hi {name or "there"},
      </p>
      <p style="color:#94a3b8;font-size:13px;line-height:1.7;margin:0 0 20px 0;">
        Someone requested a password reset for your AgentShield account.
        Click the button below to choose a new password. This link expires
        in 30 minutes and can only be used once.
      </p>
      {_button(reset_url, "Reset Password")}
      {_link_fallback(reset_url)}
    """
    html = _shell(title, body_html)
    text = (
        f"Hi {name or 'there'},\n\n"
        f"Reset your AgentShield password by opening this link:\n\n"
        f"{reset_url}\n\n"
        f"This link expires in 30 minutes and can only be used once.\n\n"
        f"If you didn't request this, ignore this email."
    )
    return html, text


def email_verification_email(name: str, verify_url: str) -> tuple[str, str]:
    title = "Verify your email"
    body_html = f"""
      <p style="color:#94a3b8;font-size:13px;line-height:1.7;margin:0 0 12px 0;">
        Hi {name or "there"},
      </p>
      <p style="color:#94a3b8;font-size:13px;line-height:1.7;margin:0 0 20px 0;">
        Welcome to AgentShield. Confirm your email to unlock the full
        dashboard — audit exports, webhook notifications, and policy sync.
        This link expires in 24 hours.
      </p>
      {_button(verify_url, "Verify Email")}
      {_link_fallback(verify_url)}
    """
    html = _shell(title, body_html)
    text = (
        f"Hi {name or 'there'},\n\n"
        f"Welcome to AgentShield. Verify your email:\n\n"
        f"{verify_url}\n\n"
        f"This link expires in 24 hours."
    )
    return html, text