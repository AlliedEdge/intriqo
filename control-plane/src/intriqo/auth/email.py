"""Resend email delivery and branded account email templates."""

from __future__ import annotations

import html
import logging

import httpx

from intriqo.config import get_settings

logger = logging.getLogger("intriqo.auth.email")

RESEND_API_URL = "https://api.resend.com/emails"


def _brand_page(
    title: str,
    heading: str,
    body: str,
    action_label: str,
    action_url: str,
    expiration_minutes: int,
) -> str:
    """Render a small, accessible branded HTML email."""
    safe_title = html.escape(title)
    safe_heading = html.escape(heading)
    safe_body = html.escape(body)
    safe_label = html.escape(action_label)
    safe_url = html.escape(action_url, quote=True)
    expiry = html.escape(f"This link expires in {expiration_minutes} minutes and can only be used once.")
    return f"""<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{safe_title}</title>
  </head>
  <body style="margin:0;background:#05090f;font-family:Arial,sans-serif;color:#ebebed;">
    <div style="max-width:560px;margin:40px auto;padding:34px;background:#0b121a;border:1px solid #1c303d;border-radius:8px;">
      <div style="font-weight:800;font-size:21px;letter-spacing:4px;color:#10bbe0;margin-bottom:30px;">INTRIQO</div>
      <div style="height:2px;background:#10bbe0;margin-bottom:26px;"></div>
      <h1 style="font-size:24px;line-height:1.2;margin:0 0 16px;color:#ebebed;">{safe_heading}</h1>
      <p style="font-size:16px;line-height:1.6;color:#a6b8c2;">{safe_body}</p>
      <p style="margin:28px 0;"><a href="{safe_url}" style="display:inline-block;padding:13px 20px;background:#10bbe0;color:#031117;text-decoration:none;border-radius:4px;font-weight:700;">{safe_label}</a></p>
      <p style="font-size:13px;line-height:1.5;color:#a6b8c2;">{expiry}</p>
      <p style="font-size:12px;line-height:1.6;color:#6e8490;word-break:break-all;">If the button does not work, copy this link into your browser:<br>{safe_url}</p>
      <div style="height:1px;background:#1c303d;margin:24px 0;"></div>
      <p style="font-size:12px;line-height:1.5;color:#6e8490;">Security notice: if you did not request this email, you can safely ignore it. Intriqo will never ask for your password by email.</p>
    </div>
  </body>
</html>"""


def verification_email_html(username: str, verification_url: str, expiration_minutes: int = 60) -> str:
    """Build the email verification message without exposing secrets in logs."""
    return _brand_page(
        "Verify your Intriqo email",
        "Verify your email address",
        f"Hi {username}, confirm your email address to finish setting up your Intriqo account.",
        "Verify email",
        verification_url,
        expiration_minutes,
    )


def password_reset_email_html(username: str, reset_url: str, expiration_minutes: int = 30) -> str:
    """Build the password reset message without exposing secrets in logs."""
    return _brand_page(
        "Reset your Intriqo password",
        "Reset your password",
        f"Hi {username}, use the button below to choose a new password for your Intriqo account.",
        "Reset password",
        reset_url,
        expiration_minutes,
    )


async def send_email(*, recipient: str, subject: str, html_body: str) -> bool:
    """Send an email through Resend, or safely no-op when unconfigured.

    The caller receives ``False`` when delivery is intentionally skipped.  A
    provider failure raises so application services can decide whether the
    primary account operation should remain successful.
    """
    settings = get_settings()
    if not settings.resend_api_key or not settings.resend_api_key.get_secret_value():
        logger.info("Transactional email skipped because RESEND_API_KEY is not configured")
        return False

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            RESEND_API_URL,
            headers={
                "Authorization": f"Bearer {settings.resend_api_key.get_secret_value()}",
                "Content-Type": "application/json",
            },
            json={
                "from": settings.resend_from_email,
                "to": [recipient],
                "subject": subject,
                "html": html_body,
            },
        )
        response.raise_for_status()
    return True
