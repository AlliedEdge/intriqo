"""Resend email delivery and branded account email templates."""

from __future__ import annotations

import html
import logging

import httpx

from intriqo.config import get_settings

logger = logging.getLogger("intriqo.auth.email")

RESEND_API_URL = "https://api.resend.com/emails"

# ---------------------------------------------------------------------------
# Inline SVG logo — rendered in every email client without external hosting
# ---------------------------------------------------------------------------
_LOGO_SVG = """
<svg width="36" height="36" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle;">
  <rect width="36" height="36" rx="7" fill="#10bbe0" fill-opacity="0.15"/>
  <path d="M18 7L29 13V23C29 27.4 24.9 31.1 18 33C11.1 31.1 7 27.4 7 23V13L18 7Z"
        stroke="#10bbe0" stroke-width="1.8" stroke-linejoin="round" fill="none"/>
  <path d="M14 18L16.5 20.5L22 15" stroke="#10bbe0" stroke-width="1.8"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""


def _base_template(
    *,
    preheader: str,
    header_label: str,
    hero_icon_svg: str,
    heading: str,
    subheading: str,
    body_paragraphs: list[str],
    action_label: str,
    action_url: str,
    action_sublabel: str,
    expiry_note: str,
    security_note: str,
    accent: str = "#10bbe0",
) -> str:
    """Master layout — every email type is a call to this function."""

    safe_url = html.escape(action_url, quote=True)
    safe_action_label = html.escape(action_label)
    safe_expiry = html.escape(expiry_note)
    safe_security = html.escape(security_note)
    safe_heading = html.escape(heading)
    safe_subheading = html.escape(subheading)
    safe_preheader = html.escape(preheader)
    safe_header_label = html.escape(header_label)
    safe_action_sublabel = html.escape(action_sublabel)

    body_html = "".join(
        f'<p style="margin:0 0 14px 0;font-size:15px;line-height:1.65;color:#a6b8c2;">{html.escape(p)}</p>'
        for p in body_paragraphs
    )

    year = "2026"

    return f"""<!doctype html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>{safe_heading} — Intriqo</title>
  <!--[if mso]><noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript><![endif]-->
</head>
<body style="margin:0;padding:0;background:#030810;font-family:'Segoe UI',Arial,sans-serif;-webkit-font-smoothing:antialiased;">

  <!-- Preheader (hidden) -->
  <div style="display:none;max-height:0;overflow:hidden;color:#030810;font-size:1px;">{safe_preheader}&nbsp;&#8205;&#8205;&#8205;&#8205;&#8205;&#8205;</div>

  <!-- Outer wrapper -->
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#030810;">
    <tr><td align="center" style="padding:40px 16px 24px;">

      <!-- Card -->
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:580px;">

        <!-- ── TOP NAV BAR ── -->
        <tr>
          <td style="background:#07101c;border:1px solid #1c303d;border-bottom:none;border-radius:10px 10px 0 0;padding:18px 32px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td>
                  {_LOGO_SVG}
                  <span style="display:inline-block;vertical-align:middle;margin-left:10px;font-size:15px;font-weight:800;letter-spacing:4px;color:#ebebed;">INTRIQO</span>
                </td>
                <td align="right">
                  <span style="display:inline-block;padding:3px 10px;border:1px solid #1c303d;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:2px;color:{accent};background:rgba(16,187,224,0.07);">{safe_header_label}</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── HERO ACCENT LINE ── -->
        <tr>
          <td style="background:linear-gradient(90deg,{accent} 0%,#0a7a98 60%,transparent 100%);height:2px;border-left:1px solid #1c303d;border-right:1px solid #1c303d;"></td>
        </tr>

        <!-- ── HERO SECTION ── -->
        <tr>
          <td style="background:linear-gradient(160deg,#0b1825 0%,#07101c 100%);border-left:1px solid #1c303d;border-right:1px solid #1c303d;padding:40px 32px 32px;text-align:center;">

            <!-- Icon badge -->
            <div style="display:inline-block;width:64px;height:64px;border-radius:16px;background:rgba(16,187,224,0.1);border:1px solid rgba(16,187,224,0.3);line-height:64px;text-align:center;margin-bottom:22px;">
              {hero_icon_svg}
            </div>

            <h1 style="margin:0 0 10px;font-size:26px;font-weight:700;color:#ebebed;letter-spacing:-0.5px;line-height:1.2;">{safe_heading}</h1>
            <p style="margin:0;font-size:15px;color:#74829a;line-height:1.5;">{safe_subheading}</p>
          </td>
        </tr>

        <!-- ── BODY SECTION ── -->
        <tr>
          <td style="background:#0b121a;border-left:1px solid #1c303d;border-right:1px solid #1c303d;padding:32px 32px 24px;">
            {body_html}

            <!-- CTA Button -->
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:28px 0 8px;">
              <tr>
                <td style="border-radius:6px;background:{accent};">
                  <a href="{safe_url}" style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:700;color:#031117;text-decoration:none;border-radius:6px;letter-spacing:0.2px;">{safe_action_label}</a>
                </td>
              </tr>
            </table>
            <p style="margin:8px 0 0;font-size:12px;color:#6e8490;">{safe_action_sublabel}</p>
          </td>
        </tr>

        <!-- ── EXPIRY NOTE ── -->
        <tr>
          <td style="background:#080f16;border-left:1px solid #1c303d;border-right:1px solid #1c303d;padding:18px 32px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td width="20" valign="top" style="padding-top:1px;">
                  <div style="width:16px;height:16px;border-radius:50%;background:rgba(16,187,224,0.12);border:1px solid rgba(16,187,224,0.28);text-align:center;line-height:14px;">
                    <span style="font-size:9px;color:{accent};font-weight:700;">i</span>
                  </div>
                </td>
                <td style="padding-left:10px;font-size:13px;color:#6e8490;line-height:1.55;">{safe_expiry}</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── FALLBACK LINK ── -->
        <tr>
          <td style="background:#080f16;border-left:1px solid #1c303d;border-right:1px solid #1c303d;padding:0 32px 24px;">
            <p style="margin:0;font-size:12px;color:#6e8490;line-height:1.6;">
              Button not working? Copy this link into your browser:<br>
              <a href="{safe_url}" style="color:{accent};word-break:break-all;font-size:11px;">{safe_url}</a>
            </p>
          </td>
        </tr>

        <!-- ── DIVIDER ── -->
        <tr>
          <td style="background:#080f16;border-left:1px solid #1c303d;border-right:1px solid #1c303d;padding:0 32px;">
            <div style="height:1px;background:#1c303d;"></div>
          </td>
        </tr>

        <!-- ── SECURITY NOTE ── -->
        <tr>
          <td style="background:#080f16;border-left:1px solid #1c303d;border-right:1px solid #1c303d;padding:20px 32px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td width="20" valign="top" style="padding-top:1px;">
                  <div style="width:16px;height:16px;border-radius:50%;background:rgba(255,82,82,0.08);border:1px solid rgba(255,82,82,0.2);text-align:center;line-height:14px;">
                    <span style="font-size:9px;color:#ff8585;font-weight:700;">!</span>
                  </div>
                </td>
                <td style="padding-left:10px;font-size:12px;color:#6e8490;line-height:1.55;">{safe_security}</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── FOOTER ── -->
        <tr>
          <td style="background:#040b14;border:1px solid #1c303d;border-top:none;border-radius:0 0 10px 10px;padding:24px 32px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td>
                  <p style="margin:0 0 6px;font-size:12px;font-weight:700;letter-spacing:3px;color:#2a4657;">INTRIQO</p>
                  <p style="margin:0;font-size:11px;color:#2a4657;line-height:1.6;">
                    Security Operations Platform &nbsp;·&nbsp; AI-Powered Threat Intelligence<br>
                    This is an automated message — please do not reply to this email.
                  </p>
                </td>
                <td align="right" valign="top">
                  <p style="margin:0;font-size:11px;color:#2a4657;">&copy; {year} Intriqo</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── BOTTOM SPACER ── -->
        <tr><td style="height:24px;"></td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Hero icons — inline SVG per email type
# ---------------------------------------------------------------------------
_ICON_SHIELD_CHECK = """<svg width="28" height="28" viewBox="0 0 24 24" fill="none"
  xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle;">
  <path d="M12 3L20 6V11C20 16 16.6 19.6 12 21C7.4 19.6 4 16 4 11V6L12 3Z"
        stroke="#10bbe0" stroke-width="1.6" stroke-linejoin="round"/>
  <path d="M9 12L11 14L15 10" stroke="#10bbe0" stroke-width="1.6"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

_ICON_LOCK_RESET = """<svg width="28" height="28" viewBox="0 0 24 24" fill="none"
  xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle;">
  <path d="M7 11V8a5 5 0 0 1 9.9-1" stroke="#10bbe0" stroke-width="1.6"
        stroke-linecap="round"/>
  <rect x="4" y="11" width="16" height="10" rx="2"
        stroke="#10bbe0" stroke-width="1.6"/>
  <path d="M12 15v2" stroke="#10bbe0" stroke-width="1.6" stroke-linecap="round"/>
  <path d="M18 5l2 2-2 2" stroke="#10bbe0" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""


def verification_email_html(
    username: str, verification_url: str, expiration_minutes: int = 60
) -> str:
    """High-quality branded email verification message."""
    return _base_template(
        preheader=f"Hi {username}, confirm your email to activate your Intriqo account.",
        header_label="ACCOUNT SETUP",
        hero_icon_svg=_ICON_SHIELD_CHECK,
        heading="Verify your email address",
        subheading="One step away from your Security Operations Platform",
        body_paragraphs=[
            f"Hi {username},",
            "To finish setting up your Intriqo account, we need to confirm this email address belongs to you. "
            "Click the button below — it takes less than a second.",
            "Once verified, you'll have full access to the control plane, threat intelligence feeds, "
            "and AI-powered investigation workflows.",
        ],
        action_label="Verify my email address",
        action_url=verification_url,
        action_sublabel=f"This button will open a secure page on the Intriqo platform.",
        expiry_note=f"This verification link expires in {expiration_minutes} minutes and can only be used once. "
                    f"If it expires, you can request a new one from the login page.",
        security_note=(
            "If you did not create an Intriqo account, no action is required — this email can be safely ignored. "
            "Intriqo will never ask for your password, credit card, or personal information by email."
        ),
    )


def password_reset_email_html(
    username: str, reset_url: str, expiration_minutes: int = 30
) -> str:
    """High-quality branded password reset message."""
    return _base_template(
        preheader=f"Hi {username}, a password reset was requested for your Intriqo account.",
        header_label="SECURITY ALERT",
        hero_icon_svg=_ICON_LOCK_RESET,
        heading="Reset your password",
        subheading="A request was made to change your Intriqo account password",
        body_paragraphs=[
            f"Hi {username},",
            "We received a request to reset the password associated with this email address. "
            "If this was you, click the button below to choose a new password.",
            "For your protection, this link will expire soon and can only be used once. "
            "After resetting, you'll be signed out of all active sessions.",
        ],
        action_label="Reset my password",
        action_url=reset_url,
        action_sublabel="You'll be taken to a secure page to choose a new password.",
        expiry_note=f"This reset link expires in {expiration_minutes} minutes and is single-use only. "
                    f"If it has expired, visit the login page and request a new one.",
        security_note=(
            "If you did not request a password reset, your account may be at risk. "
            "Please ignore this email — your current password will remain unchanged. "
            "Consider enabling additional security measures on your account."
        ),
        accent="#10bbe0",
    )


async def send_email(*, recipient: str, subject: str, html_body: str) -> bool:
    """Send an email through Resend, or safely no-op when unconfigured."""
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
