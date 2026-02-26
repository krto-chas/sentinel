"""
alerts.py – Alerting vid säkerhetshändelser i Sentinel Upload API.

Stöder två kanaler (kan kombineras):
  - Slack/Teams/valfri webhook via ALERT_WEBHOOK_URL
  - E-post via SMTP (ALERT_SMTP_* miljövariabler)

Aktiveras när en uppladdning får:
  - scan_status = "malicious"
  - decision    = "rejected"
  - risk_score  >= ALERT_RISK_THRESHOLD (default 70)

Miljövariabler:
  ALERT_WEBHOOK_URL          – URL att POST:a JSON-payload till (Slack/Teams/custom)
  ALERT_RISK_THRESHOLD       – Minsta risk_score som triggar alert (default 70)
  ALERT_SMTP_HOST            – SMTP-server (t.ex. smtp.gmail.com)
  ALERT_SMTP_PORT            – SMTP-port (default 587)
  ALERT_SMTP_USER            – SMTP-användarnamn
  ALERT_SMTP_PASSWORD        – SMTP-lösenord
  ALERT_SMTP_FROM            – Avsändaradress
  ALERT_SMTP_TO              – Mottagaradress (kommaseparerat för flera)
  ALERT_ENV_NAME             – Miljönamn som visas i alertet (default "production")
"""

import asyncio
import json
import logging
import os
import smtplib
from email.mime.text import MIMEText
from urllib import request as urllib_request

logger = logging.getLogger("sentinel.alerts")

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
ALERT_RISK_THRESHOLD = int(os.getenv("ALERT_RISK_THRESHOLD", "70"))
ALERT_ENV_NAME = os.getenv("ALERT_ENV_NAME", "production")

_SMTP_HOST = os.getenv("ALERT_SMTP_HOST", "").strip()
_SMTP_PORT = int(os.getenv("ALERT_SMTP_PORT", "587"))
_SMTP_USER = os.getenv("ALERT_SMTP_USER", "").strip()
_SMTP_PASSWORD = os.getenv("ALERT_SMTP_PASSWORD", "").strip()
_SMTP_FROM = os.getenv("ALERT_SMTP_FROM", "").strip()
_SMTP_TO_RAW = os.getenv("ALERT_SMTP_TO", "").strip()
_SMTP_TO = [addr.strip() for addr in _SMTP_TO_RAW.split(",") if addr.strip()]


def _should_alert(scan_status: str, decision: str, risk_score: int) -> bool:
    """Avgör om en uppladdning ska trigga ett alert."""
    return (
        scan_status == "malicious"
        or decision == "rejected"
        or risk_score >= ALERT_RISK_THRESHOLD
    )


def _build_payload(
    filename: str,
    sha256: str,
    scan_status: str,
    scan_engine: str,
    scan_detail: str,
    decision: str,
    risk_score: int,
    risk_reasons: list[str],
    user_id: str,
    client_ip: str,
) -> dict:
    """Bygg en strukturerad payload för webhook och e-post."""
    return {
        "env": ALERT_ENV_NAME,
        "event": "upload_alert",
        "severity": "critical" if scan_status == "malicious" else "high",
        "filename": filename,
        "sha256": sha256,
        "scan_status": scan_status,
        "scan_engine": scan_engine,
        "scan_detail": scan_detail,
        "decision": decision,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "user_id": user_id,
        "client_ip": client_ip,
    }


def _send_webhook(payload: dict) -> None:
    """Synkron webhook-avsändning (körs i en tråd via asyncio.to_thread)."""
    if not ALERT_WEBHOOK_URL:
        return
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(
            ALERT_WEBHOOK_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=5) as resp:
            logger.info("Alert webhook delivered, status=%s", resp.status)
    except Exception as exc:
        logger.error("Alert webhook failed: %s", exc)


def _send_email(payload: dict) -> None:
    """Synkron e-postavsändning (körs i en tråd via asyncio.to_thread)."""
    if not (_SMTP_HOST and _SMTP_FROM and _SMTP_TO):
        return
    try:
        subject = (
            f"[Sentinel/{ALERT_ENV_NAME}] "
            f"{payload['severity'].upper()} – {payload['filename']} "
            f"({payload['scan_status']}, score={payload['risk_score']})"
        )
        body_lines = [
            f"Miljö:        {payload['env']}",
            f"Fil:          {payload['filename']}",
            f"SHA-256:      {payload['sha256']}",
            f"Scan-status:  {payload['scan_status']}",
            f"Scan-motor:   {payload['scan_engine']}",
            f"Scan-detalj:  {payload['scan_detail']}",
            f"Decision:     {payload['decision']}",
            f"Risk score:   {payload['risk_score']}",
            f"Riskorsaker:  {', '.join(payload['risk_reasons'])}",
            f"Användare:    {payload['user_id']}",
            f"Klient-IP:    {payload['client_ip']}",
        ]
        msg = MIMEText("\n".join(body_lines), "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = _SMTP_FROM
        msg["To"] = ", ".join(_SMTP_TO)

        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            if _SMTP_USER and _SMTP_PASSWORD:
                server.login(_SMTP_USER, _SMTP_PASSWORD)
            server.sendmail(_SMTP_FROM, _SMTP_TO, msg.as_string())
        logger.info("Alert e-post skickad till %s", _SMTP_TO)
    except Exception as exc:
        logger.error("Alert e-post misslyckades: %s", exc)


async def maybe_send_alert(
    filename: str,
    sha256: str,
    scan_status: str,
    scan_engine: str,
    scan_detail: str,
    decision: str,
    risk_score: int,
    risk_reasons: list[str],
    user_id: str = "anonymous",
    client_ip: str = "unknown",
) -> None:
    """
    Asynkron ingångspunkt som anropas från upload-endpointen.
    Skickar alert om tröskeln uppnås, annars är det en no-op.
    Fel i alerting ska aldrig blockera upload-svaret.
    """
    if not _should_alert(scan_status, decision, risk_score):
        return

    payload = _build_payload(
        filename=filename,
        sha256=sha256,
        scan_status=scan_status,
        scan_engine=scan_engine,
        scan_detail=scan_detail,
        decision=decision,
        risk_score=risk_score,
        risk_reasons=risk_reasons,
        user_id=user_id,
        client_ip=client_ip,
    )

    logger.warning(
        "ALERT triggered: file=%s decision=%s score=%d scan_status=%s user=%s ip=%s",
        filename, decision, risk_score, scan_status, user_id, client_ip,
    )

    # Kör webhook och e-post parallellt i bakgrundstrådar
    # so att de inte blockerar request-hanteringen
    tasks = []
    if ALERT_WEBHOOK_URL:
        tasks.append(asyncio.to_thread(_send_webhook, payload))
    if _SMTP_HOST and _SMTP_FROM and _SMTP_TO:
        tasks.append(asyncio.to_thread(_send_email, payload))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.error("Alert delivery error: %s", result)