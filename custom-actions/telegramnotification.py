#!/usr/bin/env python3
"""
QRadar Custom Action — Telegram Alert Notification
====================================================
Параметры Custom Action (добавить в UI):
  - bot_token     : string  : Токен Telegram-бота
  - chat_id       : string  : ID чата
  - offense_id    : number  : $offenseId
  - offense_desc  : string  : $offenseDescription
  - src_ip        : string  : $sourceIP
  - severity      : string  : $offenseSeverity
  - rule_name     : string  : $ruleName
  - magnitude     : number  : $magnitude
"""

import sys
import json
import urllib.request
import urllib.error
from datetime import datetime

TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"

QRADAR_CONSOLE_URL = "https://16.16.213.68"

SEVERITY_EMOJI = {
    "1": "🟢", "2": "🟢", "3": "🟡",
    "4": "🟡", "5": "🟠", "6": "🟠",
    "7": "🔴", "8": "🔴", "9": "🔴", "10": "🔴"
}

WINDOWS_RULE_CATEGORIES = {
    "Failed Logon Attempt": "Authentication Failure",
    "Successful RDP Logon": "Remote Access",
    "Special Privileges Assigned": "Privilege Escalation",
    "New Local User Created": "Account Creation",
    "User Added To Privileged Group": "Privilege Escalation",
    "Windows Event Log Cleared": "Defense Evasion",
    "Scheduled Task Created": "Persistence",
    "New Service Installed": "Persistence",
    "Suspicious PowerShell Execution": "Command Execution",
    "Suspicious LOLBins Execution": "Living Off The Land"
}


def get_rule_tag(rule_name: str) -> str:
    for key, value in WINDOWS_RULE_CATEGORIES.items():
        if key in rule_name:
            return f"#{key.replace(' ', '_')} — {value}"
    return "#Windows_Unknown"


def format_severity_bar(magnitude: int) -> str:
    filled = min(magnitude, 10)
    return "█" * filled + "░" * (10 - filled)


def build_message(params: dict) -> str:
    offense_id  = params.get("offense_id", "N/A")
    description = params.get("offense_desc", "No description")
    src_ip      = params.get("src_ip", "Unknown")
    severity    = params.get("severity", "5")
    rule_name   = params.get("rule_name", "Unknown Rule")
    timestamp   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        magnitude = int(str(params.get("magnitude", "5")).strip())
    except ValueError:
        magnitude = 5

    sev_emoji   = SEVERITY_EMOJI.get(str(severity).strip(), "🔴")
    rule_tag    = get_rule_tag(rule_name)
    mag_bar     = format_severity_bar(magnitude)
    offense_url = (
        f"{QRADAR_CONSOLE_URL}/console/do/sem/offensesummary"
        f"?appName=Sem&pageId=OffenseSummary&summaryId={offense_id}"
    )

    message = (
        f"{sev_emoji} <b>QRADAR OFFENSE ALERT</b> {sev_emoji}\n"
        f"{'─' * 30}\n\n"
        f"🆔 <b>Offense ID:</b> <code>{offense_id}</code>\n"
        f"📋 <b>Rule:</b> {rule_name}\n"
        f"🏷 <b>Category:</b> {rule_tag}\n\n"
        f"📝 <b>Description:</b>\n"
        f"{description[:300]}{'...' if len(description) > 300 else ''}\n\n"
        f"🌐 <b>Source IP:</b> <code>{src_ip}</code>\n"
        f"⚡ <b>Severity:</b> {severity}/10\n"
        f"📊 <b>Magnitude:</b> [{mag_bar}] {magnitude}/10\n"
        f"🕐 <b>Time:</b> {timestamp}\n\n"
        f'🔗 <a href="{offense_url}">Open in QRadar</a>'
    )
    return message


def send_telegram(bot_token: str, chat_id: str, message: str) -> dict:
    url = TELEGRAM_API_URL.format(token=bot_token)
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        print(f"[ERROR] Telegram HTTP {e.code}: {error_body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[ERROR] Cannot reach Telegram: {e.reason}", file=sys.stderr)
        sys.exit(1)


def main():
    params = {}
    for arg in sys.argv[1:]:
        if "=" in arg:
            key, _, val = arg.partition("=")
            params[key.strip()] = val.strip()

    bot_token = params.get("bot_token", "").strip()
    chat_id   = params.get("chat_id", "").strip()

    if not bot_token or not chat_id:
        print("[ERROR] bot_token and chat_id are required.", file=sys.stderr)
        sys.exit(1)

    message = build_message(params)
    result  = send_telegram(bot_token, chat_id, message)

    if result.get("ok"):
        print(f"[OK] Sent. Message ID: {result['result']['message_id']}")
    else:
        print(f"[ERROR] Telegram error: {result}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
