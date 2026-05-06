"""
alerts.py — وحدة التنبيهات والسجلات
Alerts & Logging Module
"""

import json
import os
import datetime

ALERTS_FILE = os.path.join(os.path.dirname(__file__), "alerts.json")
MAX_ALERTS  = 200   # الحد الأقصى للتنبيهات المحفوظة


def _load() -> list:
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: list) -> None:
    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data[-MAX_ALERTS:], f, ensure_ascii=False, indent=2)


def create_alerts(unknown_devices: list[dict], scan_result: dict) -> list[dict]:
    """
    إنشاء تنبيهات للأجهزة غير المعروفة وحفظها.
    يُرجع قائمة التنبيهات الجديدة.
    """
    if not unknown_devices:
        return []

    existing = _load()
    new_alerts = []

    for device in unknown_devices:
        alert = {
            "id":         len(existing) + len(new_alerts) + 1,
            "timestamp":  datetime.datetime.now().isoformat(timespec="seconds"),
            "ip":         device["ip"],
            "mac":        device["mac"],
            "network":    scan_result.get("network", ""),
            "severity":   "warning",
            "message":    f"جهاز غير معروف تم اكتشافه: {device['ip']} ({device['mac']})",
            "acknowledged": False,
        }
        new_alerts.append(alert)

    _save(existing + new_alerts)
    return new_alerts


def get_all(limit: int = 50) -> list:
    """جلب آخر `limit` تنبيه مرتبة من الأحدث للأقدم."""
    alerts = _load()
    return list(reversed(alerts))[:limit]


def acknowledge(alert_id: int) -> bool:
    """تأكيد قراءة تنبيه معين."""
    alerts = _load()
    for a in alerts:
        if a["id"] == alert_id:
            a["acknowledged"] = True
            _save(alerts)
            return True
    return False


def unread_count() -> int:
    """عدد التنبيهات غير المقروءة."""
    return sum(1 for a in _load() if not a.get("acknowledged"))
