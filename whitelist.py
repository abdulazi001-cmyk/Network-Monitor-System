"""
whitelist.py — إدارة قائمة الأجهزة الموثوقة
Trusted Devices Whitelist Manager
"""

import json
import os

WHITELIST_FILE = os.path.join(os.path.dirname(__file__), "whitelist.json")


def _load() -> dict:
    """تحميل الـ whitelist من الملف."""
    if not os.path.exists(WHITELIST_FILE):
        return {}
    with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict) -> None:
    """حفظ الـ whitelist في الملف."""
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_all() -> dict:
    """إرجاع جميع الأجهزة الموثوقة {MAC: label}."""
    return _load()


def add(mac: str, label: str = "") -> None:
    """إضافة جهاز إلى الـ whitelist."""
    data = _load()
    data[mac.upper()] = label or mac
    _save(data)


def remove(mac: str) -> bool:
    """حذف جهاز من الـ whitelist. يُرجع True إن وُجد."""
    data = _load()
    mac = mac.upper()
    if mac in data:
        del data[mac]
        _save(data)
        return True
    return False


def is_trusted(mac: str) -> bool:
    """التحقق إن كان الجهاز في الـ whitelist."""
    return mac.upper() in _load()


def classify(devices: list[dict]) -> list[dict]:
    """
    تصنيف الأجهزة إلى موثوقة وغير موثوقة.
    يُضيف حقلَي  trusted: bool  و  label: str  لكل جهاز.
    """
    wl = _load()
    result = []
    for d in devices:
        mac = d["mac"].upper()
        trusted = mac in wl
        result.append({
            **d,
            "trusted": trusted,
            "label":   wl.get(mac, ""),
            "status":  "trusted" if trusted else "unknown",
        })
    return result
