"""
scanner.py — وحدة فحص الشبكة
Network Scanner Module using Scapy (ARP ping)
"""

import subprocess
import socket
import re
import datetime
import platform

# ── محاولة استيراد Scapy؛ إن لم تكن متاحة نستخدم fallback ──────────────────
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _arp_scan_scapy(network: str) -> list[dict]:
    """فحص الشبكة باستخدام Scapy."""
    arp    = ARP(pdst=network)
    ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for _, received in result:
        devices.append({
            "ip":  received.psrc,
            "mac": received.hwsrc.upper(),
        })
    return devices


def _arp_scan_fallback(network: str) -> list[dict]:
    """
    Fallback: يقرأ جدول ARP من نظام التشغيل.
    يعمل بدون صلاحيات root لكنه يعرض الأجهزة التي سبق التواصل معها فقط.
    """
    devices = []
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("arp -a", shell=True).decode()
            for line in out.splitlines():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]{17})", line
                )
                if m:
                    devices.append({
                        "ip":  m.group(1),
                        "mac": m.group(2).upper().replace("-", ":"),
                    })
        else:
            out = subprocess.check_output(["arp", "-n"], stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and ":" in parts[2]:
                    devices.append({
                        "ip":  parts[0],
                        "mac": parts[2].upper(),
                    })
    except Exception:
        pass
    return devices


def get_local_ip() -> str:
    """الحصول على عنوان IP المحلي للجهاز الحالي."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_default_network() -> str:
    """استنتاج نطاق الشبكة من IP المحلي."""
    ip = get_local_ip()
    parts = ip.rsplit(".", 1)
    return f"{parts[0]}.0/24"


def scan(network: str | None = None) -> dict:
    """
    نقطة الدخول الرئيسية للفحص.

    Returns:
        {
            "network": str,
            "scanned_at": str (ISO timestamp),
            "method": "scapy" | "arp_table",
            "devices": [{"ip": str, "mac": str}]
        }
    """
    if network is None:
        network = get_default_network()

    method = "scapy" if SCAPY_AVAILABLE else "arp_table"

    if SCAPY_AVAILABLE:
        try:
            devices = _arp_scan_scapy(network)
        except PermissionError:
            # Scapy تحتاج root — نتراجع للـ fallback
            method = "arp_table"
            devices = _arp_scan_fallback(network)
    else:
        devices = _arp_scan_fallback(network)

    return {
        "network":    network,
        "scanned_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "method":     method,
        "devices":    devices,
    }
