"""
app.py — نقطة الدخول الرئيسية للتطبيق
Flask Web Application Entry Point
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
import scanner
import whitelist
import alerts as alerts_mod

app = Flask(__name__)


# ══════════════════════════════════════════════════════
#  صفحات HTML
# ══════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ══════════════════════════════════════════════════════
#  API: الفحص
# ══════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
def api_scan():
    network = request.json.get("network") if request.is_json else None
    result  = scanner.scan(network)

    # تصنيف الأجهزة
    classified = whitelist.classify(result["devices"])
    result["devices"] = classified

    # إنشاء تنبيهات للأجهزة غير المعروفة
    unknown = [d for d in classified if not d["trusted"]]
    new_alerts = alerts_mod.create_alerts(unknown, result)

    return jsonify({
        **result,
        "new_alerts": len(new_alerts),
        "unread_alerts": alerts_mod.unread_count(),
    })


# ══════════════════════════════════════════════════════
#  API: الـ Whitelist
# ══════════════════════════════════════════════════════

@app.route("/api/whitelist", methods=["GET"])
def api_whitelist_get():
    wl = whitelist.get_all()
    return jsonify([{"mac": k, "label": v} for k, v in wl.items()])


@app.route("/api/whitelist", methods=["POST"])
def api_whitelist_add():
    data  = request.get_json()
    mac   = data.get("mac", "").strip()
    label = data.get("label", "").strip()
    if not mac:
        return jsonify({"error": "MAC address required"}), 400
    whitelist.add(mac, label)
    return jsonify({"ok": True, "mac": mac.upper(), "label": label})


@app.route("/api/whitelist/<mac>", methods=["DELETE"])
def api_whitelist_delete(mac):
    removed = whitelist.remove(mac)
    return jsonify({"ok": removed})


# ══════════════════════════════════════════════════════
#  API: التنبيهات
# ══════════════════════════════════════════════════════

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    return jsonify(alerts_mod.get_all())


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
def api_alert_ack(alert_id):
    ok = alerts_mod.acknowledge(alert_id)
    return jsonify({"ok": ok})


@app.route("/api/alerts/unread", methods=["GET"])
def api_unread():
    return jsonify({"count": alerts_mod.unread_count()})


# ══════════════════════════════════════════════════════
#  API: معلومات الشبكة
# ══════════════════════════════════════════════════════

@app.route("/api/network-info", methods=["GET"])
def api_network_info():
    return jsonify({
        "local_ip": scanner.get_local_ip(),
        "default_network": scanner.get_default_network(),
        "scapy_available": scanner.SCAPY_AVAILABLE,
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  Network Monitor — نظام مراقبة الشبكة")
    print("  http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
