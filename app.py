"""
app.py
──────
SOC Lab — Flask REST API Backend
Serves alert data, detection rules, stats,
and incident management endpoints.
"""

import sys, os, json, random
from datetime import datetime
from typing import List

from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from backend.threat_engine import AlertGenerator, DetectionEngine, Alert

app  = Flask(__name__)
CORS(app)

# ── In-memory alert store (replace with DB in production) ─
_generator = AlertGenerator()
_alerts: List[Alert] = _generator.generate_batch(35)


def _find_alert(alert_id: str) -> Alert | None:
    return next((a for a in _alerts if a.alert_id == alert_id), None)


# ══════════════════════════════════════════════════════
#  API ROUTES
# ══════════════════════════════════════════════════════

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    severity = request.args.get("severity")
    status   = request.args.get("status")
    atype    = request.args.get("type")
    limit    = int(request.args.get("limit", 100))

    filtered = _alerts
    if severity: filtered = [a for a in filtered if a.severity == severity.upper()]
    if status:   filtered = [a for a in filtered if a.status   == status.lower()]
    if atype:    filtered = [a for a in filtered if a.alert_type == atype.lower()]

    return jsonify({
        "alerts": [a.to_dict() for a in filtered[:limit]],
        "total":  len(filtered)
    })


@app.route("/api/alerts/<alert_id>", methods=["GET"])
def get_alert(alert_id):
    alert = _find_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert.to_dict())


@app.route("/api/alerts/<alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):
    alert = _find_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    data             = request.json or {}
    alert.status     = data.get("status", alert.status)
    alert.assigned_to= data.get("assigned_to", alert.assigned_to)
    alert.resolution = data.get("resolution", alert.resolution)
    return jsonify({"success": True, "alert": alert.to_dict()})


@app.route("/api/alerts/generate", methods=["POST"])
def generate_alert():
    """Manually trigger a new alert (for demo)"""
    attack_types = [
        "brute_force", "port_scan", "ddos",
        "lateral_movement", "data_exfiltration",
        "malware_beacon", "privilege_escalation", "sql_injection"
    ]
    atype  = request.json.get("type") if request.json else None
    atype  = atype if atype in attack_types else random.choice(attack_types)

    gen_map = {
        "brute_force":          _generator.brute_force_alert,
        "port_scan":            _generator.port_scan_alert,
        "ddos":                 _generator.ddos_alert,
        "lateral_movement":     _generator.lateral_movement_alert,
        "data_exfiltration":    _generator.data_exfiltration_alert,
        "malware_beacon":       _generator.malware_beacon_alert,
        "privilege_escalation": _generator.privilege_escalation_alert,
        "sql_injection":        _generator.sql_injection_alert,
    }
    new_alert = gen_map[atype]()
    _alerts.insert(0, new_alert)
    return jsonify({"success": True, "alert": new_alert.to_dict()})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(DetectionEngine.get_stats(_alerts))


@app.route("/api/rules", methods=["GET"])
def get_rules():
    return jsonify({"rules": DetectionEngine.get_rules()})


@app.route("/api/mitre", methods=["GET"])
def get_mitre():
    from backend.threat_engine import MITRE_TECHNIQUES
    return jsonify({"techniques": MITRE_TECHNIQUES})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "online",
        "timestamp": datetime.now().isoformat(),
        "alerts":    len(_alerts),
        "version":   "1.0.0"
    })


if __name__ == "__main__":
    print("🛡️  SOC Lab API starting on http://localhost:5001")
    app.run(debug=True, host="0.0.0.0", port=5001)
