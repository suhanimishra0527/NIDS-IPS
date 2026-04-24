from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g

from server.auth import require_agent_auth
from server.database import db, Alert

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/api/alerts", methods=["POST"])
@require_agent_auth
def receive_alert():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid data"}), 400

    # Handle both single alert and batch (list) payloads
    alerts = data if isinstance(data, list) else [data]

    for item in alerts:
        # Parse timestamp from agent, fall back to now
        ts = item.get("timestamp")
        if ts:
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        alert = Alert(
            agent_id=g.agent.id,
            timestamp=ts,
            src_ip=item.get("src_ip", ""),
            dst_ip=item.get("dst_ip"),
            src_port=item.get("src_port"),
            dst_port=item.get("dst_port"),
            protocol=item.get("protocol"),
            attack_type=item.get("attack_type", "unknown"),
            severity=item.get("severity", "LOW"),
            threat_score=item.get("threat_score", 0),
            action_taken=item.get("action_taken", "LOG"),
            payload_snippet=item.get("payload_snippet", "")[:256] if item.get("payload_snippet") else None,
        )
        db.session.add(alert)

    db.session.commit()

    print(f"[SERVER] Stored {len(alerts)} alert(s) from agent '{g.agent.name}'")

    return jsonify({"status": "ok", "stored": len(alerts)}), 201