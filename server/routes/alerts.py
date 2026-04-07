"""
POST /api/alerts

Accepts a JSON array of alert dicts from an agent.
Batch-inserts into the alerts table.
If threat_score >= AUTO_BLOCK_THREAT_SCORE, auto-adds src_ip to global blocklist
and pushes block command to all online agents via Redis.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, g

from server.auth import require_agent_auth
from server.config import Config
from server.database import db, Alert, GlobalBlocklist, Agent
from server.redis_client import push_block_command

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/api/alerts", methods=["POST"])
@require_agent_auth
def submit_alerts():
    agent = g.agent
    data = request.get_json(silent=True)

    if not isinstance(data, list):
        return jsonify({"error": "Expected a JSON array of alert objects"}), 400

    if len(data) > 500:
        return jsonify({"error": "Too many alerts in one batch (max 500)"}), 400

    inserted = 0
    auto_blocked = []

    for item in data:
        if not isinstance(item, dict):
            continue

        threat_score = int(item.get("threat_score", 0))
        severity = _score_to_severity(threat_score)

        alert = Alert(
            agent_id=agent.id,
            src_ip=item.get("src_ip", ""),
            dst_ip=item.get("dst_ip"),
            src_port=item.get("src_port"),
            dst_port=item.get("dst_port"),
            protocol=item.get("protocol"),
            attack_type=item.get("attack_type", "unknown"),
            severity=item.get("severity", severity),
            threat_score=threat_score,
            action_taken=item.get("action_taken", "LOG"),
            payload_snippet=str(item.get("payload_snippet", ""))[:512],
        )

        # Handle timestamp from agent
        ts = item.get("timestamp")
        if ts:
            try:
                alert.timestamp = datetime.fromisoformat(ts)
            except ValueError:
                pass

        db.session.add(alert)
        inserted += 1

        # Auto-block if score is high enough
        src_ip = item.get("src_ip", "")
        if threat_score >= Config.AUTO_BLOCK_THREAT_SCORE and src_ip:
            _ensure_global_block(src_ip, agent.name, item.get("attack_type", ""), auto_blocked)

    db.session.commit()
    return jsonify({"inserted": inserted, "auto_blocked": auto_blocked}), 201


def _score_to_severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _ensure_global_block(ip: str, added_by: str, reason: str, auto_blocked: list):
    """Add IP to global blocklist if not already present, then push Redis commands."""
    existing = GlobalBlocklist.query.filter_by(ip_address=ip).first()
    if existing:
        return  # Already in blocklist

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=Config.BLOCKLIST_EXPIRY_SECONDS)
    entry = GlobalBlocklist(
        ip_address=ip,
        added_by=added_by,
        reason=reason[:256],
        expires_at=expires_at,
    )
    db.session.add(entry)
    auto_blocked.append(ip)

    # Push block command to all online agents
    online_agents = Agent.query.filter_by(status="online").all()
    for a in online_agents:
        push_block_command(a.name, ip, reason)
