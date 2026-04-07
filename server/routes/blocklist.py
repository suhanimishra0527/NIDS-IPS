"""
GET  /api/global_blocklist  — returns active (non-expired) blocklist entries
POST /api/global_blocklist  — add an entry (admin key or agent JWT)
POST /api/command/block     — manually block an IP (admin key or agent JWT)
DELETE /api/global_blocklist/<id> — remove entry (admin key)
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, g

from server.auth import require_agent_auth
from server.config import Config
from server.database import db, GlobalBlocklist, Agent
from server.redis_client import push_block_command, cache_blocklist, get_cached_blocklist

blocklist_bp = Blueprint("blocklist", __name__)


def _require_admin_or_agent(f):
    """Allow either bearer JWT (agent) or X-Admin-Key header."""
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        admin_key = request.headers.get("X-Admin-Key", "")
        if admin_key == Config.AGENT_REGISTRATION_KEY:
            g.agent = None  # admin access, no specific agent
            return f(*args, **kwargs)
        # Fall back to agent JWT
        return require_agent_auth(f)(*args, **kwargs)
    return wrapper


@blocklist_bp.route("/api/global_blocklist", methods=["GET"])
@require_agent_auth
def get_blocklist():
    # Try cache first (for frequent agent polling)
    cached = get_cached_blocklist()
    if cached is not None:
        return jsonify({"entries": cached, "source": "cache"}), 200

    now = datetime.now(timezone.utc)
    entries = GlobalBlocklist.query.filter(
        (GlobalBlocklist.expires_at == None) | (GlobalBlocklist.expires_at > now)
    ).all()
    result = [e.to_dict() for e in entries]
    cache_blocklist(result)
    return jsonify({"entries": result, "source": "db"}), 200


@blocklist_bp.route("/api/global_blocklist", methods=["POST"])
@_require_admin_or_agent
def add_to_blocklist():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip_address", "").strip()
    if not ip:
        return jsonify({"error": "ip_address is required"}), 400

    reason = data.get("reason", "manual")
    expiry_seconds = int(data.get("expiry_seconds", Config.BLOCKLIST_EXPIRY_SECONDS))
    added_by = getattr(g, "agent", None)
    added_by_name = added_by.name if added_by else "manual"

    existing = GlobalBlocklist.query.filter_by(ip_address=ip).first()
    if existing:
        existing.expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
        existing.reason = reason
        db.session.commit()
        return jsonify({"message": "Entry updated", "entry": existing.to_dict()}), 200

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
    entry = GlobalBlocklist(
        ip_address=ip,
        added_by=added_by_name,
        reason=reason[:256],
        expires_at=expires_at,
    )
    db.session.add(entry)
    db.session.commit()

    # Push to all online agents
    online_agents = Agent.query.filter_by(status="online").all()
    for a in online_agents:
        push_block_command(a.name, ip, reason)

    return jsonify({"message": "IP added to global blocklist", "entry": entry.to_dict()}), 201


@blocklist_bp.route("/api/command/block", methods=["POST"])
@_require_admin_or_agent
def command_block():
    """Manual block command: adds to DB and pushes to all agents via Redis."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip_address", "").strip()
    reason = data.get("reason", "manual block")
    expiry_seconds = int(data.get("expiry_seconds", Config.BLOCKLIST_EXPIRY_SECONDS))

    if not ip:
        return jsonify({"error": "ip_address is required"}), 400

    existing = GlobalBlocklist.query.filter_by(ip_address=ip).first()
    if not existing:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
        entry = GlobalBlocklist(
            ip_address=ip,
            added_by="manual",
            reason=reason[:256],
            expires_at=expires_at,
        )
        db.session.add(entry)
        db.session.commit()

    online_agents = Agent.query.filter_by(status="online").all()
    pushed_to = []
    for a in online_agents:
        push_block_command(a.name, ip, reason)
        pushed_to.append(a.name)

    return jsonify({
        "message": f"Block command issued for {ip}",
        "pushed_to_agents": pushed_to,
    }), 200


@blocklist_bp.route("/api/global_blocklist/<int:entry_id>", methods=["DELETE"])
def remove_from_blocklist(entry_id):
    admin_key = request.headers.get("X-Admin-Key", "")
    if admin_key != Config.AGENT_REGISTRATION_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    entry = GlobalBlocklist.query.get(entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404

    db.session.delete(entry)
    db.session.commit()
    return jsonify({"message": "Entry removed"}), 200
