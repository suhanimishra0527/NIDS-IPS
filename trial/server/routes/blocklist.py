from flask import Blueprint, request, jsonify, g
from server.models.database import db
from server.models.blocklist import GlobalBlocklist
from server.utils.security import require_agent_auth
from server.config.server_config import config

blocklist_bp = Blueprint("blocklist", __name__)

@blocklist_bp.route("/global_blocklist", methods=["GET"])
@require_agent_auth
def get_blocklist():
    entries = GlobalBlocklist.query.all()
    # Simple sync logic for now (active entries only)
    active = [e.to_dict() for e in entries if e.is_active]
    return jsonify({"entries": active}), 200

@blocklist_bp.route("/global_blocklist", methods=["POST"])
@require_agent_auth
def add_block():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip_address")
    if not ip:
        return jsonify({"error": "ip_address required"}), 400

    new_block = GlobalBlocklist(
        ip_address=ip,
        added_by=g.agent.name if g.agent else "admin",
        reason=data.get("reason", "Manual block")
    )
    db.session.add(new_block)
    db.session.commit()
    return jsonify(new_block.to_dict()), 201
