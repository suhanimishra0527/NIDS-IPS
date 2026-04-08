"""
POST /api/register

Agents call this once to receive a JWT token.
They must present the shared AGENT_REGISTRATION_KEY.
"""
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify

from server.auth import generate_token, hash_token
from server.config import Config
from server.database import db, Agent

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    agent_name = data.get("agent_name", "").strip()
    reg_key = data.get("registration_key", "")

    if not agent_name:
        return jsonify({"error": "agent_name is required"}), 400

    if reg_key != Config.AGENT_REGISTRATION_KEY:
        return jsonify({"error": "Invalid registration key"}), 403

    # Validate name characters
    if not agent_name.replace("-", "").replace("_", "").isalnum():
        return jsonify({"error": "agent_name may only contain letters, digits, hyphens, underscores"}), 400

    existing = Agent.query.filter_by(name=agent_name).first()
    if existing:
        # Re-registration: rotate token
        token = generate_token(agent_name)
        existing.token_hash = hash_token(token)
        existing.ip_address = request.remote_addr
        existing.status = "online"
        existing.last_seen = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({
            "message": "Agent re-registered",
            "agent_name": agent_name,
            "token": token,
        }), 200

    token = generate_token(agent_name)
    agent = Agent(
        name=agent_name,
        ip_address=request.remote_addr,
        token_hash=hash_token(token),
        status="online",
        last_seen=datetime.now(timezone.utc),
    )
    db.session.add(agent)
    db.session.commit()

    return jsonify({
        "message": "Agent registered successfully",
        "agent_name": agent_name,
        "token": token,
    }), 201
