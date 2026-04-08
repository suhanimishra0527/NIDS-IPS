from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from server.models.database import db
from server.models.agent import Agent
from server.utils.security import require_agent_auth, generate_token, hash_token
from server.config.server_config import config

agents_bp = Blueprint("agents", __name__)

@agents_bp.route("/register", methods=["POST"])
def register():
    """Register a new agent (Kali host)."""
    data = request.get_json(silent=True) or {}
    reg_key = data.get("registration_key")
    agent_name = data.get("agent_name")

    if reg_key != config.REGISTRATION_KEY:
        return jsonify({"error": "Invalid registration key"}), 401
    
    if not agent_name:
        return jsonify({"error": "agent_name is required"}), 400

    existing = Agent.query.filter_by(name=agent_name).first()
    if existing:
        return jsonify({"error": "Agent name already exists"}), 400

    token = generate_token(agent_name)
    agent = Agent(
        name=agent_name,
        token_hash=hash_token(token),
        status="online",
        last_seen=datetime.now(timezone.utc)
    )
    db.session.add(agent)
    db.session.commit()

    return jsonify({"token": token, "agent_name": agent_name}), 201

@agents_bp.route("/heartbeat", methods=["POST"])
@require_agent_auth
def heartbeat():
    agent = g.agent
    data = request.get_json(silent=True) or {}

    agent.status = "online"
    agent.last_seen = datetime.now(timezone.utc)
    agent.ip_address = request.remote_addr
    
    if "metrics" in data:
        import json
        agent.last_metrics = json.dumps(data["metrics"])

    db.session.commit()
    return jsonify({"status": "ok", "server_time": datetime.now(timezone.utc).isoformat()}), 200
