"""
POST /api/heartbeat  — agent liveness check + optional metrics snapshot
POST /api/metrics    — detailed metrics submission
GET  /api/commands   — agent polls for pending commands
"""
import json
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g

from server.auth import require_agent_auth
from server.database import db
from server.redis_client import store_agent_metrics, pop_commands

agents_bp = Blueprint("agents", __name__)


@agents_bp.route("/api/heartbeat", methods=["POST"])
@require_agent_auth
def heartbeat():
    agent = g.agent
    data = request.get_json(silent=True) or {}

    agent.status = "online"
    agent.last_seen = datetime.now(timezone.utc)
    agent.ip_address = request.remote_addr

    # Store lightweight metrics in Redis (optional fields)
    metrics = {
        "cpu_percent": data.get("cpu_percent"),
        "mem_percent": data.get("mem_percent"),
        "packets_per_sec": data.get("packets_per_sec"),
        "alerts_in_queue": data.get("alerts_in_queue"),
        "blocked_ips": data.get("blocked_ips"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    store_agent_metrics(agent.name, metrics)

    db.session.commit()
    return jsonify({"status": "ok", "server_time": datetime.now(timezone.utc).isoformat()}), 200


@agents_bp.route("/api/metrics", methods=["POST"])
@require_agent_auth
def metrics():
    agent = g.agent
    data = request.get_json(silent=True) or {}

    agent.last_seen = datetime.now(timezone.utc)
    agent.last_metrics = json.dumps(data)
    db.session.commit()

    store_agent_metrics(agent.name, data)
    return jsonify({"status": "ok"}), 200


@agents_bp.route("/api/commands", methods=["GET"])
@require_agent_auth
def get_commands():
    """Allow agents to poll pending commands (block IPs, etc.)."""
    agent = g.agent
    commands = pop_commands(agent.name)
    return jsonify({"commands": commands}), 200
