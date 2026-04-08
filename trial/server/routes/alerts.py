from flask import Blueprint, request, jsonify, g
from server.utils.security import require_agent_auth
from server.services.alert_processor import AlertProcessor

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/alerts", methods=["POST"])
@require_agent_auth
def submit_alerts():
    agent = g.agent
    data = request.get_json(silent=True)

    if not isinstance(data, list):
        return jsonify({"error": "Expected a JSON array"}), 400

    processed = AlertProcessor.process_batch(agent.id, data)
    return jsonify({"inserted": len(processed)}), 201
