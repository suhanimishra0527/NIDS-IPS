from flask import Blueprint, jsonify
from server.services.statistics_service import StatisticsService

statistics_bp = Blueprint("statistics", __name__)

@statistics_bp.route("/statistics/summary", methods=["GET"])
def summary():
    stats = StatisticsService.get_dashboard_summary()
    return jsonify(stats), 200

@statistics_bp.route("/statistics/attacks", methods=["GET"])
def attacks():
    dist = StatisticsService.get_attack_distribution()
    return jsonify(dist), 200
