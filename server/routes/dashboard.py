"""Routes for the web dashboard (HTML views)."""
from datetime import datetime, timezone

from flask import Blueprint, render_template, redirect, url_for, request, jsonify

from server.database import Agent, Alert, GlobalBlocklist
from server.redis_client import get_agent_metrics

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    agents = Agent.query.order_by(Agent.registered_at.desc()).all()
    recent_alerts = (
        Alert.query
        .order_by(Alert.timestamp.desc())
        .limit(100)
        .all()
    )
    now = datetime.now(timezone.utc)
    active_blocks = GlobalBlocklist.query.filter(
        (GlobalBlocklist.expires_at == None) | (GlobalBlocklist.expires_at > now)
    ).count()

    agent_data = []
    for a in agents:
        metrics = get_agent_metrics(a.name) or {}
        agent_data.append({"agent": a, "metrics": metrics})

    return render_template(
        "dashboard.html",
        agent_data=agent_data,
        recent_alerts=recent_alerts,
        active_blocks=active_blocks,
        total_agents=len(agents),
        online_agents=sum(1 for a in agents if a.status == "online"),
        total_alerts=Alert.query.count(),
    )


@dashboard_bp.route("/alerts")
def alerts_page():
    page = request.args.get("page", 1, type=int)
    attack_filter = request.args.get("attack_type", "")
    severity_filter = request.args.get("severity", "")

    query = Alert.query.order_by(Alert.timestamp.desc())
    if attack_filter:
        query = query.filter(Alert.attack_type == attack_filter)
    if severity_filter:
        query = query.filter(Alert.severity == severity_filter)

    pagination = query.paginate(page=page, per_page=50, error_out=False)
    attack_types = [r[0] for r in Alert.query.with_entities(Alert.attack_type).distinct().all()]

    return render_template(
        "alerts.html",
        pagination=pagination,
        alerts=pagination.items,
        attack_types=attack_types,
        attack_filter=attack_filter,
        severity_filter=severity_filter,
    )


@dashboard_bp.route("/blocklist")
def blocklist_page():
    now = datetime.now(timezone.utc)
    entries = (
        GlobalBlocklist.query
        .order_by(GlobalBlocklist.created_at.desc())
        .all()
    )
    return render_template("blocklist.html", entries=entries, now=now)


# --- JSON endpoints for dashboard live updates ---

@dashboard_bp.route("/api/dashboard/summary")
def api_summary():
    agents = Agent.query.all()
    now = datetime.now(timezone.utc)
    active_blocks = GlobalBlocklist.query.filter(
        (GlobalBlocklist.expires_at == None) | (GlobalBlocklist.expires_at > now)
    ).count()
    return jsonify({
        "total_agents": len(agents),
        "online_agents": sum(1 for a in agents if a.status == "online"),
        "total_alerts": Alert.query.count(),
        "active_blocks": active_blocks,
        "agents": [a.to_dict() for a in agents],
        "recent_alerts": [a.to_dict() for a in Alert.query.order_by(Alert.timestamp.desc()).limit(20).all()],
    })
