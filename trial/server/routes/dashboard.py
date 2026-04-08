from flask import Blueprint, render_template
from server.models.agent import Agent
from server.models.alert import Alert
from server.models.blocklist import GlobalBlocklist

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    # Initial load data
    agents = Agent.query.all()
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    blocks = GlobalBlocklist.query.all()
    return render_template("index.html", agents=agents, alerts=alerts, blocks=blocks)
