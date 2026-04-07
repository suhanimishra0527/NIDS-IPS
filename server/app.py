"""
Flask application factory.
Run with:  python app.py
"""
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Flask

from server.config import Config
from server.database import db, init_db, Agent
from server.routes.auth import auth_bp
from server.routes.agents import agents_bp
from server.routes.alerts import alerts_bp
from server.routes.blocklist import blocklist_bp
from server.routes.dashboard import dashboard_bp


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SQLALCHEMY_DATABASE_URI"] = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = Config.JWT_SECRET

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(agents_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(blocklist_bp)
    app.register_blueprint(dashboard_bp)

    init_db(app)
    return app


def _heartbeat_monitor(app: Flask):
    """
    Background thread: marks agents offline if last_seen is older than
    HEARTBEAT_TIMEOUT_SECONDS. Runs every 30 seconds.
    """
    timeout = timedelta(seconds=Config.HEARTBEAT_TIMEOUT_SECONDS)
    while True:
        time.sleep(30)
        try:
            with app.app_context():
                cutoff = datetime.now(timezone.utc) - timeout
                stale = Agent.query.filter(
                    Agent.status == "online",
                    Agent.last_seen < cutoff
                ).all()
                for agent in stale:
                    agent.status = "offline"
                if stale:
                    db.session.commit()
        except Exception as exc:
            print(f"[heartbeat-monitor] error: {exc}")


if __name__ == "__main__":
    app = create_app()

    # Start heartbeat monitor in daemon thread
    monitor = threading.Thread(target=_heartbeat_monitor, args=(app,), daemon=True)
    monitor.start()

    print(f"[NIDS Server] Starting on {Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
