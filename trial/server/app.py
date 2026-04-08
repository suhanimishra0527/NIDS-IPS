import os
from flask import Flask, render_template
from server.config.server_config import config
from server.models.database import init_db

def create_app():
    app = Flask(__name__, 
                template_folder="templates",
                static_folder="static")
    
    # 1. Configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = config.JWT_SECRET

    # 2. Initialize Database
    init_db(app)

    # 3. Register Blueprints
    from server.routes.agents import agents_bp
    from server.routes.alerts import alerts_bp
    from server.routes.blocklist import blocklist_bp
    from server.routes.dashboard import dashboard_bp
    from server.routes.statistics import statistics_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(agents_bp, url_prefix="/api")
    app.register_blueprint(alerts_bp, url_prefix="/api")
    app.register_blueprint(blocklist_bp, url_prefix="/api")
    app.register_blueprint(statistics_bp, url_prefix="/api")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host=config.HOST, port=config.PORT, debug=True)
