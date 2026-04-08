from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """Bind db to app and create all tables."""
    db.init_app(app)
    with app.app_context():
        # Import models here to ensure they are registered with SQLAlchemy
        from server.models.agent import Agent
        from server.models.alert import Alert
        from server.models.blocklist import GlobalBlocklist
        db.create_all()
