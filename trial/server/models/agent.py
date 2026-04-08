from datetime import datetime, timezone
from server.models.database import db

class Agent(db.Model):
    __tablename__ = "agents"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    token_hash = db.Column(db.String(256), nullable=False)
    status = db.Column(db.String(16), default="offline")   # online / offline
    last_seen = db.Column(db.DateTime(timezone=True), nullable=True)
    registered_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    last_metrics = db.Column(db.Text, nullable=True)

    alerts = db.relationship("Alert", backref="agent_ref", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "ip_address": self.ip_address,
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "registered_at": self.registered_at.isoformat(),
        }
