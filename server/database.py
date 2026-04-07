"""
SQLAlchemy models and database helpers.
Call init_db(app) from the Flask app factory.
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Bind db to app and create all tables."""
    db.init_app(app)
    with app.app_context():
        db.create_all()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

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
    # Latest metrics snapshot (JSON text)
    last_metrics = db.Column(db.Text, nullable=True)

    alerts = db.relationship("Alert", backref="agent", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "ip_address": self.ip_address,
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "registered_at": self.registered_at.isoformat(),
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), nullable=False, index=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    src_ip = db.Column(db.String(45), nullable=False, index=True)
    dst_ip = db.Column(db.String(45), nullable=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(16), nullable=True)
    attack_type = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(16), nullable=False)   # LOW / MEDIUM / HIGH / CRITICAL
    threat_score = db.Column(db.Integer, nullable=False, default=0)
    action_taken = db.Column(db.String(16), nullable=False)  # LOG / DROP / BLOCK
    payload_snippet = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "agent_name": self.agent.name if self.agent else None,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "threat_score": self.threat_score,
            "action_taken": self.action_taken,
            "payload_snippet": self.payload_snippet,
        }


class GlobalBlocklist(db.Model):
    __tablename__ = "global_blocklist"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    added_by = db.Column(db.String(128), nullable=False)   # agent name or "manual"
    reason = db.Column(db.String(256), nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)  # NULL = permanent
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    @property
    def is_active(self):
        if self.expires_at is None:
            return True
        return datetime.now(timezone.utc) < self.expires_at

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "added_by": self.added_by,
            "reason": self.reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
            "active": self.is_active,
        }
