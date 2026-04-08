from datetime import datetime, timezone
from server.models.database import db

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

    @property
    def agent(self):
        # Helper to avoid direct relationship name conflicts
        from server.models.agent import Agent
        return Agent.query.get(self.agent_id)

    def to_dict(self):
        a = self.agent
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "agent_name": a.name if a else "unknown",
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
