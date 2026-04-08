from datetime import datetime, timezone
from server.models.database import db

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
        return datetime.now(timezone.utc).replace(tzinfo=timezone.utc) < self.expires_at.replace(tzinfo=timezone.utc)

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
