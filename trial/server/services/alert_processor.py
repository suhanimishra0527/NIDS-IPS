from datetime import datetime, timezone, timedelta
from server.models.database import db
from server.models.alert import Alert
from server.models.blocklist import GlobalBlocklist
from server.config.server_config import config

class AlertProcessor:
    @staticmethod
    def process_batch(agent_id, alerts_data):
        """Process a batch of alerts from an agent."""
        processed_alerts = []
        for data in alerts_data:
            alert = Alert(
                agent_id=agent_id,
                src_ip=data.get("src_ip"),
                dst_ip=data.get("dst_ip"),
                src_port=data.get("src_port"),
                dst_port=data.get("dst_port"),
                protocol=data.get("protocol"),
                attack_type=data.get("attack_type"),
                severity=data.get("severity", "MEDIUM"),
                threat_score=data.get("threat_score", 0),
                action_taken=data.get("action_taken", "LOG"),
                payload_snippet=data.get("payload_preview")
            )
            db.session.add(alert)
            processed_alerts.append(alert)
            
            # Auto-blocking logic
            if alert.threat_score >= config._config.get("alerts", {}).get("auto_block_threat_score", 80):
                AlertProcessor._auto_block(alert)

        db.session.commit()
        return processed_alerts

    @staticmethod
    def _auto_block(alert):
        """Automatically add high-threat IPs to the global blocklist."""
        existing = GlobalBlocklist.query.filter_by(ip_address=alert.src_ip).first()
        if not existing:
            block = GlobalBlocklist(
                ip_address=alert.src_ip,
                added_by=f"auto-detect ({alert.attack_type})",
                reason=f"High threat score: {alert.threat_score}",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1)
            )
            db.session.add(block)
            print(f"[processor] Auto-blocked malicious IP: {alert.src_ip}")
