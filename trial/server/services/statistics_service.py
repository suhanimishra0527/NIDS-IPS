from sqlalchemy import func
from server.models.alert import Alert
from server.models.agent import Agent
from server.models.blocklist import GlobalBlocklist

class StatisticsService:
    @staticmethod
    def get_dashboard_summary():
        """Retrieve high-level summary stats for the dashboard."""
        return {
            "total_alerts": Alert.query.count(),
            "active_agents": Agent.query.filter_by(status="online").count(),
            "blocked_ips": GlobalBlocklist.query.count(),
            "critical_threats": Alert.query.filter_by(severity="CRITICAL").count()
        }

    @staticmethod
    def get_attack_distribution():
        """Get distribution of attack types for charts."""
        results = Alert.query.with_entities(
            Alert.attack_type, func.count(Alert.id)
        ).group_by(Alert.attack_type).all()
        return {name: count for name, count in results}
