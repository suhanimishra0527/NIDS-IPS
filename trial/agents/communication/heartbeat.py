import time
import sys
from datetime import datetime, timezone
import psutil
from agents.config.agent_config import config
from agents.communication.api_client import api_client

class HeartbeatManager:
    def __init__(self, blocklist_cache):
        self.blocklist = blocklist_cache

    def start(self):
        """Main loop for sending heartbeats (blocking)."""
        print("[heartbeat] Started heartbeat thread.")
        while True:
            self._send_heartbeat()
            time.sleep(30)

    def _send_heartbeat(self):
        data = {
            "agent_name": config.AGENT_NAME,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": {
                "cpu": psutil.cpu_percent(),
                "memory": psutil.virtual_memory().percent
            },
            "blocked_ips_count": self.blocklist.count()
        }
        resp = api_client.post("/api/heartbeat", data)
        if not resp or resp.status_code != 200:
            print("[heartbeat] WARNING: Failed to send heartbeat.", file=sys.stderr)
