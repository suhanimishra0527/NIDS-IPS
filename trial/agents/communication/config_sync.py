import time
import sys
from agents.config.agent_config import config
from agents.communication.api_client import api_client

class Syncer:
    def __init__(self, blocklist):
        self.blocklist = blocklist

    def start_blocklist_sync(self):
        """Periodically sync global blocklist (blocking)."""
        print("[sync] Started blocklist sync thread.")
        while True:
            self._sync()
            time.sleep(60)

    def _sync(self):
        resp = api_client.get("/api/global_blocklist")
        if resp and resp.status_code == 200:
            data = resp.json()
            entries = data.get("entries", [])
            added = 0
            for entry in entries:
                ip = entry.get("ip_address")
                if ip and not self.blocklist.is_blocked(ip):
                    self.blocklist.block(ip)
                    added += 1
            if added:
                print(f"[sync] Added {added} new IPs from global blocklist.")
        else:
            print("[sync] WARNING: Failed to sync global blocklist.", file=sys.stderr)

    def start_command_poll(self):
        """Poll for immediate remote commands (blocking)."""
        print("[sync] Started command polling thread.")
        while True:
            # Command polling is reserved for dynamic dashboard actions
            # Implementation can be expanded as needed.
            time.sleep(15)
