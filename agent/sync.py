"""
Server synchronisation module.

Two tasks run on separate threads:
1. Poll GET /api/global_blocklist every SYNC_INTERVAL seconds and merge into
   the local blocklist.
2. Poll GET /api/commands every 15 seconds and apply any server-pushed BLOCK
   commands immediately (e.g. from the dashboard "Block IP" button).
"""
import sys
import threading
import time

import requests

from agent.config import AgentConfig


class Syncer:
    def __init__(self, local_blocklist):
        self._blocklist = local_blocklist
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {AgentConfig.AGENT_TOKEN}",
            "Content-Type":  "application/json",
        })

    # ------------------------------------------------------------------
    # Public thread entry points
    # ------------------------------------------------------------------

    def start_blocklist_sync(self):
        """Periodically sync global blocklist (blocking)."""
        while True:
            self._sync_blocklist()
            time.sleep(AgentConfig.SYNC_INTERVAL)

    def start_command_poll(self):
        """Poll for immediate block commands from server every 15 s."""
        while True:
            self._poll_commands()
            time.sleep(15)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sync_blocklist(self):
        url = f"{AgentConfig.SERVER_URL}/api/global_blocklist"
        try:
            resp = self._session.get(url, timeout=10)
            if resp.status_code != 200:
                print(f"[sync] Global blocklist fetch returned {resp.status_code}", file=sys.stderr)
                return
            data = resp.json()
            entries = data.get("entries", [])
            added = 0
            for entry in entries:
                ip = entry.get("ip_address")
                if not ip:
                    continue
                if not self._blocklist.is_blocked(ip):
                    # Use expiry from server if present, else fall back to local TTL
                    expires_at_str = entry.get("expires_at")
                    ttl = _ttl_from_expiry(expires_at_str)
                    self._blocklist.block(ip, ttl_seconds=ttl)
                    added += 1
            if added:
                print(f"[sync] Added {added} IP(s) from global blocklist.")
        except requests.RequestException as exc:
            print(f"[sync] Blocklist sync failed: {exc}", file=sys.stderr)

    def _poll_commands(self):
        url = f"{AgentConfig.SERVER_URL}/api/commands"
        try:
            resp = self._session.get(url, timeout=8)
            if resp.status_code != 200:
                return
            data = resp.json()
            commands = data.get("commands", [])
            for cmd in commands:
                if cmd.get("action") == "block":
                    ip = cmd.get("ip")
                    if ip and not self._blocklist.is_blocked(ip):
                        self._blocklist.block(ip)
                        print(f"[sync] Applied server BLOCK command for {ip}")
        except requests.RequestException as exc:
            print(f"[sync] Command poll failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _ttl_from_expiry(expires_at_str: str | None) -> int:
    """Convert an ISO expiry string from server to a TTL in seconds."""
    if not expires_at_str:
        return AgentConfig.LOCAL_BLOCK_TTL
    try:
        from datetime import datetime, timezone
        expiry = datetime.fromisoformat(expires_at_str)
        now    = datetime.now(timezone.utc)
        ttl    = int((expiry - now).total_seconds())
        return max(ttl, 60)   # minimum 60 s
    except Exception:
        return AgentConfig.LOCAL_BLOCK_TTL
