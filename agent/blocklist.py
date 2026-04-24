"""
Local blocklist with 1-hour TTL (configurable).
Thread-safe in-memory store with background expiry cleanup.
Also removes iptables DROP rules when entries expire.
"""
import threading
import time
from datetime import datetime, timezone

from agent.config import AgentConfig
from agent.ips import unblock_ip


class LocalBlocklist:
    """
    Thread-safe IP blocklist with TTL expiry.
    Entries are stored as {ip: expiry_datetime_utc}.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._entries: dict[str, datetime] = {}
        # Start background cleanup thread
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block(self, ip: str, ttl_seconds: int = None) -> None:
        """Add IP to local blocklist with given TTL (default from config)."""
        ttl = ttl_seconds if ttl_seconds is not None else AgentConfig.LOCAL_BLOCK_TTL
        from datetime import timedelta
        expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        with self._lock:
            self._entries[ip] = expiry

    def is_blocked(self, ip: str) -> bool:
        """Return True if IP is in the blocklist and not yet expired."""
        with self._lock:
            expiry = self._entries.get(ip)
            if expiry is None:
                return False
            if datetime.now(timezone.utc) >= expiry:
                del self._entries[ip]
                # Remove the iptables DROP rule since the block has expired
                unblock_ip(ip)
                return False
            return True

    def remove(self, ip: str) -> bool:
        """Manually remove an IP and its iptables rule. Returns True if it was present."""
        with self._lock:
            was_present = self._entries.pop(ip, None) is not None
        if was_present:
            unblock_ip(ip)
        return was_present

    def all_active(self) -> list[str]:
        """Return list of currently active (non-expired) blocked IPs."""
        now = datetime.now(timezone.utc)
        with self._lock:
            return [ip for ip, exp in self._entries.items() if now < exp]

    def count(self) -> int:
        return len(self.all_active())

    # ------------------------------------------------------------------
    # Background cleanup
    # ------------------------------------------------------------------

    def _cleanup_loop(self):
        """Remove expired entries and their iptables rules every 60 seconds."""
        while True:
            time.sleep(60)
            now = datetime.now(timezone.utc)
            with self._lock:
                expired = [ip for ip, exp in self._entries.items() if now >= exp]
                for ip in expired:
                    del self._entries[ip]
            # Remove iptables rules outside the lock (subprocess calls are slow)
            for ip in expired:
                unblock_ip(ip)
            if expired:
                print(f"[blocklist] Cleaned {len(expired)} expired entries + removed iptables rules.")
