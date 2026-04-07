"""
Anomaly detection based on per-source-IP traffic rate.

Maintains a rolling 1-second packet counter per source IP.
Fires when ANY IP exceeds ANOMALY_PPS_THRESHOLD packets/second.
"""
import threading
import time
from collections import defaultdict

from agent.config import AgentConfig

# Attack type and score assigned when rate threshold is exceeded
ANOMALY_ATTACK_TYPE = "RateAnomaly"
ANOMALY_SCORE     = 55
ANOMALY_SEVERITY  = "MEDIUM"


class AnomalyDetector:
    """
    Rolling 1-second packet rate tracker per source IP.
    Thread-safe; designed to be fed one packet at a time.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {src_ip: {"window_start": float, "count": int}}
        self._counters: dict[str, dict] = defaultdict(
            lambda: {"window_start": time.monotonic(), "count": 0}
        )
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_packet(self, src_ip: str) -> tuple | None:
        """
        Increment counter for src_ip. If the rate exceeds the configured
        threshold within the current 1-second window, return a detection
        tuple: (attack_type, score, src_ip) — else None.
        """
        threshold = AgentConfig.ANOMALY_PPS_THRESHOLD
        now = time.monotonic()

        with self._lock:
            entry = self._counters[src_ip]
            elapsed = now - entry["window_start"]

            if elapsed >= 1.0:
                # New 1-second window
                entry["window_start"] = now
                entry["count"] = 1
                return None

            entry["count"] += 1

            if entry["count"] == threshold:
                # Fire exactly once per window when threshold first crossed
                return (ANOMALY_ATTACK_TYPE, ANOMALY_SCORE, src_ip)

        return None

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _cleanup_loop(self):
        """Evict stale (>10 s) IP entries every 30 seconds."""
        while True:
            time.sleep(30)
            now = time.monotonic()
            with self._lock:
                stale = [
                    ip for ip, e in self._counters.items()
                    if now - e["window_start"] > 10.0
                ]
                for ip in stale:
                    del self._counters[ip]
