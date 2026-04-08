"""
Anomaly detection based on per-source-IP traffic rate.
"""
import threading
import time
from collections import defaultdict
from typing import Optional, Tuple
from agents.config.agent_config import config

class AnomalyDetector:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters = defaultdict(lambda: {"window_start": time.monotonic(), "count": 0})
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def check(self, packet) -> Optional[dict]:
        """Check if source IP is exceeding packets-per-second threshold."""
        if not packet.haslayer("IP"):
            return None

        src_ip = packet["IP"].src
        now = time.monotonic()
        threshold = config.ANOMALY_PPS_THRESHOLD

        with self._lock:
            entry = self._counters[src_ip]
            elapsed = now - entry["window_start"]

            if elapsed >= 1.0:
                entry["window_start"] = now
                entry["count"] = 1
                return None

            entry["count"] += 1
            if entry["count"] == threshold:
                return {
                    "src_ip": src_ip,
                    "dst_ip": packet["IP"].dst,
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "IP",
                    "attack_type": "RateAnomaly",
                    "threat_score": 55,
                    "severity": "MEDIUM"
                }
        return None

    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            now = time.monotonic()
            with self._lock:
                stale = [ip for ip, e in self._counters.items() if now - e["window_start"] > 10.0]
                for ip in stale:
                    del self._counters[ip]
