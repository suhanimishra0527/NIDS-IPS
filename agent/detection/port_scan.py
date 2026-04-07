"""
Port scan detection: SYN, FIN, NULL scans.

Uses a sliding-window approach: per source IP, track destination ports
touched within the last PORTSCAN_WINDOW_SEC seconds.
Fires when >PORTSCAN_THRESHOLD unique ports are hit in the window.
"""
import threading
import time
from collections import defaultdict, deque

from agent.config import AgentConfig

# Maps scan type flag combinator → (attack_type, threat_score)
_SCAN_TYPES = {
    "SYN":  ("SYN_Scan",  65),
    "FIN":  ("FIN_Scan",  70),
    "NULL": ("NULL_Scan", 75),
    "XMAS": ("XMAS_Scan", 70),
}


def _classify_flags(flags_int: int) -> str | None:
    """
    Return scan type string from TCP flags integer, or None if not a scan.
    Scapy flag integers:
      S=0x02 (SYN-only), F=0x01 (FIN-only), 0x00 (NULL), F+P+U=0x29 (XMAS)
    """
    if flags_int == 0x02:             # SYN only (no ACK)
        return "SYN"
    if flags_int == 0x01:             # FIN only
        return "FIN"
    if flags_int == 0x00:             # No flags at all
        return "NULL"
    if flags_int == 0x29:             # FIN+PSH+URG = XMAS
        return "XMAS"
    return None


class PortScanDetector:
    """
    Stateful per-source-IP port scan tracker.
    Thread-safe; designed to be called from the packet capture callback.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {src_ip: {scan_type: deque of (timestamp, dst_port)}
        self._windows: dict[str, dict[str, deque]] = defaultdict(
            lambda: defaultdict(deque)
        )
        # Start background eviction thread
        threading.Thread(target=self._evict_loop, daemon=True).start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_packet(self, src_ip: str, dst_port: int, flags_int: int) -> tuple | None:
        """
        Feed a TCP packet into the detector.

        Returns (attack_type, threat_score, src_ip, dst_port) if threshold
        exceeded, or None otherwise.
        """
        scan_type = _classify_flags(flags_int)
        if scan_type is None:
            return None

        now = time.monotonic()
        threshold = AgentConfig.PORTSCAN_THRESHOLD
        window    = AgentConfig.PORTSCAN_WINDOW_SEC

        with self._lock:
            dq = self._windows[src_ip][scan_type]
            # Add this packet
            dq.append((now, dst_port))
            # Remove stale entries outside the window
            cutoff = now - window
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            # Count unique ports in current window
            unique_ports = len({p for _, p in dq})
            if unique_ports >= threshold:
                # Clear window to avoid duplicate alerts for same burst
                dq.clear()
                attack_type, score = _SCAN_TYPES[scan_type]
                return (attack_type, score, src_ip, dst_port)

        return None

    # Convenience method for unit testing (accepts raw flag string)
    def track(self, src_ip: str, dst_port: int, flags: str) -> tuple | None:
        """Accept Scapy-style flag string ('S', 'F', '', 'FPU')."""
        flag_map = {"S": 0x02, "F": 0x01, "": 0x00, "FPU": 0x29}
        flags_int = flag_map.get(flags, 0)
        return self.process_packet(src_ip, dst_port, flags_int)

    def check(self, src_ip: str) -> bool:
        """Return True if there are any tracked entries for this IP."""
        with self._lock:
            return bool(self._windows.get(src_ip))

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _evict_loop(self):
        """Periodically remove IPs with no recent activity."""
        while True:
            time.sleep(30)
            cutoff = time.monotonic() - AgentConfig.PORTSCAN_WINDOW_SEC
            with self._lock:
                dead_ips = []
                for ip, scan_dict in self._windows.items():
                    for dq in scan_dict.values():
                        while dq and dq[0][0] < cutoff:
                            dq.popleft()
                    if all(len(dq) == 0 for dq in scan_dict.values()):
                        dead_ips.append(ip)
                for ip in dead_ips:
                    del self._windows[ip]
