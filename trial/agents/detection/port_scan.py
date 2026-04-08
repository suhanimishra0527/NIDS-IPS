"""
Port scan detection: SYN, FIN, NULL, XMAS scans.
"""
import threading
import time
from collections import defaultdict, deque
from typing import Optional, Tuple
from agents.config.agent_config import config

class PortScanDetector:
    def __init__(self):
        self._lock = threading.Lock()
        self._windows = defaultdict(lambda: defaultdict(deque))
        threading.Thread(target=self._evict_loop, daemon=True).start()

    def check(self, packet) -> Optional[dict]:
        """Detect stealthier TCP scans."""
        if not packet.haslayer("TCP"):
            return None

        src_ip = packet["IP"].src
        dst_port = packet["TCP"].dport
        flags_int = int(packet["TCP"].flags)
        
        scan_type = self._classify_flags(flags_int)
        if not scan_type:
            return None

        now = time.monotonic()
        with self._lock:
            dq = self._windows[src_ip][scan_type]
            dq.append((now, dst_port))
            
            # Slide window
            cutoff = now - config.PORTSCAN_WINDOW_SEC
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            # Unique ports check
            unique_ports = len({p for _, p in dq})
            if unique_ports >= config.PORTSCAN_THRESHOLD:
                dq.clear()
                types = {"SYN": ("SYN_Scan", 65), "FIN": ("FIN_Scan", 70), "NULL": ("NULL_Scan", 75), "XMAS": ("XMAS_Scan", 70)}
                attack_type, score = types[scan_type]
                return {
                    "src_ip": src_ip,
                    "dst_ip": packet["IP"].dst,
                    "src_port": packet["TCP"].sport,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "attack_type": attack_type,
                    "threat_score": score,
                    "severity": "MEDIUM"
                }
        return None

    @staticmethod
    def _classify_flags(flags_int: int) -> Optional[str]:
        if flags_int == 0x02: return "SYN"
        if flags_int == 0x01: return "FIN"
        if flags_int == 0x00: return "NULL"
        if flags_int == 0x29: return "XMAS"
        return None

    def _evict_loop(self):
        while True:
            time.sleep(30)
            cutoff = time.monotonic() - config.PORTSCAN_WINDOW_SEC
            with self._lock:
                dead_ips = [ip for ip, sd in self._windows.items() if all(len(dq) == 0 for dq in sd.values())]
                for ip in dead_ips:
                    del self._windows[ip]
