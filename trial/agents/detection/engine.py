import threading
from typing import List
from agents.detection.signature import SignatureDetector
from agents.detection.anomaly import AnomalyDetector
from agents.detection.port_scan import PortScanDetector

class DetectionEngine:
    def __init__(self, alert_queue: List, queue_lock: threading.Lock, blocklist):
        self._queue = alert_queue
        self._lock = queue_lock
        self._blocklist = blocklist
        
        # Initialize sub-detectors
        self.signatures = SignatureDetector()
        self.anomaly = AnomalyDetector()
        self.port_scan = PortScanDetector()

    def analyze(self, packet):
        """Analyze a packet through all detection modules."""
        # 1. Anomaly checks (Rate-based)
        alert = self.anomaly.check(packet)
        if alert: self._report(alert)

        # 2. Port scan checks
        alert = self.port_scan.check(packet)
        if alert: self._report(alert)

        # 3. Signature checks (Payload-based)
        alert = self.signatures.check(packet)
        if alert: self._report(alert)

    def _report(self, alert: dict):
        """Add alert to shared queue for reporting."""
        with self._lock:
            self._queue.append(alert)
