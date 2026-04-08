import threading
import time
import json
import sys
from pathlib import Path
from typing import List
from agents.config.agent_config import config
from agents.communication.api_client import api_client

class AlertSender:
    def __init__(self, alert_queue: List, queue_lock: threading.Lock):
        self._queue = alert_queue
        self._lock = queue_lock
        self._offline_path = Path("agents/data/cache/offline_alerts.jsonl")
        self._last_flush = time.monotonic()

    def start(self):
        """Main loop for batch alert reporting (blocking)."""
        print("[alert-sender] Started batch reporting thread.")
        while True:
            time.sleep(0.5)
            with self._lock:
                queue_size = len(self._queue)
            
            elapsed = time.monotonic() - self._last_flush
            if queue_size >= 10 or (queue_size > 0 and elapsed >= 5):
                self._flush()

    def _flush(self):
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()
        
        self._last_flush = time.monotonic()
        if not batch: return

        # Try sending to server
        resp = api_client.post("/api/alerts", batch)
        if resp and resp.status_code in (200, 201):
            print(f"[alert-sender] Successfully sent {len(batch)} alerts.")
        else:
            self._save_offline(batch)

    def _save_offline(self, alerts: List):
        print(f"[alert-sender] Server unreachable. Saving {len(alerts)} alerts to offline storage.")
        try:
            self._offline_path.parent.mkdir(parents=True, exist_ok=True)
            with self._offline_path.open("a") as f:
                for alert in alerts:
                    f.write(json.dumps(alert) + "\n")
        except Exception as e:
            print(f"[alert-sender] ERROR: Failed to save offline: {e}", file=sys.stderr)
