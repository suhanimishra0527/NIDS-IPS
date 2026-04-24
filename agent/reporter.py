"""
Batch alert reporter and heartbeat sender.

Two responsibilities:
1. Flush the shared alert queue to the server every BATCH_INTERVAL_SEC seconds,
   OR immediately when it reaches BATCH_MAX_ALERTS items.
2. Send agent heartbeat to server every HEARTBEAT_INTERVAL seconds.

Offline handling:
- If server is unreachable, alerts are persisted to OFFLINE_QUEUE_FILE (JSONL).
- On reconnect, the offline queue is replayed before resuming normal batching.
"""
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from agent.config import AgentConfig


class Reporter:
    def __init__(self, alert_queue: list, queue_lock: threading.Lock, local_blocklist):
        self._queue      = alert_queue
        self._lock       = queue_lock
        self._blocklist  = local_blocklist
        # Create a robust session with automatic exponential backoff retries
        self._session    = requests.Session()
        
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        # Configure strong connection retries
        retry_strategy = Retry(
            total=5,  # Maximum number of retries
            backoff_factor=1,  # Wait 1, 2, 4, 8 seconds between retries
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        self._session.headers.update({
            "Authorization": f"Bearer {AgentConfig.AGENT_TOKEN}",
            "Content-Type":  "application/json",
            "User-Agent":    f"NIDS-Agent/{AgentConfig.AGENT_NAME}"
        })
        self._server_ok  = False          # Track server reachability
        self._offline_path = Path(AgentConfig.OFFLINE_QUEUE_FILE)

    # ------------------------------------------------------------------
    # Public threads
    # ------------------------------------------------------------------

    def start_batch_reporter(self):
        """Run the batch flush loop (blocking — call from a thread)."""
        interval = AgentConfig.BATCH_INTERVAL_SEC
        max_items = AgentConfig.BATCH_MAX_ALERTS
        while True:
            time.sleep(0.5)   # tight poll so we can react to size threshold
            with self._lock:
                size = len(self._queue)
            if size >= max_items or (size > 0 and self._time_to_flush(interval)):
                self._flush()

    def start_heartbeat(self):
        """Send heartbeat every HEARTBEAT_INTERVAL seconds (blocking — call from a thread)."""
        interval = AgentConfig.HEARTBEAT_INTERVAL
        while True:
            self._send_heartbeat()
            time.sleep(interval)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    _last_flush = 0.0

    def _time_to_flush(self, interval: int) -> bool:
        now = time.monotonic()
        if now - self._last_flush >= interval:
            self._last_flush = now
            return True
        return False

    def _flush(self):
        """Extract alerts from queue and ship to server (or persist offline)."""
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()

        if not batch:
            return

        # Prepend any previously-stored offline alerts on reconnect
        if self._server_ok and self._offline_path.exists():
            batch = self._load_offline() + batch

        if not self._send_alerts(batch):
            # Server unreachable — persist to disk
            self._save_offline(batch)
        else:
            self._server_ok = True
            # Remove offline file on successful send
            if self._offline_path.exists():
                self._offline_path.unlink()

    def _send_alerts(self, alerts: list) -> bool:
        url = f"{AgentConfig.SERVER_URL}/api/alerts"
        try:
            resp = self._session.post(url, json=alerts, timeout=10)
            if resp.status_code in (200, 201):
                print(f"[reporter] Sent {len(alerts)} alert(s) → {resp.json()}")
                return True
            print(f"[reporter] Server returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
            return False
        except requests.RequestException as exc:
            print(f"[reporter] Server unreachable: {exc}", file=sys.stderr)
            self._server_ok = False
            return False

    def _send_heartbeat(self):
        url = f"{AgentConfig.SERVER_URL}/api/heartbeat"
        metrics = self._collect_metrics()
        try:
            resp = self._session.post(url, json=metrics, timeout=8)
            if resp.status_code == 200:
                self._server_ok = True
                # If we just reconnected, try replaying offline queue
                if self._offline_path.exists():
                    self._flush_offline_on_reconnect()
        except requests.RequestException as exc:
            print(f"[reporter] Heartbeat failed: {exc}", file=sys.stderr)
            self._server_ok = False

    def _flush_offline_on_reconnect(self):
        """Replay offline-stored alerts now that we're back online."""
        stored = self._load_offline()
        if stored:
            print(f"[reporter] Replaying {len(stored)} offline alert(s)…")
            if self._send_alerts(stored):
                self._offline_path.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Offline persistence
    # ------------------------------------------------------------------

    def _save_offline(self, alerts: list):
        """Append alerts to the JSONL offline queue file."""
        try:
            with self._offline_path.open("a", encoding="utf-8") as f:
                for a in alerts:
                    f.write(json.dumps(a) + "\n")
            print(f"[reporter] Saved {len(alerts)} alert(s) to offline queue.")
        except OSError as exc:
            print(f"[reporter] Failed to save offline queue: {exc}", file=sys.stderr)

    def _load_offline(self) -> list:
        """Load and clear the JSONL offline queue file."""
        alerts = []
        try:
            with self._offline_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return alerts

    # ------------------------------------------------------------------
    # Metrics collection
    # ------------------------------------------------------------------

    def _collect_metrics(self) -> dict:
        metrics: dict = {
            "agent_name":     AgentConfig.AGENT_NAME,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "blocked_ips":    self._blocklist.count(),
        }
        try:
            import psutil
            metrics["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            metrics["mem_percent"] = psutil.virtual_memory().percent
        except ImportError:
            pass
        with self._lock:
            metrics["alerts_in_queue"] = len(self._queue)
        return metrics
