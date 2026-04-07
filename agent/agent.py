"""
NIDS Agent — main entry point.

Starts all subsystem threads and runs packet capture in the main thread.
Handles SIGINT/SIGTERM for graceful shutdown.

Usage:
  python agent.py [--no-capture]   (--no-capture useful for testing without root)
"""
import signal
import sys
import threading
import time

from agent.config import AgentConfig
from agent.blocklist import LocalBlocklist
from agent.reporter import Reporter
from agent.sync import Syncer
from agent.capture import PacketCapture


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
alert_queue: list = []
queue_lock = threading.Lock()


def main():
    no_capture = "--no-capture" in sys.argv

    print("=" * 60)
    print(f"  NIDS Agent — {AgentConfig.AGENT_NAME}")
    print(f"  Server : {AgentConfig.SERVER_URL}")
    print(f"  Iface  : {AgentConfig.INTERFACE or 'auto-detect'}")
    print("=" * 60)

    if not AgentConfig.AGENT_TOKEN:
        print("[agent] ERROR: AGENT_TOKEN is not set. Register first with install_agent.sh.", file=sys.stderr)
        sys.exit(1)

    # Shared components
    local_blocklist = LocalBlocklist()
    reporter = Reporter(alert_queue, queue_lock, local_blocklist)
    syncer   = Syncer(local_blocklist)

    # ---------------------------------------------------------------------------
    # Daemon threads
    # ---------------------------------------------------------------------------
    threads = [
        threading.Thread(target=reporter.start_batch_reporter, name="batch-reporter", daemon=True),
        threading.Thread(target=reporter.start_heartbeat,      name="heartbeat",      daemon=True),
        threading.Thread(target=syncer.start_blocklist_sync,   name="bl-sync",        daemon=True),
        threading.Thread(target=syncer.start_command_poll,     name="cmd-poll",       daemon=True),
    ]
    for t in threads:
        t.start()

    # ---------------------------------------------------------------------------
    # Packet capture (main thread or skipped)
    # ---------------------------------------------------------------------------
    capture = PacketCapture(local_blocklist, alert_queue, queue_lock)

    def _shutdown(signum, frame):
        print("\n[agent] Shutting down…")
        capture.stop()
        # Flush remaining queue before exit
        with queue_lock:
            remaining = list(alert_queue)
            alert_queue.clear()
        if remaining:
            print(f"[agent] Flushing {len(remaining)} unsent alert(s) to offline queue…")
            reporter._save_offline(remaining)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if no_capture:
        print("[agent] Capture disabled (--no-capture). Running reporter/sync threads only.")
        print("[agent] Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    else:
        # This call blocks until stop() is called or KeyboardInterrupt
        capture.start()


if __name__ == "__main__":
    main()
