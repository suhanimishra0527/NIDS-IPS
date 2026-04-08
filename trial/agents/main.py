import signal
import sys
import threading
import time

from agents.config.agent_config import config
from agents.enforcement.blocklist_cache import LocalBlocklist
from agents.communication.alert_sender import AlertSender
from agents.communication.heartbeat import HeartbeatManager
from agents.communication.config_sync import Syncer
from agents.capture.sniffer import PacketCapture
from agents.detection.engine import DetectionEngine

# Shared state
alert_queue = []
queue_lock = threading.Lock()

def main():
    print("=" * 60)
    print(f"  NIDS Agent — {config.AGENT_NAME}")
    print(f"  Interface : {config.INTERFACE or 'auto'}")
    print("=" * 60)

    if not config.AGENT_TOKEN:
        print("[agent] ERROR: AGENT_TOKEN is missing. Please register first.", file=sys.stderr)
        sys.exit(1)

    # 1. Initialize Components
    blocklist = LocalBlocklist()
    engine = DetectionEngine(alert_queue, queue_lock, blocklist)
    
    sender = AlertSender(alert_queue, queue_lock)
    heartbeat = HeartbeatManager(blocklist)
    syncer = Syncer(blocklist)
    
    capture = PacketCapture(engine)

    # 2. Start Communication Threads
    threads = [
        threading.Thread(target=sender.start, name="alert-sender", daemon=True),
        threading.Thread(target=heartbeat.start, name="heartbeat", daemon=True),
        threading.Thread(target=syncer.start_blocklist_sync, name="bl-sync", daemon=True),
        threading.Thread(target=syncer.start_command_poll, name="cmd-poll", daemon=True),
    ]
    for t in threads: t.start()

    # 3. Handle Shutdown
    def _shutdown(sig, frame):
        print("\n[agent] Shutting down gracefully...")
        capture.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # 4. Start Capture (Main Thread)
    if "--no-capture" in sys.argv:
        print("[agent] Running in NO-CAPTURE mode (Communication only).")
        while True: time.sleep(1)
    else:
        capture.start()

if __name__ == "__main__":
    main()
