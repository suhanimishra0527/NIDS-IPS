"""
Agent configuration — driven entirely by environment variables.
Set these in /etc/nids/agent.env or export before running.
"""
import os


class AgentConfig:
    # Server connection
    SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:5000").rstrip("/")
    AGENT_NAME = os.environ.get("AGENT_NAME", "agent-1")
    AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")   # JWT from /api/register

    # Network capture
    INTERFACE = os.environ.get("INTERFACE", "")        # "" = auto-detect first non-loopback
    CAPTURE_FILTER = os.environ.get("CAPTURE_FILTER", "ip")  # BPF filter

    # IPS action thresholds
    THREAT_SCORE_LOG   = int(os.environ.get("THREAT_SCORE_LOG",   30))
    THREAT_SCORE_DROP  = int(os.environ.get("THREAT_SCORE_DROP",  50))
    THREAT_SCORE_BLOCK = int(os.environ.get("THREAT_SCORE_BLOCK", 80))

    # Reporting
    BATCH_INTERVAL_SEC = int(os.environ.get("BATCH_INTERVAL_SEC", 5))
    BATCH_MAX_ALERTS   = int(os.environ.get("BATCH_MAX_ALERTS",   10))
    HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", 30))
    SYNC_INTERVAL      = int(os.environ.get("SYNC_INTERVAL",      60))

    # Local blocklist TTL (seconds)
    LOCAL_BLOCK_TTL = int(os.environ.get("LOCAL_BLOCK_TTL", 3600))  # 1 hour

    # Offline queue persistence file
    OFFLINE_QUEUE_FILE = os.environ.get("OFFLINE_QUEUE_FILE", "offline_queue.jsonl")

    # Port scan detection
    PORTSCAN_WINDOW_SEC  = int(os.environ.get("PORTSCAN_WINDOW_SEC",  10))
    PORTSCAN_THRESHOLD   = int(os.environ.get("PORTSCAN_THRESHOLD",   20))

    # Anomaly detection (packets per second threshold per IP)
    ANOMALY_PPS_THRESHOLD = int(os.environ.get("ANOMALY_PPS_THRESHOLD", 500))
