import threading
import sys
from agents.config.agent_config import config
from agents.enforcement.firewall import Firewall

def decide_and_act(
    src_ip: str, 
    dst_ip: str, 
    src_port: int, 
    dst_port: int, 
    protocol: str, 
    attack_type: str, 
    threat_score: int, 
    payload_snippet: str,
    local_blocklist,
    alert_queue: list,
    queue_lock: threading.Lock
):
    """
    Core IPS decision engine:
    1. Determine action based on threat score and config thresholds.
    2. Enforce action (LOG, DROP, or BLOCK).
    3. Queue alert for reporting to server.
    """
    action = "LOG"
    if threat_score >= config.THREAT_SCORE_BLOCK:
        action = "BLOCK"
    elif threat_score >= config.THREAT_SCORE_DROP:
        action = "DROP"
    
    print(f"[ips] Detection: {attack_type} from {src_ip} (Score: {threat_score}, Action: {action})")

    # Enforcement
    if action == "BLOCK":
        local_blocklist.block(src_ip)
        Firewall.block_ip(src_ip)
    elif action == "DROP":
        Firewall.block_ip(src_ip) # For simple DROP we use firewall as well

    # Prepare alarm for batch reporting
    alert = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "attack_type": attack_type,
        "threat_score": threat_score,
        "action_taken": action,
        "payload_preview": payload_snippet[:256] if payload_snippet else None
    }

    with queue_lock:
        alert_queue.append(alert)
