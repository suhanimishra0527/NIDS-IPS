"""
IPS Engine — decides action and pushes alerts to queue.
"""

from datetime import datetime
from agent.config import AgentConfig

def unblock_ip(ip: str):
    """Placeholder for unblocking an IP (usually iptables on Linux)"""
    pass


def decide_and_act(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    attack_type,
    threat_score,
    payload_snippet,
    local_blocklist,
    alert_queue,
    queue_lock
):
    """
    Core IPS decision engine:
    - Assign severity
    - Decide action (ALLOW / DROP / BLOCK)
    - Optionally block IP
    - Push alert to queue (CRITICAL PART)
    """

    # -----------------------------
    # Severity + Action Logic
    # -----------------------------
    severity = "LOW"
    action = "ALLOW"

    if threat_score >= AgentConfig.THREAT_SCORE_BLOCK:
        severity = "CRITICAL"
        action = "BLOCK"
        local_blocklist.block(src_ip)

    elif threat_score >= AgentConfig.THREAT_SCORE_DROP:
        severity = "HIGH"
        action = "DROP"

    elif threat_score >= AgentConfig.THREAT_SCORE_LOG:
        severity = "MEDIUM"
        action = "MONITOR"

    else:
        severity = "LOW"
        action = "ALLOW"

    # -----------------------------
    # Build alert object
    # -----------------------------
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "attack_type": attack_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "threat_score": threat_score,
        "severity": severity,
        "action_taken": action,
        "payload_snippet": payload_snippet[:200] if payload_snippet else ""
    }

    # -----------------------------
    # 🔥 CRITICAL: PUSH TO QUEUE
    # -----------------------------
    try:
        with queue_lock:
            alert_queue.append(alert)
        
        # INSTANT ALERTING: If it's a critical attack, force the Reporter to flush immediately
        # We don't want to wait 5 seconds for the batch timer when under active attack.
        if severity == "CRITICAL":
            # We signal the Reporter thread by artificially bumping the queue size over the max
            # This makes the reporter thread wake up and instantly transmit the alert to the API.
            pass # The reporter thread already polls every 0.5s for size >= max_items
                 # To force it instantly, we could just trigger the HTTP request right here, 
                 # but we want to keep network I/O out of the packet capture thread.
                 # Let's import requests and send it instantly in the background.
            import threading
            from agent.config import AgentConfig
            import requests

            def _instant_fire(alert_data):
                try:
                    requests.post(
                        f"{AgentConfig.SERVER_URL}/api/alerts",
                        json=[alert_data],
                        headers={"Authorization": f"Bearer {AgentConfig.AGENT_TOKEN}", "Content-Type": "application/json"},
                        timeout=3
                    )
                except Exception:
                    pass
            
            # Fire and forget
            threading.Thread(target=_instant_fire, args=(alert,), daemon=True).start()

    except Exception as e:
        print(f"[IPS ERROR] Failed to push alert: {e}")

    # -----------------------------
    # Debug (optional but useful)
    # -----------------------------
    print(
        f"[ALERT] {attack_type} | {src_ip}:{src_port} → {dst_ip}:{dst_port} "
        f"| {protocol} | score={threat_score} | {severity} | {action}"
    )