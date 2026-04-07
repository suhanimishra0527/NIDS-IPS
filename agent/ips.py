"""
IPS (Intrusion Prevention System) engine.

Decides action based on threat score thresholds:
  < LOG_THRESHOLD  → ignore
  LOG_THRESHOLD..DROP_THRESHOLD-1  → LOG only
  DROP_THRESHOLD..BLOCK_THRESHOLD-1 → DROP (temp iptables rule)
  >= BLOCK_THRESHOLD → BLOCK (iptables + TCP RST) + local blocklist

iptables and RST require root/sudo on Linux.
On non-Linux platforms the engine degrades gracefully to LOG-only.
"""
import platform
import subprocess
import sys
import threading
from datetime import datetime, timezone

from agent.config import AgentConfig

_IS_LINUX = platform.system() == "Linux"
_iptables_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _run_iptables(args: list[str], check: bool = False) -> bool:
    """Run an iptables command. Returns True on success."""
    if not _IS_LINUX:
        return False
    try:
        with _iptables_lock:
            subprocess.run(
                ["iptables"] + args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=check,
            )
        return True
    except Exception as exc:
        print(f"[ips] iptables error: {exc}", file=sys.stderr)
        return False


def _send_tcp_rst(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> None:
    """Send a TCP RST to terminate an existing connection."""
    if not _IS_LINUX:
        return
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import send
        rst_pkt = (
            IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dst_port, dport=src_port, flags="R", seq=0)
        )
        send(rst_pkt, verbose=0)
    except Exception as exc:
        print(f"[ips] TCP RST error: {exc}", file=sys.stderr)


def drop_ip(src_ip: str) -> None:
    """Insert a DROP rule for the source IP (survives until removed or reboot)."""
    _run_iptables(["-I", "INPUT", "-s", src_ip, "-j", "DROP"])


def unblock_ip(src_ip: str) -> None:
    """Remove the DROP rule for a source IP."""
    _run_iptables(["-D", "INPUT", "-s", src_ip, "-j", "DROP"])


# ---------------------------------------------------------------------------
# Main IPS decision function
# ---------------------------------------------------------------------------

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
    queue_lock: threading.Lock,
) -> str:
    """
    Core IPS function. Evaluates threat score, applies firewall rules,
    appends a structured alert dict to the shared queue, and returns the
    action taken as a string.
    """
    log_thresh   = AgentConfig.THREAT_SCORE_LOG
    drop_thresh  = AgentConfig.THREAT_SCORE_DROP
    block_thresh = AgentConfig.THREAT_SCORE_BLOCK

    action = "IGNORE"
    severity = _score_to_severity(threat_score)

    if threat_score < log_thresh:
        return "IGNORE"

    if threat_score < drop_thresh:
        action = "LOG"

    elif threat_score < block_thresh:
        action = "DROP"
        drop_ip(src_ip)

    else:
        action = "BLOCK"
        # Permanent iptables rule
        drop_ip(src_ip)
        # TCP RST to terminate active connection
        _send_tcp_rst(src_ip, dst_ip, src_port or 0, dst_port or 0)
        # Add to local blocklist
        local_blocklist.block(src_ip)

    alert = {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "src_ip":          src_ip,
        "dst_ip":          dst_ip,
        "src_port":        src_port,
        "dst_port":        dst_port,
        "protocol":        protocol,
        "attack_type":     attack_type,
        "severity":        severity,
        "threat_score":    threat_score,
        "action_taken":    action,
        "payload_snippet": payload_snippet[:256] if payload_snippet else "",
    }

    with queue_lock:
        alert_queue.append(alert)

    print(
        f"[IPS] {action:5s} | score={threat_score:3d} | {attack_type:20s} | "
        f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
    )
    return action


def _score_to_severity(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"
