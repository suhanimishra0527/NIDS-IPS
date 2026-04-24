"""
Scapy-based live packet capture loop.

Runs in its own thread (or the main thread if preferred).
For each packet:
  1. Skip if src_ip is in the local blocklist (already handled).
  2. Run anomaly detector (rate check).
  3. For TCP: run port scan detector + signature detection on payload.
  4. For UDP/any HTTP-like: run signature detection.
  5. If any detector fires, call IPS engine.
"""
import sys
import threading

from agent.config import AgentConfig
from agent.detection.anomaly import AnomalyDetector
from agent.detection.port_scan import PortScanDetector
from agent.detection.signatures import detect_signatures
from agent.ips import decide_and_act


def _get_default_interface() -> str:
    """Return first non-loopback network interface, or empty string."""
    try:
        import scapy.config
        ifaces = list(scapy.config.conf.ifaces.keys())
        for iface in ifaces:
            if iface not in ("lo", "lo0", "localhost"):
                return iface
    except Exception:
        pass
    return ""


class PacketCapture:
    """
    Manages Scapy live capture and feeds packets through the detection pipeline.
    """

    def __init__(self, local_blocklist, alert_queue: list, queue_lock: threading.Lock):
        self._blocklist    = local_blocklist
        self._alert_queue  = alert_queue
        self._queue_lock   = queue_lock
        self._running      = False

        self._anomaly  = AnomalyDetector()
        self._portscan = PortScanDetector()

        self._iface = AgentConfig.INTERFACE or _get_default_interface()
        self._bpf   = AgentConfig.CAPTURE_FILTER

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Start sniffing using AsyncSniffer for robust threading and performance."""
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError:
            print("[capture] Scapy not installed — capture disabled.", file=sys.stderr)
            return

        self._running = True
        kwargs = {
            "prn":     self._process_packet,
            "filter":  self._bpf,
            "store":   False,
        }
        if self._iface:
            kwargs["iface"] = self._iface

        print(f"[capture] Sniffing on interface '{self._iface or 'default'}' with filter '{self._bpf}'")
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        
        # Keep the thread alive while running
        import time
        while self._running:
            time.sleep(1)

    def stop(self):
        self._running = False
        if hasattr(self, '_sniffer') and self._sniffer.running:
            self._sniffer.stop()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _process_packet(self, pkt):
        try:
            self._handle(pkt)
        except Exception as exc:
            print(f"[capture] packet handler error: {exc}", file=sys.stderr)

    def _handle(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # 1. Skip already-blocked IPs silently
        if self._blocklist.is_blocked(src_ip):
            return

        # DEBUG VISIBILITY: Packet received
        # print(f"[capture debug] Received IP packet {src_ip} -> {dst_ip}")

        # 2. Rate anomaly check (all IP packets)
        result = self._anomaly.process_packet(src_ip)
        if result:
            attack_type, score, _ = result
            decide_and_act(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=0, dst_port=0,
                protocol="IP",
                attack_type=attack_type,
                threat_score=score,
                payload_snippet="",
                local_blocklist=self._blocklist,
                alert_queue=self._alert_queue,
                queue_lock=self._queue_lock,
            )
            return  # Rate anomaly takes priority; skip further checks this packet

        # 3. TCP-specific checks
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags_int = int(tcp.flags)

            print(f"[capture debug] TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} flags={flags_int}")

            # Port scan detection
            ps_result = self._portscan.process_packet(src_ip, dst_port, flags_int)
            if ps_result:
                attack_type, score, _, _ = ps_result
                decide_and_act(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol="TCP",
                    attack_type=attack_type,
                    threat_score=score,
                    payload_snippet="",
                    local_blocklist=self._blocklist,
                    alert_queue=self._alert_queue,
                    queue_lock=self._queue_lock,
                )
                return

            # Signature detection on TCP payload
            payload = self._extract_payload(pkt)
            if payload:
                sig_results = detect_signatures(payload)
                for attack_type, score in sig_results:
                    decide_and_act(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=src_port, dst_port=dst_port,
                        protocol="TCP",
                        attack_type=attack_type,
                        threat_score=score,
                        payload_snippet=payload[:256],
                        local_blocklist=self._blocklist,
                        alert_queue=self._alert_queue,
                        queue_lock=self._queue_lock,
                    )

        # 4. UDP payload signature check
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            print(f"[capture debug] UDP {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}")
            payload = self._extract_payload(pkt)
            if payload:
                sig_results = detect_signatures(payload)
                for attack_type, score in sig_results:
                    decide_and_act(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=udp.sport, dst_port=udp.dport,
                        protocol="UDP",
                        attack_type=attack_type,
                        threat_score=score,
                        payload_snippet=payload[:256],
                        local_blocklist=self._blocklist,
                        alert_queue=self._alert_queue,
                        queue_lock=self._queue_lock,
                    )

    @staticmethod
    def _extract_payload(pkt) -> str:
        """Robustly extract raw payload bytes using Scapy's Raw layer and decode as UTF-8."""
        from scapy.packet import Raw
        try:
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                if not raw:
                    return ""
                return raw.decode("utf-8", errors="replace")
            return ""
        except Exception:
            return ""
