import sys
import threading
from agents.config.agent_config import config

class PacketCapture:
    """
    Focused Scapy capture module. Simply sniffs and hands off to the engine.
    """
    def __init__(self, engine):
        self._engine = engine
        self._running = False
        self._iface = config.INTERFACE or self._get_default_interface()

    def start(self):
        """Start sniffing (blocking)."""
        try:
            from scapy.sendrecv import sniff
        except ImportError:
            print("[capture] ERROR: Scapy not installed.", file=sys.stderr)
            return

        self._running = True
        print(f"[capture] Sniffing on interface: {self._iface or 'auto'}")
        
        sniff(
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: not self._running,
            iface=self._iface if self._iface else None
        )

    def stop(self):
        self._running = False

    def _process_packet(self, pkt):
        try:
            self._engine.analyze(pkt)
        except Exception as e:
            print(f"[capture] Handler error: {e}", file=sys.stderr)

    @staticmethod
    def _get_default_interface() -> str:
        try:
            import scapy.config
            for iface in scapy.config.conf.ifaces.keys():
                if iface not in ("lo", "lo0", "localhost"):
                    return str(iface)
        except: pass
        return ""
