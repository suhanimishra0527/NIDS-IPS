import subprocess
import sys

class Firewall:
    @staticmethod
    def block_ip(ip: str):
        """Enforce an IP block using iptables."""
        try:
            # Check if rule already exists to avoid duplicates
            check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
            if check.returncode != 0:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                print(f"[firewall] Blocked IP: {ip}")
        except Exception as e:
            print(f"[firewall] ERROR blocking {ip}: {e}", file=sys.stderr)

    @staticmethod
    def unblock_ip(ip: str):
        """Remove an IP block from iptables."""
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[firewall] Unblocked IP: {ip}")
        except Exception as e:
            pass # Rule likely didn't exist
