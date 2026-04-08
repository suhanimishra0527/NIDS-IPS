import threading
import time

class LocalBlocklist:
    def __init__(self):
        self._blocks = {} # ip -> expiry_timestamp
        self._lock = threading.Lock()

    def block(self, ip: str, ttl: int = 3600):
        with self._lock:
            self._blocks[ip] = time.time() + ttl

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            expiry = self._blocks.get(ip)
            if expiry and time.time() < expiry:
                return True
            if expiry: del self._blocks[ip]
        return False

    def count(self) -> int:
        with self._lock:
            return len(self._blocks)
