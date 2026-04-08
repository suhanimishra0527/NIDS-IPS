"""
Signature-based detection for HTTP payloads.
Detects: SQL Injection, XSS, Directory Traversal.
Returns a list of (attack_type, threat_score) tuples for all matches found.
"""
import re
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

_SQLI_PATTERNS = [
    re.compile(r"(union[\s+]select)", re.IGNORECASE),
    re.compile(r"('\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+'?)", re.IGNORECASE),
    re.compile(r"(--\s*$)", re.IGNORECASE | re.MULTILINE),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"xp_cmdshell", re.IGNORECASE),
    re.compile(r"exec(\s|\+)+(s|x)p\w+", re.IGNORECASE),
    re.compile(r"(insert|update|delete|select).+(from|into|where|set)", re.IGNORECASE),
    re.compile(r"waitfor\s+delay", re.IGNORECASE),
    re.compile(r"benchmark\(\d+,", re.IGNORECASE),
    re.compile(r"sleep\(\d+\)", re.IGNORECASE),
    re.compile(r"char\(\d+\)", re.IGNORECASE),
    re.compile(r"0x[0-9a-f]{4,}", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"</script>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouse\w+|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"<\s*iframe", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src\s*=\s*[\"']?\s*javascript", re.IGNORECASE),
    re.compile(r"document\.(cookie|location|write)", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"expression\s*\(", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
]

_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"\.\.%2[fF]", re.IGNORECASE),
    re.compile(r"\.\.%5[cC]", re.IGNORECASE),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|hosts|group)", re.IGNORECASE),
    re.compile(r"/proc/self", re.IGNORECASE),
    re.compile(r"(boot\.ini|win\.ini|system32)", re.IGNORECASE),
]

_SIGNATURES = [
    ("SQLi",       _SQLI_PATTERNS,      85),
    ("XSS",        _XSS_PATTERNS,       75),
    ("DirTraversal", _TRAVERSAL_PATTERNS, 80),
]

class SignatureDetector:
    def check(self, packet) -> List[Tuple[str, int]]:
        """Scan packet payload for known attack signatures."""
        payload = self._extract_payload(packet)
        if not payload:
            return []

        matches = []
        for name, patterns, base_score in _SIGNATURES:
            hit_count = sum(1 for p in patterns if p.search(payload))
            if hit_count > 0:
                score = min(base_score + (hit_count - 1) * 2, base_score + 10)
                matches.append((name, score))

        return matches

    @staticmethod
    def _extract_payload(pkt) -> str:
        """Extract raw payload bytes and decode as UTF-8."""
        try:
            # Check for TCP/UDP layers that might have payload
            if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
                raw = bytes(pkt.lastlayer().payload)
                if not raw: return ""
                return raw.decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""
