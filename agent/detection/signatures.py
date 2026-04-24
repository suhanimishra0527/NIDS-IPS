"""
Signature-based detection for HTTP payloads.
Detects: SQL Injection, XSS, Directory Traversal.
Returns a list of (attack_type, threat_score) tuples for all matches found.

HTTP-aware: extracts URI/query-string from request lines before matching,
so normal HTML body text containing words like "select" or "from" won't
trigger false positives.
"""
import re

# ---------------------------------------------------------------------------
# HTTP pre-processing
# ---------------------------------------------------------------------------

# Matches an HTTP request line: "GET /path?foo=bar HTTP/1.1"
_HTTP_REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_attack_surface(payload: str) -> str:
    """
    Extract the parts of an HTTP payload most likely to contain attacks:
    the URI, query parameters, and any POST body that looks form-encoded
    or JSON-ish. If no HTTP structure is detected, return the raw payload
    (it might be a non-HTTP protocol, and we still want to scan it).
    """
    parts = []

    # Pull out the request URI (contains path + query string)
    m = _HTTP_REQUEST_LINE.search(payload)
    if m:
        parts.append(m.group(2))  # e.g. "/login?user=admin' OR 1=1--"

    # If there's a blank-line separated body (POST body), include it
    body_sep = payload.find("\r\n\r\n")
    if body_sep == -1:
        body_sep = payload.find("\n\n")
    if body_sep != -1:
        body = payload[body_sep:].strip()
        if body:
            parts.append(body)

    # If we found HTTP structure, scan only the extracted parts
    if parts:
        return "\n".join(parts)

    # Not HTTP — scan the whole thing (could be raw TCP data)
    return payload


# ---------------------------------------------------------------------------
# Signature definitions
# Each entry: (name, compiled_pattern, threat_score)
# ---------------------------------------------------------------------------

_SQLI_PATTERNS = [
    re.compile(r"union(\s|\+|%20)+(all(\s|\+|%20)+)?select(\s|\+|%20)", re.IGNORECASE),
    re.compile(r"['\"]\s*(or|and)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
    re.compile(r"['\"]\s*;\s*--", re.IGNORECASE),
    re.compile(r"['\"]\s*--\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r";\s*(drop|alter|truncate)\s+table\b", re.IGNORECASE),
    re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
    re.compile(r"\bexec(\s|\+)+(s|x)p\w+", re.IGNORECASE),
    re.compile(r"(select\s+.{1,80}\bfrom\s+\w+.*('|--|;|/\*|\*/|\bunion\b))", re.IGNORECASE),
    re.compile(r"\b(insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.IGNORECASE),
    re.compile(r"\bwaitfor\s+delay\b", re.IGNORECASE),
    re.compile(r"\bbenchmark\s*\(\s*\d+\s*,", re.IGNORECASE),
    re.compile(r"\bsleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"\bchar\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"0x[0-9a-f]{8,}", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"</script\s*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\bon(error|load|click|mouse\w+|focus|blur|submit|change)\s*=", re.IGNORECASE),
    re.compile(r"<\s*iframe", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+\bsrc\s*=\s*[\"']?\s*javascript", re.IGNORECASE),
    re.compile(r"\bdocument\s*\.\s*(cookie|location|write)", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexpression\s*\(", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
]

_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"\.\.%2[fF]", re.IGNORECASE),
    re.compile(r"\.\.%5[cC]", re.IGNORECASE),
    re.compile(r"%2e%2e(%2f|%5c)", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|hosts|group)\b", re.IGNORECASE),
    re.compile(r"/proc/self/", re.IGNORECASE),
    re.compile(r"\b(boot\.ini|win\.ini)\b", re.IGNORECASE),
    re.compile(r"\\system32\\", re.IGNORECASE),
]

_RCE_CMD_INJECTION_PATTERNS = [
    re.compile(r";\s*(wget|curl|nc|ncat|netcat|bash|sh|zsh|perl|python|ruby|php)\s+", re.IGNORECASE),
    re.compile(r"\|\s*(wget|curl|nc|ncat|netcat|bash|sh|zsh)\b", re.IGNORECASE),
    re.compile(r"&\s*(wget|curl|nc|ncat|netcat|bash|sh|zsh)\b", re.IGNORECASE),
    re.compile(r"\$\(\s*(wget|curl|nc|ncat|netcat|bash|sh|zsh|ls|cat|pwd)", re.IGNORECASE),
    re.compile(r"`\s*(wget|curl|nc|ncat|netcat|bash|sh|zsh|ls|cat|pwd)[^`]*`", re.IGNORECASE),
    re.compile(r"bash\s+-i", re.IGNORECASE),
    re.compile(r"nc\s+-e\s+/bin/", re.IGNORECASE),
    re.compile(r"\b(jndi|ldap|rmi|ldaps|dns):\/\/", re.IGNORECASE), # Log4j
]

_MALWARE_BOTNET_PATTERNS = [
    re.compile(r"User-Agent:\s*(masscan|zgrab|nmap|nikto|sqlmap|dirbuster|gobuster)", re.IGNORECASE),
    re.compile(r"User-Agent:\s*(Mirai|Kinsing|Mozi|Tsunami)", re.IGNORECASE),
    re.compile(r"\.php\?cmd=(wget|curl)", re.IGNORECASE),
    re.compile(r"/cgi-bin/(awstats|bash|sh)", re.IGNORECASE), # Shellshock
]

_SIGNATURES = [
    ("SQLi",         _SQLI_PATTERNS,             95),  # STRONGEST: Instant Block
    ("XSS",          _XSS_PATTERNS,              90),  # STRONGEST: Instant Block
    ("DirTraversal", _TRAVERSAL_PATTERNS,        95),  # STRONGEST: Instant Block
    ("RCE_Command",  _RCE_CMD_INJECTION_PATTERNS,99),  # STRONGEST: Instant Block
    ("MalwareBotnet",_MALWARE_BOTNET_PATTERNS,   99),  # STRONGEST: Instant Block
]


def detect_signatures(payload: str, method: str = "GET") -> list[tuple[str, int]]:
    """
    Scan payload for known attack signatures.

    First extracts the HTTP attack surface (URI, query string, POST body)
    to avoid matching normal HTML/text content. Falls back to full payload
    scanning for non-HTTP traffic.

    Args:
        payload: The raw packet payload decoded as text.
        method:  HTTP method (unused currently, reserved).

    Returns:
        List of (attack_type, threat_score) for each category that matched.
    """
    if not payload:
        return []

    # Focus detection on the attack surface, not the full page body
    target = _extract_attack_surface(payload)

    matches = []
    for name, patterns, base_score in _SIGNATURES:
        hit_count = sum(1 for p in patterns if p.search(target))
        if hit_count > 0:
            # Slightly bump score for multiple pattern hits (max +10)
            score = min(base_score + (hit_count - 1) * 2, base_score + 10)
            matches.append((name, score))

    return matches
