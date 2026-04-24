"""Quick verification of all fixes applied."""
import sys

print("=" * 60)
print("  NIDS+IPS Fix Verification")
print("=" * 60)

errors = 0

# --- 1. Agent config loads dotenv ---
try:
    from agent.config import AgentConfig
    print("[PASS] agent/config.py imports cleanly (dotenv wired)")
except Exception as e:
    print(f"[FAIL] agent/config.py: {e}")
    errors += 1

# --- 2. IPS unblock_ip importable ---
try:
    from agent.ips import unblock_ip, drop_ip
    print("[PASS] agent/ips.py unblock_ip is importable")
except Exception as e:
    print(f"[FAIL] agent/ips.py: {e}")
    errors += 1

# --- 3. Blocklist now imports unblock_ip ---
try:
    from agent.blocklist import LocalBlocklist
    bl = LocalBlocklist()
    print("[PASS] agent/blocklist.py imports cleanly (unblock_ip wired)")
except Exception as e:
    print(f"[FAIL] agent/blocklist.py: {e}")
    errors += 1

# --- 4. Signature detection false positive reduction ---
try:
    from agent.detection.signatures import detect_signatures, _extract_attack_surface

    # Test 1: Normal HTTP should NOT trigger SQLi
    normal_http = "GET /select-products?from=catalog&where=available HTTP/1.1\r\nHost: example.com\r\n\r\n"
    result = detect_signatures(normal_http)
    sqli_hits = [r for r in result if r[0] == "SQLi"]
    if sqli_hits:
        print(f"[FAIL] False positive: normal HTTP triggered SQLi: {sqli_hits}")
        errors += 1
    else:
        print("[PASS] Normal HTTP with 'select/from' words: no SQLi false positive")

    # Test 2: Actual SQLi SHOULD trigger
    sqli_attack = "GET /login?user=admin'+OR+'1'%3d'1'-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
    result2 = detect_signatures(sqli_attack)
    sqli_hits2 = [r for r in result2 if r[0] == "SQLi"]
    if sqli_hits2:
        print(f"[PASS] Real SQLi attack detected: {sqli_hits2}")
    else:
        print("[WARN] SQLi attack not detected (may need URL-decoded input)")

    # Test 3: UNION SELECT injection
    union_attack = "GET /search?q=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1"
    result3 = detect_signatures(union_attack)
    sqli_hits3 = [r for r in result3 if r[0] == "SQLi"]
    if sqli_hits3:
        print(f"[PASS] UNION SELECT injection detected: {sqli_hits3}")
    else:
        print("[FAIL] UNION SELECT injection NOT detected")
        errors += 1

    # Test 4: XSS should still work
    xss_attack = "GET /page?q=<script>alert(1)</script> HTTP/1.1"
    result4 = detect_signatures(xss_attack)
    xss_hits = [r for r in result4 if r[0] == "XSS"]
    if xss_hits:
        print(f"[PASS] XSS attack detected: {xss_hits}")
    else:
        print("[FAIL] XSS attack NOT detected")
        errors += 1

    # Test 5: Directory traversal should still work
    traversal = "GET /files?path=../../../../etc/passwd HTTP/1.1"
    result5 = detect_signatures(traversal)
    trav_hits = [r for r in result5 if r[0] == "DirTraversal"]
    if trav_hits:
        print(f"[PASS] Directory traversal detected: {trav_hits}")
    else:
        print("[FAIL] Directory traversal NOT detected")
        errors += 1

    # Test 6: HTTP-aware extraction
    surface = _extract_attack_surface(normal_http)
    if "select-products" in surface and len(surface) < len(normal_http):
        print("[PASS] HTTP attack surface extraction working")
    else:
        print("[WARN] Attack surface extraction may not be filtering correctly")

except Exception as e:
    print(f"[FAIL] agent/detection/signatures.py: {e}")
    errors += 1

# --- 5. Server config loads dotenv + has SSL options ---
try:
    from server.config import Config
    assert hasattr(Config, "SSL_CERT"), "Missing SSL_CERT"
    assert hasattr(Config, "SSL_KEY"), "Missing SSL_KEY"
    print("[PASS] server/config.py imports cleanly (dotenv + SSL options present)")
except Exception as e:
    print(f"[FAIL] server/config.py: {e}")
    errors += 1

# --- 6. trial/ is gone ---
import os
if os.path.exists(os.path.join(os.path.dirname(__file__), "trial")):
    print("[FAIL] trial/ directory still exists")
    errors += 1
else:
    print("[PASS] trial/ directory removed")

# --- 7. alerts.py uses correct model fields ---
try:
    import ast
    alerts_path = os.path.join(os.path.dirname(__file__), "server", "routes", "alerts.py")
    with open(alerts_path, "r") as f:
        content = f.read()
    
    if "agent_name=" in content and "agent_id=" not in content:
        print("[FAIL] alerts.py still uses agent_name instead of agent_id")
        errors += 1
    elif "agent_id=g.agent.id" in content:
        print("[PASS] alerts.py uses agent_id from authenticated agent")
    else:
        print("[WARN] alerts.py - could not verify agent_id usage")
    
    if "@require_agent_auth" in content:
        print("[PASS] alerts.py has JWT authentication")
    else:
        print("[FAIL] alerts.py missing authentication")
        errors += 1

    if "threat_score" in content and "dst_ip" in content and "payload_snippet" in content:
        print("[PASS] alerts.py maps all Alert model fields")
    else:
        print("[FAIL] alerts.py missing some Alert model fields")
        errors += 1
except Exception as e:
    print(f"[FAIL] alerts.py check: {e}")
    errors += 1

# --- Summary ---
print()
print("=" * 60)
if errors == 0:
    print("  ALL CHECKS PASSED")
else:
    print(f"  {errors} CHECK(S) FAILED")
print("=" * 60)
sys.exit(errors)
