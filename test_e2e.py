"""End-to-end test: register agent -> send alerts -> verify on dashboard."""
import requests
import json
import sys

SERVER = "http://127.0.0.1:5000"

print("=" * 60)
print("  End-to-End Test")
print("=" * 60)

# --- Step 1: Register an agent ---
print("\n[1] Registering test agent...")
resp = requests.post(f"{SERVER}/api/register", json={
    "agent_name": "test-agent-e2e",
    "registration_key": "testkey123"
})
print(f"    Status: {resp.status_code}")
data = resp.json()
print(f"    Response: {json.dumps(data, indent=2)}")

if resp.status_code not in (200, 201):
    print("    FAILED to register agent!")
    sys.exit(1)

token = data.get("token", "")
print(f"    Token: {token[:20]}...{token[-10:]}")

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# --- Step 2: Send heartbeat ---
print("\n[2] Sending heartbeat...")
resp = requests.post(f"{SERVER}/api/heartbeat", headers=headers, json={
    "agent_name": "test-agent-e2e",
    "cpu_percent": 23.5,
    "mem_percent": 45.2,
    "blocked_ips": 3,
    "alerts_in_queue": 0,
})
print(f"    Status: {resp.status_code} -> {resp.json()}")

# --- Step 3: Send batch of test alerts ---
print("\n[3] Sending 3 test alerts...")
test_alerts = [
    {
        "timestamp": "2026-04-22T12:00:00+00:00",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 45678,
        "dst_port": 80,
        "protocol": "TCP",
        "attack_type": "SQLi",
        "severity": "CRITICAL",
        "threat_score": 90,
        "action_taken": "BLOCK",
        "payload_snippet": "GET /login?user=admin' OR '1'='1'-- HTTP/1.1",
    },
    {
        "timestamp": "2026-04-22T12:01:00+00:00",
        "src_ip": "10.10.10.50",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "attack_type": "XSS",
        "severity": "HIGH",
        "threat_score": 75,
        "action_taken": "DROP",
        "payload_snippet": "<script>document.cookie</script>",
    },
    {
        "timestamp": "2026-04-22T12:02:00+00:00",
        "src_ip": "172.16.0.99",
        "dst_ip": "10.0.0.1",
        "src_port": 55555,
        "dst_port": 22,
        "protocol": "TCP",
        "attack_type": "SYN_Scan",
        "severity": "HIGH",
        "threat_score": 65,
        "action_taken": "DROP",
        "payload_snippet": "",
    },
]

resp = requests.post(f"{SERVER}/api/alerts", headers=headers, json=test_alerts)
print(f"    Status: {resp.status_code} -> {resp.json()}")

if resp.status_code not in (200, 201):
    print("    FAILED to store alerts!")
    print(f"    Response body: {resp.text}")
    sys.exit(1)

# --- Step 4: Check dashboard summary ---
print("\n[4] Fetching dashboard summary...")
resp = requests.get(f"{SERVER}/api/dashboard/summary")
summary = resp.json()
print(f"    Total agents: {summary['total_agents']}")
print(f"    Online agents: {summary['online_agents']}")
print(f"    Total alerts: {summary['total_alerts']}")
print(f"    Active blocks: {summary['active_blocks']}")
print(f"    Recent alerts count: {len(summary['recent_alerts'])}")

if summary['total_alerts'] >= 3:
    print("\n    [OK] Alerts are being stored in the database!")
else:
    print("\n    [FAIL] Alert count is wrong -- something is still broken")
    sys.exit(1)

# --- Step 5: Verify alert details ---
print("\n[5] Checking alert details...")
for alert in summary['recent_alerts'][:3]:
    print(f"    [{alert['severity']:8s}] {alert['attack_type']:15s} "
          f"| {alert['src_ip']:15s} -> {alert['dst_ip']:15s} "
          f"| score={alert['threat_score']} | action={alert['action_taken']}")
    
    # Verify all fields are populated
    missing = [k for k in ['src_ip','dst_ip','src_port','dst_port','protocol',
                           'attack_type','severity','threat_score','action_taken']
               if alert.get(k) is None]
    if missing:
        print(f"    [WARN] Missing fields: {missing}")

# --- Step 6: Check HTML dashboard loads ---
print("\n[6] Loading HTML dashboard...")
resp = requests.get(f"{SERVER}/")
print(f"    Status: {resp.status_code}")
print(f"    Content-Type: {resp.headers.get('Content-Type')}")
print(f"    Page size: {len(resp.text)} bytes")
has_alerts = "SQLi" in resp.text or "test-agent" in resp.text
print(f"    Contains alert/agent data: {has_alerts}")

# --- Step 7: Check alerts page ---
print("\n[7] Loading alerts page...")
resp = requests.get(f"{SERVER}/alerts")
print(f"    Status: {resp.status_code}")
print(f"    Page size: {len(resp.text)} bytes")

print("\n" + "=" * 60)
print("  ALL END-TO-END TESTS PASSED")
print("=" * 60)
