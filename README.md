# Distributed NIDS+IPS System

A Python-based distributed **Network Intrusion Detection + Prevention System** with a central Flask/PostgreSQL/Redis server and multiple Scapy-based edge agents.

> **No machine learning** — purely signature-based and traffic-rate anomaly detection.

---

## Architecture (Single-OS Kali Linux)

```
┌─────────────────────────────────────────────────────┐
│                 Kali Linux Machine                  │
│                                                     │
│   ┌─────────────────────────────────────────────┐   │
│   │ Central Server (http://127.0.0.1:5000)      │   │
│   │ Flask REST API + Web Dashboard              │   │
│   │ PostgreSQL + Redis (Local)                  │   │
│   └───────▲──────────────────────────────▲──────┘   │
│           │ Local API Transfer (RAM)     │          │
│   ┌───────┴──────────────────────────────┴──────┐   │
│   │ Edge Agent (Running as Root)                │   │
│   │ Scapy (Listening on eth0/wlan0)             │   │
│   │ iptables (Real IPS Blocks)                  │   │
│   └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## Project Structure

```
NIDS TEST/
├── server/               # Central server
│   ├── app.py            # Flask app factory + heartbeat monitor
│   ├── config.py         # Env-var configuration
│   ├── database.py       # SQLAlchemy models
│   ├── redis_client.py   # Redis helpers
│   ├── auth.py           # JWT generation + decorator
│   ├── routes/
│   │   ├── auth.py       # POST /api/register
│   │   ├── agents.py     # POST /api/heartbeat, /api/metrics, GET /api/commands
│   │   ├── alerts.py     # POST /api/alerts
│   │   ├── blocklist.py  # GET|POST /api/global_blocklist, POST /api/command/block
│   │   └── dashboard.py  # Web dashboard (HTML + JSON)
│   ├── templates/        # Jinja2 dark-theme Bootstrap templates
│   ├── .env.example
│   └── requirements.txt
│
├── agent/                # Edge agent
│   ├── agent.py          # Main entrypoint + thread orchestration
│   ├── config.py         # Env-var configuration
│   ├── capture.py        # Scapy packet capture loop
│   ├── detection/
│   │   ├── signatures.py # SQLi / XSS / Directory Traversal (regex)
│   │   ├── port_scan.py  # SYN / FIN / NULL / XMAS scan (sliding window)
│   │   └── anomaly.py    # Per-IP rate anomaly (rolling 1s window)
│   ├── ips.py            # LOG / DROP / BLOCK + TCP RST engine
│   ├── blocklist.py      # Local blocklist (TTL-based, thread-safe)
│   ├── reporter.py       # Batch alerts + heartbeat + offline queue
│   ├── sync.py           # Global blocklist sync + command poll
│   ├── .env.example
│   └── requirements.txt
│
└── scripts/
    ├── install_server.sh  # Full server setup + systemd
    ├── install_agent.sh   # Full agent setup + systemd
    ├── server.service     # systemd unit (server)
    └── agent.service      # systemd unit (agent)
```

---

## Detection Rules

### Signature Detection (HTTP Payload)

| Attack | Patterns | Base Score |
|--------|----------|-----------|
| RCE / Cmd Inject | `wget`, `bash -i`, `nc -e`, Log4j `jndi:` | 99 |
| Botnets | User-Agents: `Mirai`, `Masscan`, `Kinsing` | 99 |
| SQL Injection | `UNION SELECT`, `OR 1=1`, `xp_cmdshell` | 95 |
| Directory Traversal | `../`, `%2F`, `/etc/passwd` | 95 |
| XSS | `<script>`, `onerror=`, `eval()` | 90 |

> Score guarantees an instant CRITICAL alert and an immediate iptables DROP.

### Port Scan Detection (Sliding Window)

| Scan Type | TCP Flags | Score |
|-----------|-----------|-------|
| XMAS Scan | FIN+PSH+URG (0x29) | 99 |
| NULL Scan | No flags (0x00) | 95 |
| FIN Scan | FIN only (0x01) | 95 |
| SYN Scan | SYN only (0x02) | 90 |

> Fires instantly when **5 unique destination ports** are hit within a 10-second window.

### Rate Anomaly (Per-IP PPS)

| Condition | Score | Severity |
|-----------|-------|----------|
| Source IP exceeds **50 pps** in 1-second window | 95 | CRITICAL |

---

## IPS Actions

| Threat Score | Action | Effect |
|---|---|---|
| < 30 | IGNORE | Packet passes through |
| 30 – 49 | LOG | Alert recorded, no enforcement |
| 50 – 79 | DROP | `iptables -I INPUT -s <ip> -j DROP` |
| 80+ | BLOCK | iptables DROP + TCP RST via Scapy + local blocklist (1h TTL) |

> **Windows / non-Linux**: IPS degrades to LOG-only. `iptables` and RST require root on Linux.

---

## Offline / Resilience

- Agents that cannot reach the server save alerts to **`offline_queue.jsonl`**
- On the next successful heartbeat, the offline queue is replayed and cleared
- Local blocklist and all detection continue to function with no server connection
- Server auto-marks agents `offline` after 90 seconds of missed heartbeats

---

## Configuration Reference

### Server (`/etc/nids/server.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 5000 | HTTP listen port |
| `HOST` | 0.0.0.0 | Bind address |
| `DATABASE_URL` | postgresql://… | PostgreSQL DSN |
| `REDIS_URL` | redis://localhost:6379/0 | Redis DSN |
| `JWT_SECRET` | — | HMAC secret for JWT signing |
| `AGENT_REGISTRATION_KEY` | changeme | Shared key for agent registration |
| `HEARTBEAT_TIMEOUT_SECONDS` | 90 | Seconds before agent marked offline |
| `AUTO_BLOCK_THREAT_SCORE` | 80 | Score threshold for auto-global-block |
| `BLOCKLIST_EXPIRY_SECONDS` | 86400 | Blocklist entry TTL (24 h) |

### Agent (`/etc/nids/agent.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_URL` | — | Central server base URL |
| `AGENT_NAME` | agent-1 | Unique agent identifier |
| `AGENT_TOKEN` | — | JWT from `/api/register` |
| `INTERFACE` | auto | Network interface for capture |
| `THREAT_SCORE_LOG` | 30 | Minimum score to log |
| `THREAT_SCORE_DROP` | 50 | Minimum score to DROP |
| `THREAT_SCORE_BLOCK` | 80 | Minimum score to BLOCK |
| `BATCH_INTERVAL_SEC` | 5 | Alert batch flush interval |
| `BATCH_MAX_ALERTS` | 10 | Flush immediately at this count |
| `HEARTBEAT_INTERVAL` | 30 | Seconds between heartbeats |
| `SYNC_INTERVAL` | 60 | Seconds between blocklist syncs |
| `LOCAL_BLOCK_TTL` | 3600 | Local block expiry (1 hour) |
| `PORTSCAN_THRESHOLD` | 20 | Unique ports to trigger scan alert |
| `PORTSCAN_WINDOW_SEC` | 10 | Port scan detection window |
| `ANOMALY_PPS_THRESHOLD` | 500 | Packets/sec to trigger rate alert |

---

## Production Notes

1. **Reverse proxy**: Place Nginx in front of the Flask server for TLS termination.
2. **iptables persistence**: Use `iptables-persistent` (`apt install iptables-persistent`) to survive reboots.
3. **Logs**: `journalctl -u nids-server -f` / `journalctl -u nids-agent -f`
4. **Dashboard access**: Restrict with Nginx `auth_basic` or VPN in production.
5. **Multiple agents**: Run `install_agent.sh` on each host with a unique `AGENT_NAME`.

---

## License

MIT
