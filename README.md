# Distributed NIDS+IPS System

A Python-based distributed **Network Intrusion Detection + Prevention System** with a central Flask/PostgreSQL/Redis server and multiple Scapy-based edge agents.

> **No machine learning** — purely signature-based and traffic-rate anomaly detection.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Central Server                     │
│   Flask REST API + Web Dashboard                    │
│   PostgreSQL (alerts, agents, blocklist)            │
│   Redis (command queues, blocklist cache)           │
└──────────────────┬──────────────────────────────────┘
                   │  JWT-authenticated REST
       ┌───────────┼───────────┐
       ▼           ▼           ▼
  ┌─────────┐ ┌─────────┐ ┌─────────┐
  │ Agent 1 │ │ Agent 2 │ │ Agent N │
  │ Scapy   │ │ Scapy   │ │ Scapy   │
  │ iptables│ │ iptables│ │ iptables│
  └─────────┘ └─────────┘ └─────────┘
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

## Quick Start

| Component | Platform | Requirement |
|---|---|---|
| **Server** | Windows or Linux | Python 3.11+, PostgreSQL 14+, Redis 7+ |
| **Agent** | Linux only (root) | Python 3.11+, libpcap, iptables |

---

## Option A — Windows (Local Testing)

### 1. Start PostgreSQL + Redis via Docker

The fastest way on Windows — no manual DB install needed:

```yaml
# docker-compose.yml  (place in project root)
version: "3"
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: nids_user
      POSTGRES_PASSWORD: changeme
      POSTGRES_DB: nids_db
    ports: ["5432:5432"]
  redis:
    image: redis:7
    ports: ["6379:6379"]
```

```powershell
docker-compose up -d
```

Or install natively: [PostgreSQL for Windows](https://www.postgresql.org/download/windows/) + [Redis for Windows](https://github.com/tporadowski/redis/releases).  
Then create the database manually in pgAdmin / psql:

```sql
CREATE USER nids_user WITH PASSWORD 'changeme';
CREATE DATABASE nids_db OWNER nids_user;
GRANT ALL PRIVILEGES ON DATABASE nids_db TO nids_user;
```

### 2. Set up the Python environment

```powershell
cd "c:\Users\ASUS\Desktop\NIDS TEST\server"
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure environment variables (PowerShell)

```powershell
$env:DATABASE_URL           = "postgresql://nids_user:changeme@localhost:5432/nids_db"
$env:REDIS_URL              = "redis://localhost:6379/0"
$env:JWT_SECRET             = "change-me-to-something-long-and-random"
$env:AGENT_REGISTRATION_KEY = "changeme"
$env:PORT                   = "5000"
```

Or copy and edit the example env file:

```powershell
copy .env.example .env   # then edit .env in VS Code
```

### 4. Run the server

```powershell
python app.py
# → [NIDS Server] Starting on 0.0.0.0:5000
```

Open **http://localhost:5000** — the dashboard will be live.

### 5. Register a test agent

```powershell
# PowerShell
Invoke-WebRequest -Uri http://localhost:5000/api/register `
  -Method POST -ContentType "application/json" `
  -Body '{"agent_name":"test-agent","registration_key":"changeme"}'
```

Or with Python:

```python
import requests
r = requests.post("http://localhost:5000/api/register", json={
    "agent_name": "test-agent",
    "registration_key": "changeme"
})
print(r.json())  # → {"token": "eyJ..."}
```

---

## Option B — Linux (Production)

### Server — Manual

```bash
cd server
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
nano .env   # Set DATABASE_URL, REDIS_URL, JWT_SECRET, AGENT_REGISTRATION_KEY

source .env && python app.py
# → Listening on http://0.0.0.0:5000
```

### Server — via Install Script (Debian/Ubuntu)

```bash
sudo bash scripts/install_server.sh
# Installs PostgreSQL + Redis, creates DB/user, writes /etc/nids/server.env,
# installs and starts the nids-server systemd service.
```

### Agent — Manual

```bash
# 1. Register and get a JWT
curl -X POST http://SERVER_IP:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"agent_name":"agent-1","registration_key":"changeme"}'
# → {"token": "eyJ..."}

# 2. Set up environment
cd agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env   # Set SERVER_URL, AGENT_NAME, AGENT_TOKEN, INTERFACE

# 3. Run with root (required for Scapy raw socket + iptables)
sudo -E python agent.py

# Run without capture (reporter/sync only — no root needed):
python agent.py --no-capture
```

### Agent — via Install Script

```bash
sudo bash scripts/install_agent.sh
# Prompts: server URL, agent name, registration key, network interface.
# Automatically calls /api/register, saves JWT, installs systemd service.
```

---

## Service Management (Linux systemd)

```bash
# Server
sudo systemctl status nids-server
sudo systemctl restart nids-server
journalctl -u nids-server -f        # live logs

# Agent
sudo systemctl status nids-agent
sudo systemctl restart nids-agent
journalctl -u nids-agent -f         # live logs
```

---

## API Reference

All agent endpoints require `Authorization: Bearer <JWT>` header.  
Admin endpoints also accept `X-Admin-Key: <AGENT_REGISTRATION_KEY>`.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/register` | None (reg key in body) | Register agent, get JWT |
| `POST` | `/api/heartbeat` | Agent JWT | Send heartbeat + lightweight metrics |
| `POST` | `/api/metrics` | Agent JWT | Send detailed metrics snapshot |
| `GET`  | `/api/commands` | Agent JWT | Poll push commands (block IPs) |
| `POST` | `/api/alerts` | Agent JWT | Submit batch of alert objects |
| `GET`  | `/api/global_blocklist` | Agent JWT | Get active blocklist entries |
| `POST` | `/api/global_blocklist` | Agent JWT / Admin | Add IP to global blocklist |
| `DELETE` | `/api/global_blocklist/<id>` | Admin key | Remove blocklist entry |
| `POST` | `/api/command/block` | Agent JWT / Admin | Block IP across all agents |
| `GET`  | `/` | None | Web dashboard |
| `GET`  | `/alerts` | None | Paginated alert feed |
| `GET`  | `/blocklist` | None | Global blocklist manager |
| `GET`  | `/api/dashboard/summary` | None | JSON summary for live refresh |

---

## Detection Rules

### Signature Detection (HTTP Payload)

| Attack | Patterns | Base Score |
|--------|----------|-----------|
| SQL Injection | `UNION SELECT`, `OR 1=1`, `xp_cmdshell`, `SLEEP()`, … (12 patterns) | 85 |
| XSS | `<script>`, `onerror=`, `javascript:`, `eval()`, … (10 patterns) | 75 |
| Directory Traversal | `../`, `%2F`, `/etc/passwd`, `boot.ini`, … (8 patterns) | 80 |

> Score is capped at base+10 for multiple pattern matches within the same category.

### Port Scan Detection (Sliding Window)

| Scan Type | TCP Flags | Score |
|-----------|-----------|-------|
| SYN Scan | SYN only (0x02) | 65 |
| FIN Scan | FIN only (0x01) | 70 |
| NULL Scan | No flags (0x00) | 75 |
| XMAS Scan | FIN+PSH+URG (0x29) | 70 |

> Fires when ≥20 unique destination ports are hit within a 10-second window (configurable).

### Rate Anomaly (Per-IP PPS)

| Condition | Score |
|-----------|-------|
| Source IP exceeds 500 pps in 1-second window | 55 |

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
