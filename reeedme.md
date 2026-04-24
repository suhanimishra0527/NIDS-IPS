# NIDS+IPS — How This Project Actually Works

No marketing. No fluff. Here's what every file does, how they connect, and where things break.

---

## What This Is

A distributed Network Intrusion Detection and Prevention System.  
Two halves: a **central Flask server** and one-or-more **edge agents** that sniff traffic with Scapy.

- Server: Flask + PostgreSQL + Redis. Receives alerts, manages agents, serves a web dashboard.
- Agent: Scapy packet sniffer + regex-based detection + iptables enforcement. Runs on Linux as root.
- No ML. No deep learning. Pure regex signatures and packet-rate thresholds.
- IPS only works on Linux. On Windows, the entire enforcement layer degrades to printing log lines.

---

## Project Structure (What's Actually Used)

```
Root/
├── server/                 ← Central server (the one with the web UI)
│   ├── app.py              ← Flask app factory + heartbeat monitor thread
│   ├── config.py           ← Reads env vars into a Config class
│   ├── database.py         ← SQLAlchemy models: Agent, Alert, GlobalBlocklist
│   ├── redis_client.py     ← Redis connection pool + command queues + caches
│   ├── auth.py             ← JWT generation, hashing, and the @require_agent_auth decorator
│   ├── routes/
│   │   ├── auth.py         ← POST /api/register
│   │   ├── agents.py       ← POST /api/heartbeat, POST /api/metrics, GET /api/commands
│   │   ├── alerts.py       ← POST /api/alerts — ⚠️ THIS FILE HAS A BUG (see below)
│   │   ├── blocklist.py    ← CRUD for global blocklist + push-block via Redis
│   │   └── dashboard.py    ← HTML pages (/, /alerts, /blocklist) + JSON summary endpoint
│   ├── templates/          ← Jinja2 HTML (dark Bootstrap theme)
│   │   ├── base.html       ← Shared layout (navbar, CSS, JS)
│   │   ├── dashboard.html  ← Main dashboard with agent cards + alert table
│   │   ├── alerts.html     ← Paginated alert feed with filters
│   │   └── blocklist.html  ← Blocklist manager
│   ├── .env.example
│   └── requirements.txt
│
├── agent/                  ← Edge agent (runs on each monitored host)
│   ├── agent.py            ← Main entrypoint — spins up 4 daemon threads, capture on main
│   ├── config.py           ← Reads env vars into AgentConfig class
│   ├── capture.py          ← Scapy sniff loop + detection pipeline per packet
│   ├── detection/
│   │   ├── signatures.py   ← Regex-based SQLi/XSS/DirTraversal detection
│   │   ├── port_scan.py    ← Sliding-window SYN/FIN/NULL/XMAS scan detector
│   │   └── anomaly.py      ← Per-IP packets-per-second rate check
│   ├── ips.py              ← Decision engine: IGNORE/LOG/DROP/BLOCK + iptables + TCP RST
│   ├── blocklist.py        ← In-memory IP blocklist with TTL expiry
│   ├── reporter.py         ← Batches alerts and ships them to server + heartbeat loop
│   ├── sync.py             ← Pulls global blocklist + polls for server-pushed commands
│   ├── .env.example
│   └── requirements.txt
│
├── scripts/
│   ├── install_server.sh   ← Automated Debian/Ubuntu server deployment
│   ├── install_agent.sh    ← Automated agent deployment (prompts, registers, systemd)
│   ├── server.service      ← systemd unit file for server
│   └── agent.service       ← systemd unit file for agent
│
├── trial/                  ← ⚠️ OLDER/ALTERNATE VERSION of the entire project
│                              Contains its own server/, agents/, shared/, tests/, docs/, etc.
│                              NOT used by the main server/ and agent/ directories.
│                              Appears to be leftover from an earlier refactoring attempt.
│
├── docker-compose.yml      ← Spins up PostgreSQL 16 + Redis 7 containers
└── README.md               ← The existing marketing README
```

### About `trial/`

The `trial/` directory is a completely separate, older implementation of the same project. It has its own `server/`, `agents/`, `shared/`, `tests/`, `deployment/` directories with a different internal structure (service layers, modular config directories, etc.). **Nothing in `trial/` is imported or used by the main `server/` or `agent/` code.** It's dead weight in the repo — either an abandoned refactor or a parallel experiment.

---

## How Everything Connects — The Full Data Flow

### Step 1: Agent Registration

```
Agent                              Server
  |                                  |
  |  POST /api/register              |
  |  {agent_name, registration_key}  |
  |  ──────────────────────────────► |
  |                                  |  Validates registration_key against Config.AGENT_REGISTRATION_KEY
  |                                  |  Creates Agent row in PostgreSQL (or rotates token if re-registering)
  |                                  |  Generates JWT with PyJWT (sub=agent_name, exp=365 days)
  |                                  |  Stores SHA-256 hash of token in Agent.token_hash
  |  ◄────────────────────────────── |
  |  {token: "eyJ..."}              |
  |                                  |
  |  Agent stores token as           |
  |  AGENT_TOKEN env var             |
```

After this, every agent request includes `Authorization: Bearer <token>`. The server validates it in `@require_agent_auth` by decoding the JWT and matching the SHA-256 hash against the `agents` table.

### Step 2: Packet Capture & Detection (Agent Side)

When `agent.py` starts, it:

1. Creates a `LocalBlocklist` instance (shared across all threads)
2. Creates a `Reporter` (holds a reference to the shared alert queue + lock)
3. Creates a `Syncer` (holds a reference to the local blocklist)
4. Spawns **4 daemon threads**:
   - `batch-reporter` — flushes alert queue to server
   - `heartbeat` — sends liveness pings
   - `bl-sync` — syncs global blocklist from server
   - `cmd-poll` — polls for server-pushed block commands
5. Starts `PacketCapture.start()` on the **main thread** (blocking Scapy sniff)

**For every captured packet, the pipeline is:**

```
Raw packet arrives via Scapy sniff()
  │
  ▼
_handle(pkt)
  │
  ├── Not IP? → skip
  │
  ├── src_ip in local blocklist? → skip silently
  │
  ├── AnomalyDetector.process_packet(src_ip)
  │     └── Tracks packets-per-second per source IP in 1-second rolling windows
  │     └── Fires ONCE when count hits ANOMALY_PPS_THRESHOLD (default 500)
  │     └── If fired → call decide_and_act() → RETURN (skip further checks)
  │
  ├── TCP packet?
  │     ├── PortScanDetector.process_packet(src_ip, dst_port, flags)
  │     │     └── Classifies flags: SYN-only=SYN scan, FIN-only=FIN scan, 0x00=NULL, FPU=XMAS
  │     │     └── Maintains per-IP sliding window of (timestamp, dst_port) entries
  │     │     └── Fires when unique ports in window >= PORTSCAN_THRESHOLD (default 20)
  │     │     └── If fired → decide_and_act() → RETURN
  │     │
  │     └── Extract TCP payload → detect_signatures(payload)
  │           └── Runs payload through 30 compiled regexes (12 SQLi, 10 XSS, 8 DirTraversal)
  │           └── Returns list of (attack_type, score) for each category that matched
  │           └── For each match → decide_and_act()
  │
  └── UDP packet?
        └── Extract UDP payload → detect_signatures(payload) → same as above
```

### Step 3: IPS Decision (`decide_and_act`)

This is the core enforcement function in `ips.py`. For each detection result:

```
threat_score < 30 (THREAT_SCORE_LOG)     → IGNORE, return immediately, no alert created
30 <= score < 50 (THREAT_SCORE_DROP)     → LOG:   alert dict appended to queue
50 <= score < 80 (THREAT_SCORE_BLOCK)    → DROP:  iptables -I INPUT -s <ip> -j DROP + alert queued
score >= 80                              → BLOCK: iptables DROP + TCP RST packet + add to LocalBlocklist + alert queued
```

On non-Linux: `_IS_LINUX = platform.system() == "Linux"` is checked. If False, `_run_iptables()` returns False and `_send_tcp_rst()` returns immediately. The system becomes log-only.

The alert dict created looks like:
```python
{
    "timestamp": "ISO UTC",
    "src_ip": "...", "dst_ip": "...",
    "src_port": int, "dst_port": int,
    "protocol": "TCP"/"UDP"/"IP",
    "attack_type": "SQLi"/"XSS"/"SYN_Scan"/etc,
    "severity": "LOW"/"MEDIUM"/"HIGH"/"CRITICAL",
    "threat_score": int,
    "action_taken": "LOG"/"DROP"/"BLOCK",
    "payload_snippet": "first 256 chars of payload"
}
```

This dict gets appended to the shared `alert_queue` list (protected by `queue_lock`).

### Step 4: Alert Reporting (Agent → Server)

`Reporter.start_batch_reporter()` runs in a daemon thread:

- Polls every 0.5 seconds
- Flushes the queue when either:
  - Queue size >= `BATCH_MAX_ALERTS` (default 10), OR
  - `BATCH_INTERVAL_SEC` (default 5) seconds have elapsed and queue is non-empty
- Sends batch via `POST /api/alerts` with the JWT header

**If the server is unreachable:**
- Alerts are appended to `offline_queue.jsonl` (one JSON object per line)
- On the next successful heartbeat, `_flush_offline_on_reconnect()` replays the stored alerts
- The JSONL file is deleted after successful replay

### Step 5: Heartbeat (Agent → Server)

`Reporter.start_heartbeat()` runs every `HEARTBEAT_INTERVAL` (default 30s):

- Collects metrics: `agent_name`, `timestamp`, `blocked_ips` count, `alerts_in_queue` count
- Optionally includes `cpu_percent` and `mem_percent` if `psutil` is installed
- Sends via `POST /api/heartbeat`
- Server updates `Agent.status = "online"`, `Agent.last_seen = now`, stores metrics in Redis

### Step 6: Server Heartbeat Monitor

A background thread in `app.py` (`_heartbeat_monitor`) runs every 30 seconds:

- Queries all agents where `status == "online"` AND `last_seen < (now - 90 seconds)`
- Sets those agents to `status = "offline"`

### Step 7: Blocklist Sync (Agent ← Server)

`Syncer.start_blocklist_sync()` runs every `SYNC_INTERVAL` (default 60s):

- `GET /api/global_blocklist` — server returns all non-expired blocklist entries
- Server first checks Redis cache (TTL 120s). Cache miss → queries PostgreSQL → caches result
- Agent merges new IPs into `LocalBlocklist` with the server's expiry TTL

`Syncer.start_command_poll()` runs every 15 seconds:

- `GET /api/commands` — pops all pending commands from the agent's Redis queue
- If command `action == "block"` → adds the IP to `LocalBlocklist`
- This is how the dashboard "Block IP" button reaches agents in near-real-time

### Step 8: The Dashboard

Three HTML pages served by `routes/dashboard.py`:

- `GET /` → `dashboard.html` — shows agent cards (with live metrics from Redis), recent 100 alerts, summary counts
- `GET /alerts` → `alerts.html` — paginated alert table (50/page), filterable by attack_type and severity
- `GET /blocklist` → `blocklist.html` — lists all global blocklist entries with add/remove controls

Plus one JSON endpoint for AJAX refresh:
- `GET /api/dashboard/summary` → returns agents, recent alerts, counts as JSON

---

## Every Major Function and What It Does

### Agent: `agent.py`

| Function | What it does |
|---|---|
| `main()` | Parses `--no-capture`, validates `AGENT_TOKEN`, creates `LocalBlocklist` / `Reporter` / `Syncer`, starts 4 daemon threads, runs capture on main thread |
| `_shutdown(signum, frame)` | SIGINT/SIGTERM handler. Stops capture, drains remaining alerts to offline queue, exits |

### Agent: `capture.py`

| Function | What it does |
|---|---|
| `_get_default_interface()` | Iterates Scapy's known interfaces, returns first non-loopback. Fallback: empty string |
| `PacketCapture.__init__()` | Creates `AnomalyDetector` and `PortScanDetector` instances, resolves network interface |
| `PacketCapture.start()` | Calls `scapy.sniff()` with BPF filter, `store=False`, routes each packet to `_process_packet`. Blocks until `stop()` |
| `PacketCapture.stop()` | Sets `_running = False`. Scapy's `stop_filter` lambda checks this |
| `PacketCapture._process_packet(pkt)` | Try/except wrapper around `_handle()`. Swallows exceptions so one bad packet doesn't kill the sniffer |
| `PacketCapture._handle(pkt)` | The full detection pipeline. Checks blocklist → anomaly → port scan → signature. Calls `decide_and_act()` for each hit |
| `PacketCapture._extract_payload(pkt)` | Walks `pkt.payload.payload.payload` (IP → TCP/UDP → raw) and decodes as UTF-8 with `errors="replace"`. Returns empty string on failure |

### Agent: `detection/signatures.py`

| Function | What it does |
|---|---|
| `detect_signatures(payload, method)` | Runs payload against 30 pre-compiled regexes grouped into 3 categories (SQLi/XSS/DirTraversal). For each category, counts hits. Score = `base_score + (hits-1)*2`, capped at `base_score + 10`. Returns list of `(attack_type, score)` tuples |

The regex patterns are compiled at module load (good for performance). The `method` parameter is accepted but **never used** — it's reserved for "future weighting" that was never implemented.

### Agent: `detection/port_scan.py`

| Function | What it does |
|---|---|
| `_classify_flags(flags_int)` | Maps TCP flag integers to scan type strings. `0x02`→SYN, `0x01`→FIN, `0x00`→NULL, `0x29`→XMAS. Everything else → `None` |
| `PortScanDetector.__init__()` | Creates a nested defaultdict `{src_ip: {scan_type: deque}}`, starts a background eviction thread |
| `PortScanDetector.process_packet(src_ip, dst_port, flags_int)` | Classifies flags, appends `(timestamp, dst_port)` to the IP's deque, prunes entries older than `PORTSCAN_WINDOW_SEC`, counts unique ports. If `>= PORTSCAN_THRESHOLD`, clears the deque (prevent duplicate alerts) and returns `(attack_type, score, src_ip, dst_port)` |
| `PortScanDetector.track(src_ip, dst_port, flags)` | Convenience wrapper that maps string flags ("S", "F", "", "FPU") to integers. Used in unit tests |
| `PortScanDetector.check(src_ip)` | Returns True if any tracked entries exist for the IP |
| `PortScanDetector._evict_loop()` | Runs every 30s. Removes IPs with no recent activity to prevent memory leak |

### Agent: `detection/anomaly.py`

| Function | What it does |
|---|---|
| `AnomalyDetector.__init__()` | Creates a per-IP counter dict `{src_ip: {window_start, count}}`, starts cleanup thread |
| `AnomalyDetector.process_packet(src_ip)` | Increments counter for src_ip. If 1-second window elapsed → reset window. If counter hits `ANOMALY_PPS_THRESHOLD` exactly → fire once (returns tuple). Subsequent packets in same window → None |
| `AnomalyDetector._cleanup_loop()` | Runs every 30s. Evicts IPs not seen for 10+ seconds |

### Agent: `ips.py`

| Function | What it does |
|---|---|
| `_run_iptables(args, check)` | Runs `iptables <args>` via subprocess. Returns False on non-Linux. Thread-safe via `_iptables_lock`. 5-second timeout |
| `_send_tcp_rst(src_ip, dst_ip, src_port, dst_port)` | Crafts and sends a TCP RST packet via Scapy to terminate the attacker's connection. Only works on Linux |
| `drop_ip(src_ip)` | Calls `iptables -I INPUT -s <ip> -j DROP` |
| `unblock_ip(src_ip)` | Calls `iptables -D INPUT -s <ip> -j DROP` |
| `decide_and_act(...)` | The main function. Compares `threat_score` against thresholds. Applies iptables rules, sends TCP RST, adds to local blocklist. Builds an alert dict and appends to shared queue. Prints a formatted log line. Returns the action string |
| `_score_to_severity(score)` | `>=80`→CRITICAL, `>=50`→HIGH, `>=30`→MEDIUM, else LOW |

### Agent: `blocklist.py`

| Function | What it does |
|---|---|
| `LocalBlocklist.__init__()` | Creates thread-safe dict `{ip: expiry_datetime}`, starts cleanup thread |
| `LocalBlocklist.block(ip, ttl_seconds)` | Adds IP with expiry = now + TTL (default from `LOCAL_BLOCK_TTL`, 1 hour) |
| `LocalBlocklist.is_blocked(ip)` | Returns True if IP exists and not expired. Deletes on-access if expired |
| `LocalBlocklist.remove(ip)` | Manual removal, returns True if it was present |
| `LocalBlocklist.all_active()` | Returns list of all currently non-expired IPs |
| `LocalBlocklist.count()` | Calls `all_active()` and returns length |
| `LocalBlocklist._cleanup_loop()` | Runs every 60s. Bulk-removes all expired entries |

### Agent: `reporter.py`

| Function | What it does |
|---|---|
| `Reporter.__init__()` | Sets up `requests.Session` with JWT auth header. Tracks `_server_ok` flag and offline queue path |
| `Reporter.start_batch_reporter()` | Infinite loop (0.5s sleep). Flushes queue when size >= max or interval elapsed |
| `Reporter.start_heartbeat()` | Infinite loop. Sends heartbeat every `HEARTBEAT_INTERVAL` seconds |
| `Reporter._flush()` | Extracts all alerts from shared queue, prepends any offline-stored alerts, posts to server. If server fails → `_save_offline()` |
| `Reporter._send_alerts(alerts)` | POST to `/api/alerts`. Returns True on 200/201, False otherwise |
| `Reporter._send_heartbeat()` | POST to `/api/heartbeat` with metrics. On success, tries replaying offline queue |
| `Reporter._flush_offline_on_reconnect()` | Loads offline JSONL, resends, deletes file on success |
| `Reporter._save_offline(alerts)` | Appends JSON lines to `offline_queue.jsonl` |
| `Reporter._load_offline()` | Reads JSONL file line by line, parses each as JSON. Silently skips corrupt lines |
| `Reporter._collect_metrics()` | Builds dict with agent name, timestamp, blocked IP count, queue size. Adds CPU/RAM if psutil available |

### Agent: `sync.py`

| Function | What it does |
|---|---|
| `Syncer.__init__()` | Sets up `requests.Session` with JWT header, holds reference to local blocklist |
| `Syncer.start_blocklist_sync()` | Infinite loop. GETs `/api/global_blocklist` every `SYNC_INTERVAL`. Merges new IPs into local blocklist |
| `Syncer.start_command_poll()` | Infinite loop. GETs `/api/commands` every 15s. Applies `block` commands locally |
| `Syncer._sync_blocklist()` | Parses server's blocklist response, calculates TTL from `expires_at`, blocks any new IPs locally |
| `Syncer._poll_commands()` | Pops commands from Redis (via server endpoint), applies block actions |
| `_ttl_from_expiry(expires_at_str)` | Converts ISO timestamp to seconds-from-now. Minimum TTL: 60 seconds. Falls back to config default |

---

### Server: `app.py`

| Function | What it does |
|---|---|
| `create_app()` | Flask factory. Configures SQLAlchemy + secret key. Registers 5 blueprints. Calls `init_db()` to create tables |
| `_heartbeat_monitor(app)` | Background daemon thread. Every 30s, marks agents as "offline" if `last_seen` is older than `HEARTBEAT_TIMEOUT_SECONDS` (default 90s) |

### Server: `config.py`

Single `Config` class. Every field is read from environment variables with `os.environ.get()`. Defaults are baked in for local dev. No `.env` file loading — you need to `source .env` yourself or use the systemd `EnvironmentFile` directive.

### Server: `database.py`

| Function / Class | What it does |
|---|---|
| `init_db(app)` | Binds SQLAlchemy to Flask app, creates all tables via `db.create_all()` |
| `Agent` model | Columns: id, name, ip_address, token_hash, status, last_seen, registered_at, last_metrics. Has a `to_dict()` for JSON serialization |
| `Alert` model | Columns: id, agent_id (FK → agents), timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, severity, threat_score, action_taken, payload_snippet. Has `to_dict()` |
| `GlobalBlocklist` model | Columns: id, ip_address (unique), added_by, reason, expires_at, created_at. `is_active` property checks expiry. Has `to_dict()` |

### Server: `redis_client.py`

| Function | What it does |
|---|---|
| `get_redis()` | Lazy-init connection pool from `REDIS_URL`, returns Redis client |
| `push_block_command(agent_name, ip, reason)` | Pushes `{"action":"block","ip":...}` to Redis list `nids:cmds:<agent_name>`. Sets 10-minute expiry |
| `pop_commands(agent_name, max_items)` | Pops up to 50 items from the agent's command queue via pipeline |
| `cache_blocklist(entries, ttl)` | Stores serialized blocklist in Redis key `nids:global_blocklist` with 120s TTL |
| `get_cached_blocklist()` | Returns cached blocklist or None |
| `store_agent_metrics(agent_name, metrics, ttl)` | Stores metrics JSON in `nids:metrics:<agent_name>` with 120s TTL |
| `get_agent_metrics(agent_name)` | Returns cached metrics or None |

### Server: `auth.py`

| Function | What it does |
|---|---|
| `hash_token(token)` | SHA-256 hex digest of the raw JWT string |
| `generate_token(agent_name)` | Creates JWT with `sub=agent_name`, `iat=now`, `exp=now+365 days`. Signed with `JWT_SECRET` using HS256 |
| `decode_token(token)` | Decodes + validates JWT. Raises on expired/invalid |
| `require_agent_auth(f)` | Decorator. Extracts Bearer token → decode → lookup Agent by name + token_hash → sets `g.agent`. Returns 401 on any mismatch |

### Server: `routes/auth.py`

| Endpoint | What it does |
|---|---|
| `POST /api/register` | Validates `agent_name` (alphanumeric + hyphens/underscores only) and `registration_key`. If agent exists → re-registration (rotates token). If new → creates Agent row. Returns JWT |

### Server: `routes/agents.py`

| Endpoint | What it does |
|---|---|
| `POST /api/heartbeat` | Updates `Agent.status = "online"`, `last_seen = now`. Stores lightweight metrics in Redis via `store_agent_metrics()` |
| `POST /api/metrics` | Stores detailed metrics snapshot in both `Agent.last_metrics` (PostgreSQL JSON text) and Redis |
| `GET /api/commands` | Pops all pending commands from the agent's Redis queue and returns them. This is how server-pushed blocks reach agents |

### Server: `routes/alerts.py`

| Endpoint | What it does |
|---|---|
| `POST /api/alerts` | Accepts single alert or batch (list). Creates Alert rows in PostgreSQL |

### Server: `routes/blocklist.py`

| Endpoint | What it does |
|---|---|
| `GET /api/global_blocklist` | Returns active (non-expired) blocklist entries. Cache-first via Redis (120s TTL) |
| `POST /api/global_blocklist` | Adds an IP to the global blocklist. Pushes `block` command to all online agents via Redis |
| `POST /api/command/block` | Same as above but semantically a "manual block command". Creates DB entry if not exists, pushes to all online agents |
| `DELETE /api/global_blocklist/<id>` | Removes a blocklist entry. Requires `X-Admin-Key` header |

### Server: `routes/dashboard.py`

| Endpoint | What it does |
|---|---|
| `GET /` | Renders main dashboard. Queries all agents + metrics from Redis + last 100 alerts + active block count |
| `GET /alerts` | Paginated alert feed (50/page). Supports `?attack_type=` and `?severity=` filters |
| `GET /blocklist` | Lists all global blocklist entries (active and expired) |
| `GET /api/dashboard/summary` | JSON endpoint with summary stats for AJAX live-refresh on the dashboard |

---

## Known Issues & Inconsistencies

### 1. `routes/alerts.py` Has a Schema Mismatch (BUG)

The `Alert` model in `database.py` has these columns:
```
id, agent_id (FK), timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
attack_type, severity, threat_score, action_taken, payload_snippet
```

But `routes/alerts.py` creates Alert objects like this:
```python
Alert(
    agent_name=item.get("agent_name"),   # ← Column doesn't exist. The model uses agent_id (int FK)
    src_ip=item.get("src_ip"),
    attack_type=item.get("attack_type"),
    severity=item.get("severity"),
    action_taken=item.get("action_taken")
)
```

**Problems:**
- `agent_name` is not a column on the `Alert` model. This will either silently pass (SQLAlchemy ignores unknown kwargs) or crash.
- `agent_id` is never set, but it's `nullable=False`. This will cause an IntegrityError on commit.
- `threat_score`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `payload_snippet`, `timestamp` — all sent by the agent but never saved.
- The endpoint has **no authentication**. Any request can inject alerts.

This means **the alerts endpoint is broken**. Alerts sent by the agent will fail to persist unless this file was patched after the version I'm reading.

### 2. No Auth on the Alerts Endpoint

`routes/alerts.py` doesn't use `@require_agent_auth`. Compare this to `routes/agents.py` where heartbeat and commands are protected. Anyone who can reach the server can post fake alerts.

### 3. `trial/` is Dead Code

Entire directory tree sitting in the repo doing nothing. Different architecture (service layer pattern, modular configs, separate shared schemas). Not wired into anything.

### 4. No `.env` Auto-Loading

Both `config.py` files read from `os.environ` directly. They import `python-dotenv` in `requirements.txt` but **never call `load_dotenv()`**. You must `source .env` manually or rely on systemd's `EnvironmentFile=`.

### 5. IPS is Linux-Only

The entire enforcement layer (iptables DROP rules + TCP RST) checks `platform.system() == "Linux"`. On Windows, macOS, or WSL, the IPS does nothing. The system becomes a pure IDS (detection + logging only).

### 6. No HTTPS

All communication between agent and server is plain HTTP. JWT tokens travel unencrypted. The README recommends putting Nginx in front, but nothing enforces it.

### 7. `unblock_ip()` is Never Called

`ips.py` defines `unblock_ip()` to remove iptables rules. It is never called anywhere in the codebase. Blocked IPs only expire from the local Python blocklist. The iptables rules persist until reboot or manual cleanup.

### 8. Dashboard Has No Auth

All dashboard pages (`/`, `/alerts`, `/blocklist`, `/api/dashboard/summary`) are publicly accessible. No login, no session, no role check.

---

## Detection Specifics

### Signature Detection (SQLi / XSS / Directory Traversal)

All 30 patterns are compiled once at import time into `re.compile` objects. Matching is case-insensitive.

**SQLi (12 patterns, base score 85):**
- `union select`, `' or '1'='1'`, `-- ` (line comment), `; drop table`, `xp_cmdshell`, `exec sp_*`, `select...from...where`, `waitfor delay`, `benchmark(`, `sleep(`, `char(`, hex strings `0x????`

**XSS (10 patterns, base score 75):**
- `<script>`, `</script>`, `javascript:`, event handlers (`onerror=`, `onclick=`, etc.), `<iframe`, `<img src=javascript`, `document.cookie`, `eval(`, `expression(`, `vbscript:`

**Directory Traversal (8 patterns, base score 80):**
- `../`, `..\`, URL-encoded variants (`%2f`, `%5c`, `%2e%2e%2f`), `/etc/passwd`, `/etc/shadow`, `/proc/self`, `boot.ini`, `win.ini`, `system32`

**Scoring:** base_score + 2 per additional pattern hit, capped at base_score + 10.

### False Positive Risk

The `select...from...where` regex pattern (`(insert|update|delete|select).+(from|into|where|set)`) will match **any** HTTP request containing these common English words in the right order. A URL like `/select-products?from=catalog&where=available` would trigger SQLi detection at score 85+. There's no HTTP-aware parsing — it regex-matches across the entire raw payload.

---

## Thread Model (Agent)

```
Main thread:  PacketCapture.start() → Scapy sniff loop (blocking)
              └─ Each packet → _handle() → detection pipeline → decide_and_act()
              └─ decide_and_act() appends to alert_queue under queue_lock

Thread 1:     Reporter.start_batch_reporter() → polls alert_queue, flushes to server
Thread 2:     Reporter.start_heartbeat() → periodic heartbeat POST
Thread 3:     Syncer.start_blocklist_sync() → periodic GET /api/global_blocklist
Thread 4:     Syncer.start_command_poll() → periodic GET /api/commands

Background:   AnomalyDetector._cleanup_loop() (daemon)
              PortScanDetector._evict_loop() (daemon)
              LocalBlocklist._cleanup_loop() (daemon)
```

Total: Main thread + 4 explicit daemon threads + 3 implicit cleanup daemon threads = 8 threads.

All shared state is protected by `threading.Lock`:
- `alert_queue` + `queue_lock` — shared between capture (write) and reporter (read+clear)
- `LocalBlocklist._lock` — shared between capture, syncer, and cleanup
- `AnomalyDetector._lock` — capture + cleanup
- `PortScanDetector._lock` — capture + cleanup
- `_iptables_lock` — serializes iptables subprocess calls

---

## Deployment Scripts

### `install_server.sh`
1. `apt-get install` PostgreSQL, Redis, Python3
2. Copies `server/` to `/opt/nids/server/`
3. Creates venv, installs requirements
4. Prompts for PostgreSQL password, creates user/db
5. Enables Redis
6. Writes `/etc/nids/server.env` (prompts for JWT secret, registration key, port)
7. Creates+enables systemd service `nids-server`

### `install_agent.sh`
1. `apt-get install` Python3, tcpdump, libpcap, iptables, curl
2. Copies `agent/` to `/opt/nids/agent/`
3. Creates venv, installs requirements
4. Prompts for server URL, agent name, registration key, interface
5. Calls `POST /api/register` via curl, extracts JWT from response
6. Writes `/etc/nids/agent.env`
7. Creates+enables systemd service `nids-agent`

Both scripts assume Debian/Ubuntu and require root.

---

## Dependencies

### Server
| Package | Version | Purpose |
|---|---|---|
| Flask | 3.x | Web framework |
| Flask-SQLAlchemy | 3.x | ORM |
| psycopg2-binary | 2.x | PostgreSQL driver |
| redis | 5.x | Redis client |
| PyJWT | 2.x | JWT tokens |
| Werkzeug | 3.x | WSGI utilities (Flask depends on it) |
| gunicorn | 21.x | Production WSGI server (listed but not used in the code) |
| python-dotenv | 1.x | Listed but never imported in code |

### Agent
| Package | Version | Purpose |
|---|---|---|
| scapy | 2.5.x | Packet capture and crafting |
| requests | 2.x | HTTP client for server communication |
| psutil | 5.x–6.x | CPU/memory metrics (optional, gracefully degrades) |
| python-dotenv | 1.x | Listed but never imported in code |

### Infrastructure
| Service | Version | Purpose |
|---|---|---|
| PostgreSQL | 16 | Primary database (agents, alerts, blocklist) |
| Redis | 7 | Command queues, metrics cache, blocklist cache |

---

## Summary

This is a functional-but-rough distributed NIDS+IPS. The agent detection pipeline (capture → anomaly/portscan/signature → IPS action → batch report) is solidly wired. The server side (registration, heartbeat monitoring, blocklist sync, dashboard) is complete. The `trial/` directory is dead code. The `routes/alerts.py` file is broken due to a model mismatch. The dashboard is unauthenticated. Enforcement only works on Linux with root. No HTTPS by default. The regex signatures will produce false positives on normal HTTP traffic containing SQL-like keywords.
