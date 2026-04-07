"""
Redis helpers: connection pool, per-agent command queues, blocklist cache.
"""
import json
import redis
from server.config import Config

_pool = None


def get_redis() -> redis.Redis:
    """Return a Redis client from the shared connection pool."""
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(Config.REDIS_URL, decode_responses=True)
    return redis.Redis(connection_pool=_pool)


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _agent_cmd_key(agent_name: str) -> str:
    return f"nids:cmds:{agent_name}"


def _blocklist_cache_key() -> str:
    return "nids:global_blocklist"


# ---------------------------------------------------------------------------
# Command queue (per-agent)
# ---------------------------------------------------------------------------

def push_block_command(agent_name: str, ip: str, reason: str = "") -> None:
    """Push an immediate BLOCK command to an agent's Redis queue."""
    r = get_redis()
    payload = json.dumps({"action": "block", "ip": ip, "reason": reason})
    r.rpush(_agent_cmd_key(agent_name), payload)
    # Expire queue after 10 minutes in case agent is offline
    r.expire(_agent_cmd_key(agent_name), 600)


def pop_commands(agent_name: str, max_items: int = 50) -> list:
    """Pop all pending commands for an agent (up to max_items)."""
    r = get_redis()
    key = _agent_cmd_key(agent_name)
    pipe = r.pipeline()
    for _ in range(max_items):
        pipe.lpop(key)
    results = pipe.execute()
    return [json.loads(item) for item in results if item is not None]


# ---------------------------------------------------------------------------
# Blocklist cache
# ---------------------------------------------------------------------------

def cache_blocklist(entries: list, ttl: int = 120) -> None:
    """Cache serialised blocklist for fast agent polling."""
    r = get_redis()
    r.setex(_blocklist_cache_key(), ttl, json.dumps(entries))


def get_cached_blocklist() -> list | None:
    """Return cached blocklist or None if cache miss."""
    r = get_redis()
    raw = r.get(_blocklist_cache_key())
    return json.loads(raw) if raw else None


# ---------------------------------------------------------------------------
# Agent metrics cache
# ---------------------------------------------------------------------------

def store_agent_metrics(agent_name: str, metrics: dict, ttl: int = 120) -> None:
    r = get_redis()
    r.setex(f"nids:metrics:{agent_name}", ttl, json.dumps(metrics))


def get_agent_metrics(agent_name: str) -> dict | None:
    r = get_redis()
    raw = r.get(f"nids:metrics:{agent_name}")
    return json.loads(raw) if raw else None
