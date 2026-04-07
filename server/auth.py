"""JWT helpers for agent authentication."""
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import request, jsonify, g

from server.config import Config


def hash_token(token: str) -> str:
    """SHA-256 hash of a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token(agent_name: str) -> str:
    """Create a signed JWT for an agent."""
    payload = {
        "sub": agent_name,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=Config.JWT_EXPIRY_DAYS),
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT; raises jwt exceptions on failure."""
    return jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])


def require_agent_auth(f):
    """Decorator: enforce Bearer JWT auth and load agent into g.agent."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from server.database import Agent
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        raw_token = auth_header.split(" ", 1)[1]
        try:
            payload = decode_token(raw_token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        agent_name = payload.get("sub")
        token_hash = hash_token(raw_token)
        agent = Agent.query.filter_by(name=agent_name, token_hash=token_hash).first()
        if not agent:
            return jsonify({"error": "Agent not found or token mismatch"}), 401
        g.agent = agent
        return f(*args, **kwargs)
    return decorated
