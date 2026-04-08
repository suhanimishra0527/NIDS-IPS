"""JWT helpers for agent authentication."""
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps
import jwt
from flask import request, jsonify, g
from server.config.server_config import config

def hash_token(token: str) -> str:
    """SHA-256 hash of a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()

def generate_token(agent_name: str) -> str:
    """Create a signed JWT for an agent."""
    payload = {
        "sub": agent_name,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=365),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict:
    """Decode and validate a JWT."""
    return jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])

def require_agent_auth(f):
    """Decorator: enforce Bearer JWT auth and load agent into g.agent."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from server.models.agent import Agent
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
        # In this modular version, we just check if agent exists for now.
        # token_hash check can be re-enabled if needed.
        agent = Agent.query.filter_by(name=agent_name).first()
        if not agent:
            return jsonify({"error": "Agent not found"}), 401
        
        g.agent = agent
        return f(*args, **kwargs)
    return decorated
