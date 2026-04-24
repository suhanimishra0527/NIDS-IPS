"""
Server configuration – driven entirely by environment variables.
Loads .env automatically via python-dotenv (local .env first, then /etc/nids/server.env).
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from working directory first, then system-wide fallback
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=False)
load_dotenv(dotenv_path="/etc/nids/server.env", override=False)

class Config:
    # Network
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))
    DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

    # Database (PostgreSQL)
    DATABASE_URL = os.environ.get(
        "DATABASE_URL",
        "postgresql://nids_user:changeme@localhost:5432/nids_db"
    )

    # Redis
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # Security
    JWT_SECRET = os.environ.get("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRY_DAYS = int(os.environ.get("JWT_EXPIRY_DAYS", 365))

    # Agent registration shared secret
    AGENT_REGISTRATION_KEY = os.environ.get("AGENT_REGISTRATION_KEY", "changeme")

    # Heartbeat monitoring
    # Agents not seen in this many seconds are marked offline
    HEARTBEAT_TIMEOUT_SECONDS = int(os.environ.get("HEARTBEAT_TIMEOUT_SECONDS", 90))

    # Alert auto-block threshold
    AUTO_BLOCK_THREAT_SCORE = int(os.environ.get("AUTO_BLOCK_THREAT_SCORE", 80))

    # Global blocklist expiry (seconds), default 24 hours
    BLOCKLIST_EXPIRY_SECONDS = int(os.environ.get("BLOCKLIST_EXPIRY_SECONDS", 86400))

    # Optional HTTPS — set both to enable TLS
    SSL_CERT = os.environ.get("SSL_CERT", "")  # Path to PEM certificate file
    SSL_KEY  = os.environ.get("SSL_KEY", "")    # Path to PEM private key file
