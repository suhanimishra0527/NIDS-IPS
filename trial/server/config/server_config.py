import os
import yaml
from pathlib import Path
from typing import Any, Dict

class ServerConfig:
    _config: Dict[str, Any] = {}

    @classmethod
    def load(cls, config_path: str = "server/config/default.yaml"):
        # Get base directory (project root)
        base_dir = Path(__file__).resolve().parent.parent.parent
        
        # 1. Load defaults
        path = Path(config_path)
        if path.exists():
            with open(path, "r") as f:
                cls._config = yaml.safe_load(f) or {}

        # 2. Override with Env
        cls._config["port"] = int(os.environ.get("PORT", cls._config.get("port", 5000)))
        cls._config["host"] = os.environ.get("HOST", cls._config.get("host", "0.0.0.0"))
        
        db_config = cls._config.get("database", {})
        # Default to an absolute path for SQLite
        default_db_path = f"sqlite:///{ (base_dir / 'server' / 'database' / 'nids.db').as_posix() }"
        db_config["url"] = os.environ.get("DATABASE_URL", db_config.get("url", default_db_path))
        cls._config["database"] = db_config

        sec_config = cls._config.get("security", {})
        sec_config["jwt_secret"] = os.environ.get("JWT_SECRET", sec_config.get("jwt_secret", "CHANGE_ME"))
        sec_config["agent_registration_key"] = os.environ.get("AGENT_REGISTRATION_KEY", sec_config.get("agent_registration_key", "changeme"))
        cls._config["security"] = sec_config

    @property
    def PORT(self) -> int: return self._config.get("port", 5000)
    
    @property
    def HOST(self) -> str: return self._config.get("host", "0.0.0.0")
    
    @property
    def DATABASE_URL(self) -> str: return self._config.get("database", {}).get("url")
    
    @property
    def JWT_SECRET(self) -> str: return self._config.get("security", {}).get("jwt_secret", "CHANGE_ME")
    
    @property
    def REGISTRATION_KEY(self) -> str: return self._config.get("security", {}).get("agent_registration_key", "changeme")

# Singleton instance
config = ServerConfig()
config.load()
