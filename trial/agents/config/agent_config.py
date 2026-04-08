import os
import yaml
from pathlib import Path
from typing import Any, Dict

class AgentConfig:
    _config: Dict[str, Any] = {}

    @classmethod
    def load(cls, config_path: str = "agents/config/agent.yaml"):
        # 1. Load defaults from YAML if exists
        path = Path(config_path)
        if path.exists():
            with open(path, "r") as f:
                cls._config = yaml.safe_load(f) or {}
        
        # 2. Override with Environment Variables
        cls._config["server_url"] = os.environ.get("SERVER_URL", cls._config.get("server_url", "http://localhost:5000")).rstrip("/")
        cls._config["agent_name"] = os.environ.get("AGENT_NAME", cls._config.get("agent_name", "agent-1"))
        cls._config["agent_token"] = os.environ.get("AGENT_TOKEN", cls._config.get("agent_token", ""))
        cls._config["interface"] = os.environ.get("INTERFACE", cls._config.get("interface", ""))
        
        # 3. Handle thresholds
        thresholds = cls._config.get("thresholds", {})
        thresholds["threat_score_log"] = int(os.environ.get("THREAT_SCORE_LOG", thresholds.get("threat_score_log", 30)))
        thresholds["threat_score_drop"] = int(os.environ.get("THREAT_SCORE_DROP", thresholds.get("threat_score_drop", 50)))
        thresholds["threat_score_block"] = int(os.environ.get("THREAT_SCORE_BLOCK", thresholds.get("threat_score_block", 80)))
        cls._config["thresholds"] = thresholds

    @property
    def SERVER_URL(self) -> str: return self._config.get("server_url", "http://localhost:5000")
    
    @property
    def AGENT_NAME(self) -> str: return self._config.get("agent_name", "agent-1")
    
    @property
    def AGENT_TOKEN(self) -> str: return self._config.get("agent_token", "")
    
    @property
    def INTERFACE(self) -> str: return self._config.get("interface", "")
    
    @property
    def THREAT_SCORE_LOG(self) -> int: return self._config.get("thresholds", {}).get("threat_score_log", 30)
    
    @property
    def THREAT_SCORE_DROP(self) -> int: return self._config.get("thresholds", {}).get("threat_score_drop", 50)
    
    @property
    def THREAT_SCORE_BLOCK(self) -> int: return self._config.get("thresholds", {}).get("threat_score_block", 80)

# Singleton instance
config = AgentConfig()
config.load()
