import requests
import sys
from typing import Optional, Any, Dict
from agents.config.agent_config import config

class APIClient:
    def __init__(self):
        self.session = requests.Session()
        self.update_token()

    def update_token(self):
        """Update authorization headers with the current token."""
        self.session.headers.update({
            "Authorization": f"Bearer {config.AGENT_TOKEN}",
            "Content-Type": "application/json"
        })

    def post(self, endpoint: str, data: Any, timeout: int = 10) -> Optional[requests.Response]:
        url = f"{config.SERVER_URL}{endpoint}"
        try:
            resp = self.session.post(url, json=data, timeout=timeout)
            return resp
        except requests.RequestException as e:
            print(f"[api-client] POST {endpoint} failed: {e}", file=sys.stderr)
            return None

    def get(self, endpoint: str, timeout: int = 10) -> Optional[requests.Response]:
        url = f"{config.SERVER_URL}{endpoint}"
        try:
            resp = self.session.get(url, timeout=timeout)
            return resp
        except requests.RequestException as e:
            print(f"[api-client] GET {endpoint} failed: {e}", file=sys.stderr)
            return None

# Global client
api_client = APIClient()
