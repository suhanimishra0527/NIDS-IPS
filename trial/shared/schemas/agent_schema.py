from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class AgentBase(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=100)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_info: Optional[str] = None

class AgentRegisterRequest(AgentBase):
    registration_key: str

class AgentRegisterResponse(BaseModel):
    token: str
    config_overrides: Optional[dict] = None

class AgentHeartbeat(BaseModel):
    agent_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metrics: Optional[dict] = Field(default_factory=dict)
    alerts_in_queue: int = 0
    blocked_ips_count: int = 0
