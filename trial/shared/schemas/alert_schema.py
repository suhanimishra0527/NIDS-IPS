from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List

class AlertBase(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "IP"
    attack_type: str
    threat_score: int = Field(..., ge=0, le=100)
    severity: str = "MEDIUM"
    payload_preview: Optional[str] = None
    action_taken: str = "LOG"  # LOG, DROP, BLOCK

class AlertCreate(AlertBase):
    agent_name: str

class AlertBatch(BaseModel):
    agent_name: str
    alerts: List[AlertBase]
