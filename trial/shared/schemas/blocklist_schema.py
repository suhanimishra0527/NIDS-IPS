from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List

class BlocklistEntry(BaseModel):
    ip_address: str
    reason: str
    added_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    created_by: str = "system"  # system, admin

class BlocklistSyncResponse(BaseModel):
    entries: List[BlocklistEntry]
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class CommandAction(BaseModel):
    action: str  # e.g., "block", "unblock", "update_config"
    ip: Optional[str] = None
    data: Optional[dict] = None

class CommandResponse(BaseModel):
    commands: List[CommandAction]
