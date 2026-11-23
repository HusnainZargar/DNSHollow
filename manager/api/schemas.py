"""Request bodies (pydantic)."""
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class QueryIn(BaseModel):
    ts: float                 # unix time the agent saw the query
    qname: str
    qtype: str = "A"
    # optional extras from the real agent (old agents may leave them out)
    resolver: Optional[str] = None     # destination IP of the query
    proto: Optional[str] = None        # udp | tcp
    qbytes: Optional[int] = None       # DNS query size
    rbytes: Optional[int] = None       # DNS response size
    rcode: Optional[int] = None        # response code (0 ok, 3 NXDOMAIN ...)


class IngestIn(BaseModel):
    batch_id: str = Field(min_length=1, max_length=64)   # unique per batch (retry-safe)
    os: str = Field(default="", max_length=64)
    agent_version: str = Field(default="", max_length=32)
    queries: list[QueryIn]


class BlockReportIn(BaseModel):
    """What an agent says about enforcing blocks on its machine."""
    capable: bool = False                                  # blocking is installed and works here
    enforcing: bool = False                                # rules are active right now
    method: str = Field(default="", max_length=32)         # e.g. "iptables", "windows-nrpt"
    applied: list[str] = Field(default_factory=list, max_length=1000)
    error: str = Field(default="", max_length=300)


class HeartbeatIn(BaseModel):
    os: str = Field(default="", max_length=64)
    agent_version: str = Field(default="", max_length=32)
    blocking: Optional[BlockReportIn] = None


class EnrollIn(BaseModel):
    token: str = Field(min_length=10, max_length=128)
    os: str = Field(default="", max_length=64)


class AgentCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    os: str = Field(default="", max_length=64)


class AgentPatch(BaseModel):
    enabled: bool


class AlertPatch(BaseModel):
    status: Literal["open", "ack", "false_positive"]


class SettingsBody(BaseModel):
    config: dict[str, Any]


class BlockCreate(BaseModel):
    parent: str = Field(min_length=1, max_length=253)       # the domain to block
    scope: Literal["host", "all"] = "host"
    host: Optional[str] = Field(default=None, max_length=64)  # agent name when scope = host
    hours: Optional[float] = Field(default=None, ge=0, le=24 * 365)   # None / 0 = until removed
    reason: str = Field(default="", max_length=200)


class AlertBlock(BaseModel):
    scope: Literal["host", "all"] = "host"
    hours: Optional[float] = Field(default=None, ge=0, le=24 * 365)
