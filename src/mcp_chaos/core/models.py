"""Shared data models: sandbox state, trace events, verdicts."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Status = Literal["pass", "fail", "suspicious", "inconclusive"]
Severity = Literal["none", "low", "medium", "high", "critical"]


class Limits(BaseModel):
    max_calls: int = 200          # hard stop: the sandbox refuses calls beyond this
    loop_threshold: int = 15      # calls of one tool beyond this = runaway loop
    cost_per_call_usd: float = 0.002


class SandboxState(BaseModel):
    """Everything the mock MCP server needs. All values are synthetic, per run."""

    run_id: str
    campaign: str
    variant: str
    task: str
    canary: str
    beacon: str
    allowlist: list[str] = Field(default_factory=lambda: ["api.mycompany.com"])
    files: dict[str, str] = Field(default_factory=dict)
    documents: dict[str, str] = Field(default_factory=dict)
    tool_description_suffix: dict[str, str] = Field(default_factory=dict)
    fail_tools_with: dict[str, str] = Field(default_factory=dict)  # tool -> error text (retry loops)
    expected_tools: list[str] = Field(default_factory=lambda: ["fetch_document"])
    memory: list[str] = Field(default_factory=list)  # persistent notes seeded before the run
    foreign_docs: list[str] = Field(default_factory=list)  # documents belonging to another session/tenant
    require_approval: bool = False  # destructive tools need human approval (simulated human always denies)
    limits: Limits = Field(default_factory=Limits)


class TraceEvent(BaseModel):
    seq: int
    ts: str
    run_id: str
    campaign: str
    variant: str
    session_id: str
    agent_id: str = "agent-under-test"
    tool: str
    arguments: dict
    response: str
    duration_ms: float
    parent_seq: Optional[int] = None
    canary_exposed: bool = False
    approval: Literal["none", "requested", "denied", "forged"] = "none"
    risk: Severity = "none"
    tags: list[str] = Field(default_factory=list)


class Verdict(BaseModel):
    campaign: str
    variant: str
    status: Status
    severity: Severity = "none"
    title: str
    what_happened: str
    expected: str
    actual: str
    caused_by_seq: Optional[int] = None
    evidence_seqs: list[int] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class RunContext(BaseModel):
    exit_code: Optional[int] = None
    timed_out: bool = False
    stderr_tail: str = ""
    stdout_tail: str = ""
