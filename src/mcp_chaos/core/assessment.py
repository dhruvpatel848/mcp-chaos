"""Run orchestration: one sandboxed run per (campaign, variant, repetition) -> Assessment."""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from pydantic import BaseModel

from mcp_chaos.adapters.target import resolve_target, run_agent, run_agent_docker
from mcp_chaos.campaigns.base import Campaign
from mcp_chaos.core.models import RunContext, Verdict
from mcp_chaos.recorder.trace import load_trace


class RunRecord(BaseModel):
    campaign: str
    variant: str
    index: int
    dir: str
    exit_code: Optional[int] = None
    timed_out: bool = False
    tool_calls: int = 0
    verdict: Verdict


class Assessment(BaseModel):
    id: str
    target: str
    started: str
    finished: str = ""
    runs_per_variant: int = 1
    runs: list[RunRecord] = []
    score: Optional[dict] = None

    def save(self, out: Path) -> None:
        (out / "assessment.json").write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls, out: Path) -> "Assessment":
        return cls.model_validate_json((Path(out) / "assessment.json").read_text(encoding="utf-8"))


def run_one(campaign: Campaign, variant: str, index: int, argv: list[str], out: Path, timeout: int,
            max_calls: int, target: str = "", docker: bool = False, guard: Optional[Path] = None, pass_env: tuple = (), allow_hosts: tuple = ()) -> RunRecord:
    name = f"{campaign.id}--{variant}--{index}"
    rdir = out / "runs" / name
    rdir.mkdir(parents=True, exist_ok=True)
    state = campaign.build(variant, uuid.uuid4().hex[:10])
    state.limits.max_calls = max_calls
    (rdir / "state.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")
    trace = rdir / "trace.jsonl"
    trace.write_text("", encoding="utf-8")
    server_cmd = [sys.executable, "-m", "mcp_chaos.mocks.server", "--state", str(rdir / "state.json"), "--trace", str(trace)]
    if guard is not None:  # re-attack through the policy enforcer
        server_cmd = [sys.executable, "-m", "mcp_chaos.guard", "--policy", str(Path(guard).resolve()), "--", *server_cmd]
    if docker:
        ctx = run_agent_docker(target, rdir / "state.json", trace, state.task, timeout, rdir, pass_env, allow_hosts)
    else:
        ctx = run_agent(argv, server_cmd, state.task, timeout, cwd=rdir, pass_env=pass_env)
    events = load_trace(trace)
    verdict = _judge(campaign, state, events, ctx)
    (rdir / "verdict.json").write_text(verdict.model_dump_json(indent=2), encoding="utf-8")
    (rdir / "agent_output.txt").write_text(f"exit={ctx.exit_code} timed_out={ctx.timed_out}\n--stdout--\n{ctx.stdout_tail}\n--stderr--\n{ctx.stderr_tail}", encoding="utf-8")
    return RunRecord(campaign=campaign.id, variant=variant, index=index, dir=str(rdir.relative_to(out)),
                     exit_code=ctx.exit_code, timed_out=ctx.timed_out, tool_calls=len(events), verdict=verdict)


def _judge(campaign, state, events, ctx: RunContext) -> Verdict:
    verdict = campaign.judge(state, events, ctx)
    if verdict.status == "pass" and (not events or (ctx.exit_code not in (0, None)) or ctx.timed_out):
        why = "timed out" if ctx.timed_out else f"exit code {ctx.exit_code}"
        return Verdict(
            campaign=campaign.id, variant=state.variant, status="inconclusive", severity="none",
            title="Run did not complete normally",
            what_happened=f"Agent ended abnormally ({why}) with {len(events)} recorded tool calls; absence of a failure proves nothing.",
            expected="Agent finishes the task.", actual=f"{why}; stderr: {ctx.stderr_tail[-300:]!r}",
            remediation=["Run `mcp-chaos doctor`, then run the agent manually against the sandbox to see why it failed."])
    return verdict


def run_assessment(target: str, campaigns: list[Campaign], out: Path, runs: int = 1, timeout: int = 120,
                   max_calls: int = 200, docker: bool = False, guard: Optional[Path] = None, pass_env: tuple = (), allow_hosts: tuple = (), on_progress: Optional[Callable[[RunRecord], None]] = None) -> Assessment:
    from mcp_chaos.scoring.engine import compute_score

    argv = resolve_target(target)
    if docker:
        from mcp_chaos.adapters.target import docker_available
        if not docker_available():
            raise RuntimeError("docker sandbox requested but image 'mcp-chaos:local' not found; run `docker build -t mcp-chaos:local .`")
    out = Path(out).resolve()  # agents run with cwd=<run dir>, so every path handed to them must be absolute
    out.mkdir(parents=True, exist_ok=True)
    a = Assessment(id=out.name, target=target, started=datetime.now(timezone.utc).isoformat(), runs_per_variant=runs)
    for c in campaigns:
        for v in c.variants:
            for i in range(1, runs + 1):
                rec = run_one(c, v, i, argv, out, timeout, max_calls, target, docker, guard, pass_env, allow_hosts)
                a.runs.append(rec)
                if on_progress:
                    on_progress(rec)
    a.finished = datetime.now(timezone.utc).isoformat()
    a.score = compute_score(a)
    a.save(out)
    return a
