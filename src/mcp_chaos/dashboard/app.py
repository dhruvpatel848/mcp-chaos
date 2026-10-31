"""Optional local web dashboard. Binds to 127.0.0.1; state-changing calls need a per-process token."""
from __future__ import annotations

import secrets
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from mcp_chaos.adapters.target import TargetError, resolve_target
from mcp_chaos.campaigns.registry import all_campaigns, resolve
from mcp_chaos.core.assessment import Assessment, run_assessment
from mcp_chaos.core.models import Verdict
from mcp_chaos.policies import policy as pol
from mcp_chaos.recorder.trace import load_trace
from mcp_chaos.reporting.report import write_reports

STATIC = Path(__file__).parent / "static" / "index.html"


class StartRequest(BaseModel):
    target: str
    mode: str = "all"
    runs: int = 1
    timeout: int = 120


def create_app(runs_dir: Path = Path("runs")) -> FastAPI:
    runs_dir = Path(runs_dir).resolve()
    token = secrets.token_urlsafe(24)
    jobs: dict[str, dict] = {}
    app = FastAPI(title="MCP-CHAOS dashboard", docs_url=None, redoc_url=None)
    app.state.token = token

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost", "testserver"):
            return JSONResponse({"detail": "dashboard only answers on localhost"}, status_code=403)  # DNS-rebinding guard
        return await call_next(request)

    def adir(aid: str) -> Path:
        if Path(aid).name != aid:
            raise HTTPException(400, "bad id")
        d = runs_dir / aid
        if not d.is_dir():
            raise HTTPException(404, "unknown assessment")
        return d

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return STATIC.read_text(encoding="utf-8").replace("__TOKEN__", token)

    @app.get("/api/campaigns")
    def campaigns() -> list[dict]:
        return [{"id": c.id, "name": c.name, "category": c.category, "threat": c.threat, "scenario": c.scenario,
                 "variants": c.variants, "remediation": c.remediation} for c in all_campaigns().values()]

    @app.get("/api/assessments")
    def assessments() -> list[dict]:
        out = []
        if runs_dir.is_dir():
            for d in sorted(runs_dir.iterdir(), reverse=True):
                if (d / "assessment.json").exists():
                    a = Assessment.load(d)
                    out.append({"id": a.id, "target": a.target, "started": a.started, "runs": len(a.runs),
                                "score": a.score, "state": "done"})
                elif d.name in jobs:
                    out.append({"id": d.name, "state": jobs[d.name]["state"], "target": jobs[d.name]["target"]})
        return out

    @app.get("/api/assessments/{aid}")
    def assessment(aid: str) -> dict:
        d = adir(aid)
        if not (d / "assessment.json").exists():
            done = [Verdict.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted((d / "runs").glob("*/verdict.json"))]
            return {"id": aid, "state": jobs.get(aid, {}).get("state", "unknown"), "error": jobs.get(aid, {}).get("error"),
                    "partial": [v.model_dump() for v in done]}
        return {**Assessment.load(d).model_dump(), "state": "done"}

    @app.get("/api/assessments/{aid}/trace/{run}")
    def trace(aid: str, run: str) -> list[dict]:
        if Path(run).name != run:
            raise HTTPException(400, "bad run")
        f = adir(aid) / "runs" / run / "trace.jsonl"
        if not f.exists():
            raise HTTPException(404, "no trace")
        return [e.model_dump() for e in load_trace(f)]

    @app.get("/api/assessments/{aid}/policy")
    def policy(aid: str) -> dict:
        d = adir(aid)
        a = Assessment.load(d)
        p = pol.generate(a, d)
        return {"yaml": pol.dump_policy(p), "rules": [r.model_dump(exclude_none=True) for r in p.rules],
                "test": pol.test_policy(p, a, d), "review_required": True}

    @app.post("/api/assessments")
    def start(req: StartRequest, x_chaos_token: Optional[str] = Header(default=None)) -> dict:
        if not x_chaos_token or not secrets.compare_digest(x_chaos_token, token):
            raise HTTPException(403, "missing or bad token")
        try:
            resolve_target(req.target)
            camps = resolve(req.mode)
        except (TargetError, KeyError) as exc:
            raise HTTPException(400, str(exc))
        aid = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        jobs[aid] = {"state": "running", "error": None, "target": req.target}
        out = runs_dir / aid

        def work() -> None:
            try:
                a = run_assessment(req.target, camps, out, runs=max(1, min(req.runs, 10)), timeout=max(5, min(req.timeout, 600)))
                write_reports(a, out)
                jobs[aid]["state"] = "done"
            except Exception as exc:
                jobs[aid].update(state="error", error=f"{type(exc).__name__}: {exc}")

        threading.Thread(target=work, daemon=True).start()
        return {"id": aid}

    return app
