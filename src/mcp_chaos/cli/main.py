"""mcp-chaos command line. Exit codes: 0 all passed, 1 at least one failure, 2 tool/setup error."""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import click
import yaml
from rich.console import Console

from mcp_chaos import __version__
from mcp_chaos.adapters.target import TargetError, resolve_target
from mcp_chaos.campaigns.registry import all_campaigns, resolve
from mcp_chaos.core.assessment import Assessment, run_assessment
from mcp_chaos.policies import policy as pol
from mcp_chaos.replay.replay import replay as do_replay
from mcp_chaos.reporting.report import to_markdown, write_reports

console = Console()
err = Console(stderr=True)
STATUS_STYLE = {"pass": "green", "fail": "bold red", "suspicious": "yellow", "inconclusive": "cyan"}

CONFIG_TEMPLATE = """# mcp-chaos.yaml
target: demo:vulnerable      # or ./my-agent.py, or a local command
campaigns: all               # or a list: [data-exfil, poisoned-content]
runs: 1                      # repetitions per variant (agents are non-deterministic)
timeout: 120                 # seconds per run
max_calls: 200               # hard tool-call cap enforced by the sandbox
"""


def _load_env_file(path: Path) -> None:
    """Minimal KEY=VALUE parser; existing environment variables win. Values are never printed."""
    import os

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.split(" #")[0].strip().strip("\"'")
        if v and k.strip() not in os.environ:
            os.environ[k.strip()] = v


def _fail(msg: str) -> "None":
    err.print(f"[bold red]error:[/] {msg}")
    sys.exit(2)


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """Sandboxed security testing for tool-connected (MCP) AI agents. Test only agents you own."""


@cli.command()
def init() -> None:
    """Write a starter mcp-chaos.yaml."""
    p = Path("mcp-chaos.yaml")
    if p.exists():
        _fail("mcp-chaos.yaml already exists")
    p.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    console.print("Wrote mcp-chaos.yaml. Try: [bold]mcp-chaos attack --target demo:vulnerable[/]")


@cli.command("list-campaigns")
@click.option("--json", "as_json", is_flag=True)
def list_campaigns(as_json: bool) -> None:
    """List available attack campaigns."""
    info = [{"id": c.id, "name": c.name, "category": c.category, "variants": c.variants, "threat": c.threat}
            for c in all_campaigns().values()]
    if as_json:
        click.echo(json.dumps(info, indent=2))
        return
    for c in info:
        console.print(f"[bold]{c['id']}[/]  {c['name']}\n  {c['threat']}\n  variants: {', '.join(c['variants'])}")


@cli.command()
@click.option("--target", help="Local agent: demo:vulnerable | demo:secure | ./agent.py | 'command args'")
@click.option("--mode", default=None, help="Campaign id(s), comma-separated, or 'all'")
@click.option("--runs", type=int, default=None, help="Repetitions per variant")
@click.option("--timeout", type=int, default=None, help="Seconds per run")
@click.option("--max-calls", type=int, default=None, help="Hard tool-call cap per run")
@click.option("--out", type=click.Path(path_type=Path), default=None, help="Output folder (default ./runs/<timestamp>)")
@click.option("--config", type=click.Path(path_type=Path), default=Path("mcp-chaos.yaml"))
@click.option("--env-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None, help="Load KEY=VALUE pairs (e.g. .env) into this process; they reach the agent only if named with --pass-env")
@click.option("--pass-env", multiple=True, help="Environment variable to pass through to the agent (repeatable)")
@click.option("--allow-egress", "allow_egress", multiple=True, help="Docker sandbox only: hostname the agent may reach over HTTPS via the allowlist proxy (repeatable; no wildcards)")
@click.option("--guard", type=click.Path(exists=True, path_type=Path), default=None, help="Run the agent through the mcp-guard policy enforcer")
@click.option("--sandbox", type=click.Choice(["process", "docker"]), default="process", help="docker = container with no network (build image first)")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON on stdout")
def attack(target, mode, runs, timeout, max_calls, out, config, env_file, pass_env, allow_egress, guard, sandbox, as_json) -> None:
    """Run sandboxed attack campaigns against a local agent."""
    if allow_egress and sandbox != "docker":
        _fail("--allow-egress requires --sandbox docker (the process sandbox has no network isolation to open)")
    if env_file:
        _load_env_file(env_file)
    cfg = yaml.safe_load(config.read_text(encoding="utf-8")) if config.exists() else {}
    target = target or cfg.get("target")
    if not target:
        _fail("no target: pass --target or create mcp-chaos.yaml (mcp-chaos init)")
    mode = mode or (",".join(cfg["campaigns"]) if isinstance(cfg.get("campaigns"), list) else cfg.get("campaigns", "all"))
    runs = runs or cfg.get("runs", 1)
    timeout = timeout or cfg.get("timeout", 120)
    max_calls = max_calls or cfg.get("max_calls", 200)
    out = out or Path("runs") / datetime.now().strftime("%Y-%m-%d-%H%M%S")
    try:
        resolve_target(target)
        camps = resolve(mode)
    except (TargetError, KeyError) as exc:
        _fail(str(exc))

    def progress(rec) -> None:
        if not as_json:
            v = rec.verdict
            console.print(f"[{STATUS_STYLE[v.status]}]{v.status.upper():12}[/] {rec.campaign}/{rec.variant}#{rec.index}  "
                          f"sev={v.severity} calls={rec.tool_calls}  {v.title}")

    if not as_json:
        console.print(f"[bold]mcp-chaos[/] sandbox run -> {out}  (no network, no real secrets, disposable resources)")
    try:
        a = run_assessment(target, camps, out, runs=runs, timeout=timeout, max_calls=max_calls, docker=(sandbox == "docker"), guard=guard, pass_env=tuple(pass_env), allow_hosts=tuple(allow_egress), on_progress=progress)
    except Exception as exc:  # setup failure
        _fail(f"{type(exc).__name__}: {exc}")
    write_reports(a, out)
    if as_json:
        click.echo(a.model_dump_json(indent=2))
    else:
        s = a.score
        console.print(f"\n[bold]Score {s['overall']}/100[/]  risk: {s['risk']}  critical={s['critical_findings']} high={s['high_findings']}")
        console.print(f"Report: {out / 'report.md'}   Next: mcp-chaos policy {out}")
        console.print("[dim]A score reflects these tests only; it is not proof of security.[/]")
    sys.exit(1 if any(r.verdict.status == "fail" for r in a.runs) else 0)


@cli.command()
@click.argument("trace", type=click.Path(exists=True, path_type=Path))
def replay(trace: Path) -> None:
    """Replay a recorded trace.jsonl step by step."""
    try:
        do_replay(trace)
    except ValueError as exc:
        _fail(str(exc))


@cli.command()
@click.argument("run_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True)
def report(run_dir: Path, as_json: bool) -> None:
    """Print the report of an assessment folder."""
    try:
        a = Assessment.load(run_dir)
    except Exception as exc:
        _fail(f"cannot load assessment: {exc}")
    write_reports(a, run_dir)
    click.echo(a.model_dump_json(indent=2) if as_json else to_markdown(a))


@cli.command()
@click.argument("run_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--out", type=click.Path(path_type=Path), default=Path("mcp-guard.yaml"))
def policy(run_dir: Path, out: Path) -> None:
    """Generate mcp-guard.yaml from the failures in an assessment (review before use)."""
    try:
        a = Assessment.load(run_dir)
        p = pol.generate(a, run_dir)
    except Exception as exc:
        _fail(f"cannot generate policy: {exc}")
    if not p.rules:
        console.print("No confirmed failures, so no rules were generated.")
        return
    out.write_text(pol.dump_policy(p), encoding="utf-8")
    results = pol.test_policy(p, a, run_dir)
    ok = sum(r["blocked"] for r in results)
    console.print(f"Wrote {out} with {len(p.rules)} rules. Policy test: would have stopped {ok}/{len(results)} failed runs.")
    console.print("[yellow]Review every rule (especially allowlists) before deploying; this does not guarantee security.[/]")


@cli.command("validate-policy")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
def validate_policy(policy_file: Path) -> None:
    """Validate schema and detect conflicting rules."""
    _, errors, warnings = pol.validate(policy_file)
    for w in warnings:
        console.print(f"[yellow]warning:[/] {w}")
    for e in errors:
        console.print(f"[red]error:[/] {e}")
    if errors:
        sys.exit(1)
    console.print("[green]policy valid[/]")


@cli.command()
def providers() -> None:
    """List LLM providers for the real-LLM example agent and whether a key is set (never prints keys)."""
    from mcp_chaos.llm.providers import PROVIDERS, configured

    have = configured()
    for n, p in PROVIDERS.items():
        mark = "[green]key set[/]" if have[n] else "[dim]no key[/]"
        console.print(f"{n:11} {p.region:7} {p.key_env:20} {mark}  {p.note}")


@cli.group()
def approvals() -> None:
    """Human approvals for calls held by the guard proxy."""


@approvals.command("list")
@click.option("--dir", "root", type=click.Path(path_type=Path), default=Path("approvals"))
def approvals_list(root: Path) -> None:
    from mcp_chaos.guard.approvals import list_pending

    pend = list_pending(root)
    for r in pend:
        console.print(f"[bold]{r['id']}[/]  {r['tool']}  {str(r['arguments'])[:100]}  rule={r['rule']}")
    if not pend:
        console.print("no pending approvals")


@approvals.command("approve")
@click.argument("request_id")
@click.option("--dir", "root", type=click.Path(path_type=Path), default=Path("approvals"))
def approvals_approve(request_id: str, root: Path) -> None:
    from mcp_chaos.guard.approvals import decide

    if not decide(root, request_id, "approve"):
        _fail("no such pending request")
    console.print("approved (single use)")


@approvals.command("deny")
@click.argument("request_id")
@click.option("--dir", "root", type=click.Path(path_type=Path), default=Path("approvals"))
def approvals_deny(request_id: str, root: Path) -> None:
    from mcp_chaos.guard.approvals import decide

    if not decide(root, request_id, "deny"):
        _fail("no such pending request")
    console.print("denied")


@cli.command("guard", context_settings={"ignore_unknown_options": True})
@click.option("--policy", "policy_file", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--approvals-dir", type=click.Path(path_type=Path), default=None, help="Enable human approvals: matching calls wait for `mcp-chaos approvals approve <id>`")
@click.option("--approval-timeout", type=float, default=120.0, show_default=True)
@click.argument("upstream", nargs=-1, type=click.UNPROCESSED, required=True)
def guard_cmd(policy_file: Path, approvals_dir, approval_timeout: float, upstream: tuple) -> None:
    """Enforce a policy in front of an MCP server: mcp-chaos guard --policy mcp-guard.yaml -- <server command>"""
    import asyncio

    from mcp_chaos.guard.proxy import serve

    asyncio.run(serve(policy_file, list(upstream), approvals_dir, approval_timeout))


@cli.command("serve-mcp")
def serve_mcp() -> None:
    """Expose MCP-CHAOS as an MCP server over stdio."""
    from mcp_chaos.mcp_server.server import build

    build().run(transport="stdio")


@cli.command()
@click.option("--runs-dir", type=click.Path(path_type=Path), default=Path("runs"))
@click.option("--port", type=int, default=8765)
def dashboard(runs_dir: Path, port: int) -> None:
    """Start the local web dashboard (needs: pip install mcp-chaos[dashboard])."""
    try:
        import uvicorn
        from mcp_chaos.dashboard.app import create_app
    except ImportError:
        _fail("dashboard extras missing: pip install 'mcp-chaos[dashboard]'")
    console.print(f"Dashboard on http://127.0.0.1:{port}  (local only; Ctrl+C to stop)")
    uvicorn.run(create_app(runs_dir), host="127.0.0.1", port=port, log_level="warning")


@cli.command()
def doctor() -> None:
    """Check the environment and run a smoke test."""
    import shutil
    import tempfile

    ok = True
    console.print(f"python {sys.version.split()[0]}")
    try:
        import mcp  # noqa: F401
        console.print("[green]ok[/] mcp SDK importable")
    except ImportError:
        console.print("[red]fail[/] mcp SDK missing")
        ok = False
    console.print(("[green]ok[/]" if shutil.which("docker") else "[yellow]info[/]") +
                  " docker (not required in v0.1; see docs/security-model.md)")
    with tempfile.TemporaryDirectory() as d:
        a = run_assessment("demo:secure", resolve("data-exfil"), Path(d) / "doctor", timeout=60)
        passed = all(r.verdict.status == "pass" for r in a.runs)
        console.print(("[green]ok[/]" if passed else "[red]fail[/]") + " sandbox smoke test (secure demo agent, data-exfil)")
        ok &= passed
    sys.exit(0 if ok else 2)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
