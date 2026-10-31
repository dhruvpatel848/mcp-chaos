"""Agent adapter: launches a local agent as a subprocess wired to the sandbox MCP server.

Supported targets (all local, launched by mcp-chaos itself; there is no remote-host mode):
  demo:vulnerable | demo:secure   bundled deterministic demo agents
  ./agent.py                       any Python script following the agent contract (see demo_agents/_common.py)
  "node agent.js --flag"           any local command following the same contract
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from mcp_chaos.core.models import RunContext


class TargetError(Exception):
    pass


def resolve_target(target: str) -> list[str]:
    if target.startswith("demo:"):
        name = target.split(":", 1)[1]
        if name not in ("vulnerable", "secure"):
            raise TargetError("demo target must be demo:vulnerable or demo:secure")
        return [sys.executable, "-m", f"mcp_chaos.demo_agents.{name}"]
    if "://" in target:
        raise TargetError("remote targets are not supported: mcp-chaos only launches local agents")
    p = Path(target)
    if p.suffix == ".py" and (p.is_file() or " " not in target.strip()):  # a bare script path, not `python script.py`
        if not p.is_file():
            raise TargetError(f"agent script not found: {target}")
        return [sys.executable, str(p.resolve())]
    argv = shlex.split(target, posix=os.name != "nt")
    argv = [a[1:-1] if len(a) > 1 and a[0] == a[-1] and a[0] in "\"'" else a for a in argv]
    if not argv or not (shutil.which(argv[0]) or Path(argv[0]).exists()):
        raise TargetError(f"cannot find local command: {argv[0] if argv else target!r}")
    if argv[0].lower() in ("python", "python3", "python.exe"):
        argv[0] = sys.executable  # the interpreter mcp-chaos itself runs on, so the agent sees the same packages
    # agents run with cwd=<run dir>: pin relative file arguments to where the user launched the command
    argv = [str(Path(a).resolve()) if i > 0 and not a.startswith("-") and Path(a).is_file() else a for i, a in enumerate(argv)]
    return argv


def resolve_restricted(target: str, roots: "list[str] | None" = None) -> list[str]:
    """Targets that a remote caller (MCP tool, dashboard) may start: demo:* or `[python] <script.py> [args]` where the
    script lives under an allowed directory (MCP_CHAOS_ALLOWED_TARGET_DIRS, default: the current directory).
    Arbitrary commands, `python -c`, and scripts elsewhere on disk are refused."""
    if target.startswith("demo:"):
        return resolve_target(target)
    if roots is None:
        env = os.environ.get("MCP_CHAOS_ALLOWED_TARGET_DIRS")
        roots = env.split(os.pathsep) if env else [os.getcwd()]
    allowed = [Path(r).resolve() for r in roots]
    parts = shlex.split(target, posix=os.name != "nt")
    parts = [a[1:-1] if len(a) > 1 and a[0] == a[-1] and a[0] in "\"'" else a for a in parts]
    if parts and Path(parts[0]).stem.lower() in ("python", "python3"):
        parts = parts[1:]
    if not parts or not parts[0].endswith(".py") or not Path(parts[0]).is_file():
        raise TargetError("remote callers may only start demo:* targets or an existing .py script under an allowed directory")
    script = Path(parts[0]).resolve()
    if not any(script.is_relative_to(r) for r in allowed):
        raise TargetError("script is outside the allowed directories (set MCP_CHAOS_ALLOWED_TARGET_DIRS)")
    return resolve_target(" ".join([f'"{sys.executable}"', f'"{script}"', *parts[1:]]))


def _clean_env(extra: dict[str, str], pass_env: tuple = ()) -> dict[str, str]:
    """Scrubbed environment: real secrets in the host environment are never passed to the agent."""
    keep = ["PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "PATHEXT", "COMSPEC"]
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update({k: os.environ[k] for k in pass_env if k in os.environ})  # explicit opt-in only
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        import signal
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_agent(argv: list[str], server_cmd: list[str], task: str, timeout: int, cwd: Path, pass_env: tuple = ()) -> RunContext:
    import json

    env = _clean_env({"MCP_CHAOS_SERVER_CMD": json.dumps(server_cmd), "MCP_CHAOS_TASK": task}, pass_env)
    kwargs = {} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen(argv, env=env, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", **kwargs)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        out, err = proc.communicate()
    return RunContext(exit_code=proc.returncode, timed_out=timed_out, stdout_tail=out[-2000:], stderr_tail=err[-2000:])


DOCKER_IMAGE = "mcp-chaos:local"

# Secrets never go on the `docker run` command line or into -e: those are readable through `docker inspect` and
# `ps`. They are written to the container's stdin, read by this loader, then stdin is closed before the agent starts.
_SECRET_LOADER = (
    "import json,os,runpy,sys\n"
    "os.environ.update(json.loads(sys.stdin.readline() or '{}'))\n"
    "sys.stdin.close(); sys.stdin = open(os.devnull)\n"
    "a = sys.argv[1:]\n"
    "if a[0] == '-m':\n"
    "    sys.argv = [a[1]] + a[2:]; runpy.run_module(a[1], run_name='__main__', alter_sys=True)\n"
    "else:\n"
    "    sys.argv = a; runpy.run_path(a[0], run_name='__main__')\n"
)


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE], capture_output=True)
    return r.returncode == 0


def _docker_agent_argv(target: str, mounts: list[str]) -> list[str]:
    """Translate a target into the argv used inside the container (demo agent, .py script, or `python script.py args`)."""
    if target.startswith("demo:"):
        return ["python", "-m", f"mcp_chaos.demo_agents.{target.split(':', 1)[1]}"]
    argv = resolve_target(target)
    script = next((a for a in argv[1:] if a.endswith(".py") and Path(a).is_file()), None)
    if script is None or Path(argv[0]).stem.lower() not in ("python", "python3", Path(sys.executable).stem.lower()):
        raise TargetError("docker sandbox supports demo:* targets and `python script.py [args]` only")
    p = Path(script).resolve()
    mounts += ["-v", f"{p.parent}:/agent:ro"]
    return ["python", *[f"/agent/{p.name}" if a == script else a for a in argv[1:]]]


def run_agent_docker(target: str, state_path: Path, trace_path: Path, task: str, timeout: int, cwd: Path,
                     pass_env: tuple = (), allow_hosts: tuple = ()) -> RunContext:
    """Run agent + sandbox server inside a container: no network, read-only root, capped memory/CPU/pids.

    With allow_hosts, the agent container sits on an internal network whose only exit is an allowlist-only
    HTTPS CONNECT proxy (mcp_chaos.sandbox.egress_proxy) permitting exactly those hostnames on port 443.
    """
    import json
    import uuid

    from mcp_chaos.sandbox.egress_proxy import validate_allowlist

    hosts = validate_allowlist(list(allow_hosts)) if allow_hosts else []
    rdir = state_path.parent
    mounts = ["-v", f"{rdir}:/run/chaos"]
    agent = _docker_agent_argv(target, mounts)
    server = ["python", "-m", "mcp_chaos.mocks.server", "--state", "/run/chaos/state.json", "--trace", "/run/chaos/trace.jsonl"]
    uid = uuid.uuid4().hex[:8]
    name = f"mcp-chaos-{uid}"
    net_args = ["--network", "none"]
    env_args = ["-e", f"MCP_CHAOS_SERVER_CMD={json.dumps(server)}", "-e", f"MCP_CHAOS_TASK={task}", "-e", "PYTHONIOENCODING=utf-8"]
    secrets = {k: os.environ[k] for k in pass_env if k in os.environ}
    net = proxy = None
    try:
        if hosts:
            net, proxy = f"mcp-chaos-net-{uid}", f"mcp-chaos-proxy-{uid}"
            subprocess.run(["docker", "network", "create", "--internal", net], capture_output=True, check=True)
            subprocess.run(["docker", "run", "-d", "--rm", "--name", proxy, "--network", net, "--read-only", "--cap-drop", "ALL",
                            "--security-opt", "no-new-privileges", "--memory", "128m", DOCKER_IMAGE, "python", "-m",
                            "mcp_chaos.sandbox.egress_proxy", *[x for h in hosts for x in ("--allow", h)]],
                           capture_output=True, check=True)
            subprocess.run(["docker", "network", "connect", "bridge", proxy], capture_output=True, check=True)
            net_args = ["--network", net]
            px = f"http://{proxy}:3128"
            env_args += ["-e", f"HTTPS_PROXY={px}", "-e", f"https_proxy={px}"]
        agent_cmd = ["python", "-c", _SECRET_LOADER, *agent[1:]] if secrets else agent
        cmd = ["docker", "run", "--rm", *(["-i"] if secrets else []), "--name", name, *net_args, "--read-only", "--tmpfs", "/tmp",
               "--memory", "512m", "--cpus", "1", "--pids-limit", "256", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", *env_args, *mounts, DOCKER_IMAGE, *agent_cmd]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE if secrets else subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace")
        timed_out = False
        try:
            out, err = proc.communicate(input=(json.dumps(secrets) + "\n") if secrets else None, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            subprocess.run(["docker", "kill", name], capture_output=True)
            proc.kill()
            out, err = proc.communicate()
        return RunContext(exit_code=proc.returncode, timed_out=timed_out, stdout_tail=out[-2000:], stderr_tail=err[-2000:])
    finally:
        if proxy:
            subprocess.run(["docker", "rm", "-f", proxy], capture_output=True)
        if net:
            subprocess.run(["docker", "network", "rm", net], capture_output=True)
