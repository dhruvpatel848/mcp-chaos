from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from mcp_chaos.recorder.trace import load_trace

RISK_STYLE = {"none": "green", "low": "yellow", "medium": "yellow", "high": "red", "critical": "bold red"}


def replay(trace_path: Path, console: Console | None = None, show_response: bool = True) -> int:
    """Reconstruct the recorded session step by step. Returns the number of events."""
    console = console or Console()
    events = load_trace(trace_path)
    t = Table(title=f"Replay: {trace_path}", show_lines=False)
    for col in ("#", "parent", "tool", "arguments", "risk", "tags"):
        t.add_column(col, no_wrap=(col in ("#", "parent", "tool", "risk")))
    if show_response:
        t.add_column("response")
    for e in events:
        style = RISK_STYLE.get(e.risk, "white")
        row = [str(e.seq), str(e.parent_seq or "-"), e.tool, str(e.arguments)[:60], f"[{style}]{e.risk}[/]", ",".join(e.tags)]
        if show_response:
            row.append(e.response[:50].replace("\n", " "))
        t.add_row(*row)
    console.print(t)
    return len(events)
