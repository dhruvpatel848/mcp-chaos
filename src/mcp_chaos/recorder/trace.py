from __future__ import annotations

from pathlib import Path

from mcp_chaos.core.models import TraceEvent


def load_trace(path: Path) -> list[TraceEvent]:
    """Load a JSONL trace; raises ValueError on corrupt lines or non-monotonic sequence numbers."""
    events: list[TraceEvent] = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(TraceEvent.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"{path}:{n}: invalid trace line: {exc}") from exc
    for a, b in zip(events, events[1:]):
        if b.seq != a.seq + 1:
            raise ValueError(f"{path}: trace sequence gap between #{a.seq} and #{b.seq}")
    return events
