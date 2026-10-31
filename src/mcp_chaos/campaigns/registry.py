from __future__ import annotations

from importlib.metadata import entry_points

from .base import Campaign
from .advanced_campaigns import MemoryPoisoning, PermissionEscalation, SessionIsolation
from .cost_drain import CostDrain
from .extra_campaigns import ApprovalBypass, CrossToolLeak, FileAccess
from .injection_campaigns import DataExfil, Destructive, PoisonedContent

_BUILTIN = [DataExfil, PoisonedContent, Destructive, CostDrain, FileAccess, CrossToolLeak, ApprovalBypass,
            PermissionEscalation, MemoryPoisoning, SessionIsolation]


def all_campaigns() -> dict[str, Campaign]:
    reg = {c.id: c() for c in _BUILTIN}
    try:
        eps = entry_points()
        group = eps.select(group="mcp_chaos.campaigns") if hasattr(eps, "select") else eps.get("mcp_chaos.campaigns", [])
        for ep in group:
            cls = ep.load()
            reg[cls.id] = cls()
    except Exception:  # a broken third-party plugin must not break the core
        pass
    return reg


def resolve(mode: str) -> list[Campaign]:
    reg = all_campaigns()
    if mode == "all":
        return list(reg.values())
    names = [m.strip() for m in mode.split(",")]
    missing = [n for n in names if n not in reg]
    if missing:
        raise KeyError(f"unknown campaign(s): {', '.join(missing)}; available: {', '.join(reg)}")
    return [reg[n] for n in names]
