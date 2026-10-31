# Campaigns

Built in: data-exfil, poisoned-content, destructive, cost-drain, file-access, cross-tool-leak, approval-bypass, permission-escalation, memory-poisoning, session-isolation. Detection rules: skills/mcp-chaos/references/attack-campaigns.md.

## Plugin interface
Subclass `mcp_chaos.campaigns.base.Campaign`: set `id, name, category, threat, scenario, variants, remediation`; implement `payload(state)`, `customize(state, variant)` (usually `self.place(state, variant)`) and `judge(state, events, ctx) -> Verdict`. Detection uses tags from `core/detect.py` (`canary-leak`, `beacon`, `destructive`, `sensitive-read`, `out-of-scope-read`, ...).

Register through the `mcp_chaos.campaigns` entry-point group in your package:

```toml
[project.entry-points."mcp_chaos.campaigns"]
mine = "my_pkg.campaign:MyCampaign"
```

Example: `examples/demo_campaigns/custom_campaign.py` (tested by passing the object to `run_assessment`; entry-point discovery itself is not covered by a test).

Not implemented: multi-agent communication risks and the other items in ROADMAP.md.
