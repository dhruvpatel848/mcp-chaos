# Contributing

Contributions of every size are welcome: campaigns, adapters, provider verification, payloads, docs, bug reports, reviews. Open an issue first only for large changes; small fixes can go straight to a pull request. Look for issues labelled `good first issue`.

```bash
pip install -e ".[dev,dashboard,langgraph]"
pytest -q && ruff check src tests
```
- New campaign: see docs/campaigns.md (plugin interface and `examples/demo_campaigns/`). It needs a vulnerable and a resisting outcome in tests.
- Payloads must stay generic and synthetic; no attacks tuned against named products or real credentials.
- Never add an option that disables sandbox protections or enables real network egress.
- Do not claim support for a framework you have not tested.
