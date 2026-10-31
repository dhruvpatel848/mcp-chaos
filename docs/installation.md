# Installation

Python >= 3.10. From a clone, inside a virtualenv: `pip install -e ".[dev,dashboard,langgraph]"`. Verify with `mcp-chaos doctor`.

Not on PyPI yet. Optional Docker sandbox: `docker build -t mcp-chaos:local .` then `mcp-chaos attack --sandbox docker ...` (experimental, unverified; see security-model.md).
