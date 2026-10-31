# Releasing

Published versions cannot be replaced or reused, so do these in order and stop at the first failure.

## Pre-flight (all automated, run from the repo root)
```bash
pytest -q && ruff check src tests            # 80 tests at last release prep
pip-audit --skip-editable                    # see docs/security-audit.md for accepted tool-only findings
rm -rf dist && python -m build && twine check dist/*
# install the wheel into an EMPTY virtualenv (not editable) and run: mcp-chaos doctor; attack demo:vulnerable (exit 1) and demo:secure (exit 0)
```

## 1. TestPyPI (rehearsal)
Create a token at https://test.pypi.org/manage/account/token/ and export it (never commit it):
```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD=<testpypi token> twine upload --repository-url https://test.pypi.org/legacy/ dist/*
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ mcp-chaos
```

## 2. PyPI (permanent)
Token from https://pypi.org/manage/account/token/ (scope it to the project after the first upload).
```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD=<pypi token> twine upload dist/*
```
Then tag: `git tag v0.1.0 && git push --tags`. Prefer switching to PyPI trusted publishing (GitHub Actions OIDC) so no long-lived token exists.

## 3. npm launcher (only after PyPI is live; it depends on the PyPI package)
```bash
cd npm && MCP_CHAOS_TEST_PYTHON=<python with mcp-chaos installed> npm test
npm pack --dry-run          # expect 4 files: LICENSE, README.md, bin/mcp-chaos.js, package.json
npm publish --access public # needs `npm login` or an automation token with 2FA configured
```

## Versioning
Bump `version` in `pyproject.toml` and `src/mcp_chaos/__init__.py` and `npm/package.json` together; update CHANGELOG.md.
