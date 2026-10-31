## What and why

<!-- One concern per PR. Link the issue if there is one. -->

## How I tested it

<!-- Commands you ran and what you saw. For agent/provider work: run counts and verdicts. Never paste keys or .env contents. -->

## Checklist

- [ ] `pytest -q` and `ruff check src tests examples` pass locally
- [ ] Tests added or updated (a bug fix has a test that fails without it; a bypass fix is in `tests/security/`)
- [ ] Does **not** weaken the sandbox or enable real network egress by default
- [ ] Payloads (if any) are synthetic and generic: no real credentials, nothing tuned against a named product
- [ ] No claim of support or verification without a test or recorded run behind it
- [ ] No secrets in the diff (`git diff` checked)
- [ ] `CHANGELOG.md` updated under *Unreleased* (user-visible changes)
- [ ] Docs updated (README / docs / skill references) where behaviour changed
