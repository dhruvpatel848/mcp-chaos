# CLAUDE.md

@AGENTS.md

## Claude Code specifics

- Use the project virtualenv (`.venv`) for every Python command; the global interpreter has unrelated packages and must not be modified.
- On Windows with Git Bash, long heredocs containing quotes can fail to parse. Write multi-line files with the Write tool, and put complex edit scripts in a file instead of a heredoc.
- Registry tokens and API keys live in `.env` (gitignored). Read only the variable names you need, never print values, and never include them in commit messages, issues or docs.
- Pushing, publishing to PyPI/npm, and rewriting git history are outward-facing: ask first.
- The Agent Skill for *using* MCP-CHAOS (as opposed to developing it) is in `skills/mcp-chaos/SKILL.md`.
