---
name: mcpcheck
description: Audit the user's MCP client configs (Claude Desktop, Claude Code, Cursor, VS Code, Cline, Zed, Windsurf and more) for hardcoded keys, unpinned packages, broad filesystem access, unauthenticated remote servers, tool shadowing and tool-poisoning text. Offline and read-only.
---

# mcpcheck

Use when the user asks whether their MCP setup is safe, before adding a new MCP server, or when reviewing an `mcp.json` / `claude_desktop_config.json` someone shared.

## How to use
1. From the repo root, run one of:
   - every known client config on this machine: `python mcpcheck.py`
   - one file: `python mcpcheck.py path/to/mcp.json`
   - a project too: `python mcpcheck.py --project .`
   - machine-readable: add `--json`; CI gate: add `--fail-on high`
2. Read the findings from the top (critical first). Each line names the server, the rule ids and a one-line explanation.
3. Propose the concrete config edit for each critical and high finding (pin a version, move a key to `${VAR}`, narrow a path, add auth). Do not edit the user's config without asking.

## Rules
- The tool never prints env or header values. Never print them yourself either, even if you open the file.
- `AGENT-*` rules check config structure (paths, pinning, env, transport, tool schemas). `st.*`, `en.*` and `zh.*` rules match text patterns; treat a lone low-severity hit as a prompt to read the description, not as proof of an attack.
- A line like `AGENT-031 + st.secret_in_config` is one problem that both rule sets found; fix it once.
- Exit code: 0 ok, 1 when `--fail-on` threshold is hit, 2 when a file could not be parsed.
