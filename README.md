<div align="center">

# mcpcheck

**Audit every MCP config on your machine for leaked keys, rug-pull risks and tool poisoning. Offline, no deps.**

agent-audit and MCP-checkup each catch MCP config problems the other misses. mcpcheck runs both rule sets in one pass, in one stdlib file.

Works with **Claude Code** and **Codex**.

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg) ![Status: prototype](https://img.shields.io/badge/status-prototype-orange.svg)

</div>

## Quick start
```bash
git clone https://github.com/Dodai0419/mcpcheck && cd mcpcheck
python mcpcheck.py tests/fixtures/aa-example-test.json
```
```
mcpcheck - 1 config files, 4 servers (offline, read-only)
risk 48 - 2 critical, 4 high, 2 medium, 0 low
    HIGH     filesystem             AGENT-029 + st.root_path         Filesystem access to '/' is overly broad
    CRITICAL remote-unverified      AGENT-030 + st.plaintext_http    Server URL uses unencrypted http://
    HIGH     shell-executor         AGENT-031 + st.secret_in_config  Hardcoded value for sensitive key 'DATABASE_PASSWORD'; use ${DATABASE_PASSWORD}
    CRITICAL untrusted-server       AGENT-030                        Unpinned package 'some-random-mcp-package@latest' (rug-pull risk); pin @x.y.z
```
Run `python mcpcheck.py` with no file to check every known client config on this machine (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Qoder, Zed, Gemini CLI, opencode, Continue). Add `--project .` for project files, `--json` for machines, `--fail-on high` for CI.

## The problem
- agent-audit's MCP rules catch unpinned `npx`/`uvx` packages, wildcard grants, unsandboxed stdio servers, tool shadowing and poisoned tool schemas, but miss zero-width characters, base64 payloads, typosquatted package names and Chinese injection text.
- MCP-checkup catches those, but misses pinning, sandboxing, tool shadowing and schema problems, and its report titles are in Chinese.
- Running both means two installs (agent-audit pulls click, rich, pydantic, PyYAML, aiohttp, aiofiles and langdetect), two reports, and the same leaked key reported twice.

## The solution
| Idea | Fixes |
|------|-------|
| **Both rule sets, one pass** | agent-audit's AGENT-029..057 MCP rules + MCP-checkup's 28 text rules, typosquat and auth checks on the same files |
| **Twin findings folded** | a key both tools flag shows once as `AGENT-031 + st.secret_in_config` |
| **Same results as upstream** | every AGENT finding (rule, severity, server, order) and every MCP-checkup hit plus its risk sum, tested on 24 fixtures |
| **Never prints secrets** | env and header values stay out of every report (tested) |
| **One stdlib file** | no install, no server start, no network |

## Use with Claude Code
```bash
/plugin marketplace add Dodai0419/mcpcheck
/plugin install mcpcheck@mcpcheck
```

## Use with Codex (ChatGPT)
```bash
git clone https://github.com/Dodai0419/mcpcheck && cp -r mcpcheck/skills/* ~/.codex/skills/
```
Or copy `AGENTS.md` into your project root.

## Benchmarks
Same input (`tests/fixtures/mixed.json`, 15 servers), Windows 11, Python 3.11, fresh process per run, median of 9 interleaved runs on a busy machine. Upstream = agent-audit's `MCPConfigScanner` called from a one-line script (its full CLI also loads every other scanner) plus `python -m mcp_checkup scan --config FILE --json` with an empty home.

| | original (both tools) | mcpcheck |
|-|-|-|
| wall time, one config | 1,665 ms | 613 ms |
| lines of code | 1,608 (agent-audit MCP scanner + description analyzer) + 1,169 Python + 273 JSON rules | 522 |
| dependencies | 7 (agent-audit) + 0 | 0 |

Same findings: on all 24 fixtures (16 from agent-audit's own tests and examples, 2 from MCP-checkup, 6 written for this repo) the AGENT findings equal agent-audit's, and the st/en/zh hits per server and the risk sum equal MCP-checkup's (`python -m unittest -q`). On 1,200 random configs the AGENT findings matched agent-audit's in every case. agent-audit names the AGENT-055 server by iterating a set, so that one field can differ between its own runs; mcpcheck always names the first server. YAML configs are read only when PyYAML is installed.

## Inspired by
- [HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit): the AGENT-029..057 MCP config rules and the tool-description poisoning patterns.
- [tiangang0245/MCP-checkup](https://github.com/tiangang0245/MCP-checkup): the injection and structure rules, client config paths, typosquat list and risk score.

## Roadmap
- [ ] Read per-project `mcpServers` inside `~/.claude.json`.
- [ ] SARIF output for GitHub code scanning.
- [ ] Tool-definition snapshots to catch rug pulls (MCP-checkup's `snapshot`, opt-in).

## License
MIT
