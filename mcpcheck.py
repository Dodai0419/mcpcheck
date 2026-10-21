#!/usr/bin/env python3
"""mcpcheck: offline, read-only security audit of MCP client configs.

Runs two rule sets in one pass over the same files:
  AGENT-029..057  MCP config rules from agent-audit (HeadyZhang, MIT)
  st./en./zh.*    injection and structure rules from MCP-checkup (tiangang0245, MIT)
Never starts a server, never opens a socket, never prints env or header values.

Usage:
  python mcpcheck.py [CONFIG...] [--project DIR] [--json] [--fail-on SEVERITY]
With no CONFIG, every known client config on this machine is checked.
"""
import argparse
import json
import os
import re
import sys
import unicodedata
from urllib.parse import urlparse

SEVERITIES = ("critical", "high", "medium", "low", "info")
RISK_WEIGHT = {"high": 10, "medium": 4, "low": 1, "info": 0}

# ---------------------------------------------------------------- discovery
HOME = os.path.expanduser("~")
APPDATA = os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming")
XDG = os.environ.get("XDG_CONFIG_HOME") or os.path.join(HOME, ".config")
CLIENT_PATHS = [
    ("Claude Desktop", os.path.join(APPDATA, "Claude", "claude_desktop_config.json")),
    ("Claude Desktop", os.path.join(HOME, "Library", "Application Support", "Claude", "claude_desktop_config.json")),
    ("Claude Desktop", os.path.join(XDG, "Claude", "claude_desktop_config.json")),
    ("Claude Code", os.path.join(HOME, ".claude.json")),
    ("Claude Code", os.path.join(HOME, ".mcp.json")),
    ("Cursor", os.path.join(HOME, ".cursor", "mcp.json")),
    ("Windsurf", os.path.join(HOME, ".codeium", "windsurf", "mcp_config.json")),
    ("VS Code", os.path.join(APPDATA, "Code", "User", "mcp.json")),
    ("VS Code", os.path.join(XDG, "Code", "User", "mcp.json")),
    ("VS Code", os.path.join(HOME, ".vscode", "mcp.json")),
    ("Cline", os.path.join(HOME, ".cline", "mcp_settings.json")),
    ("Cline", os.path.join(APPDATA, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")),
    ("Cline", os.path.join(XDG, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")),
    ("Qoder", os.path.join(HOME, ".qoder-cn", "mcp.json")),
    ("Qoder", os.path.join(HOME, ".qoder", "mcp.json")),
    ("Zed", os.path.join(XDG, "zed", "settings.json")),
    ("Zed", os.path.join(HOME, ".zed", "settings.json")),
    ("Gemini CLI", os.path.join(HOME, ".gemini", "settings.json")),
    ("opencode", os.path.join(XDG, "opencode", "opencode.json")),
    ("Continue", os.path.join(HOME, ".continue", "config.json")),
]
PROJECT_FILES = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".qoder/mcp.json", ".qoder-cn/mcp.json",
                 "mcp.json", "claude_desktop_config.json"]


def discover(configs, project):
    out, seen = [], set()
    cands = [("user-supplied", c) for c in configs]
    if not configs:
        cands += CLIENT_PATHS
    if project:
        cands += [("project", os.path.join(project, p)) for p in PROJECT_FILES]
    for client, p in cands:
        full = os.path.normcase(os.path.abspath(os.path.expanduser(p)))
        if full not in seen and (client == "user-supplied" or os.path.isfile(full)):
            seen.add(full)
            out.append((client, p))
    return out


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        try:  # YAML configs, only when PyYAML happens to be installed
            import yaml
            doc = yaml.safe_load(text)
        except ImportError:
            raise ValueError("invalid JSON: %s" % e)
        except Exception as e2:
            raise ValueError("not valid JSON or YAML: %s" % e2)
    if not isinstance(doc, dict):
        raise ValueError("top level is not an object")
    return doc



def servers_for_text(doc):
    """MCP-checkup's view: the first of mcpServers, servers, context_servers, mcp."""
    for key in ("mcpServers", "servers", "context_servers", "mcp"):
        if isinstance(doc.get(key), dict):
            return {str(k): v for k, v in doc[key].items() if isinstance(v, dict)}
    return {}


# ---------------------------------------------------------------- AGENT rules
def servers_for_agent(doc):
    """agent-audit's view: mcpServers, else gateway.servers, else servers (list or dict)."""
    if "mcpServers" in doc:
        sect = doc["mcpServers"]
        return [(n, c) for n, c in sect.items() if isinstance(c, dict)] if isinstance(sect, dict) else []
    if isinstance(doc.get("gateway"), dict):
        sect = doc["gateway"].get("servers", [])
        return [(c.get("name", c.get("image", "unknown")), c) for c in sect if isinstance(c, dict)] \
            if isinstance(sect, list) else []
    sect = doc.get("servers")
    if isinstance(sect, list):
        return [(c.get("name", "unknown"), c) for c in sect if isinstance(c, dict)]
    return [(n, c) for n, c in sect.items() if isinstance(c, dict)] if isinstance(sect, dict) else []


def is_openapi(doc):
    return isinstance(doc.get("openapi"), str) or isinstance(doc.get("swagger"), str) \
        or ("paths" in doc and "mcpServers" not in doc)


def transport(cfg):
    t, url = cfg.get("transport"), cfg.get("url") or ""
    if t:
        return t
    if not url:
        return "stdio"
    if "sse" in url.lower():
        return "sse"
    return "streamable-http" if url.startswith(("http://", "https://")) else None


DANGEROUS_PATHS = ["/", "/home", "/etc", "/usr", "/var", "/root", "~", "$HOME", "%USERPROFILE%", "%HOMEPATH%",
                   "C:\\", "C:/", "D:\\", "D:/"]
SENSITIVE_ENV = re.compile(r"(key|secret|token|password|credential|auth|private)", re.I)
SAFE_ENV = {"PATH", "NODE_ENV", "LOG_LEVEL", "DEBUG", "VERBOSE", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL",
            "TZ", "PYTHONPATH", "NODE_PATH"}
PLACEHOLDER = re.compile("|".join([
    r"your[-_]?api[-_]?key[-_]?here", r"your[-_]\w+[-_]here\b", r"your[-_][\w-]*(?:token|key|secret|password)\b",
    r"<[^>]{2,}>", r"^\$\{", r"xxx+", r"TODO", r"CHANGEME", r"insert[-_]?here", r"replace[-_]?me", r"example[-_]",
    r"placeholder", r"dummy[-_]"]), re.I)
SANDBOX = ("docker", "podman", "container", "sandbox", "nsjail", "firejail", "bubblewrap", "bwrap", "--read-only",
           "seccomp", "apparmor")
RISKY = ("python", "shell", "bash", "exec", "eval", "database", "sql", "code", "repl", "interpreter")
AUTH_ENV = ("auth", "token", "api_key", "apikey", "authorization", "bearer", "secret", "credential", "password")
OFFICIAL_SCOPE = "@modelcontextprotocol/"


def agent_server_rules(name, cfg, grants):
    """Yield (rule, severity, field, title) for one server, in agent-audit's order.

    grants: the raw entry for the permission checks; agent-audit reads them only under mcpServers."""
    args, env = cfg.get("args") or [], cfg.get("env") or {}
    command, url, mode = cfg.get("command") or "", cfg.get("url") or "", transport(cfg)
    # AGENT-029 overly broad filesystem access
    for i, a in enumerate(args):
        if not isinstance(a, str):
            continue
        if any(a == p or a.rstrip("/\\") == p.rstrip("/\\") for p in DANGEROUS_PATHS):
            yield "AGENT-029", "high", "args[%d]" % i, "Filesystem access to '%s' is overly broad" % a
        if "*" in a:
            yield "AGENT-029", "high", "args[%d]" % i, "Wildcard path '%s' may grant unintended access" % a
        if ".." in a:
            yield "AGENT-029", "high", "args[%d]" % i, "Path traversal '%s' may escape the intended directory" % a
    if "filesystem" in name.lower() or any("filesystem" in str(a).lower() for a in args):
        if not [a for a in args if isinstance(a, str) and not a.startswith(("-", "@"))
                and a not in ("npx", "uvx", "node", "python")]:
            yield "AGENT-029", "medium", "args", "Filesystem server has no explicit path restriction"
    # AGENT-030 unpinned or unencrypted server source
    if command in ("npx", "node") or (args and args[0] == "npx"):
        for i, a in enumerate(args):
            if not isinstance(a, str) or a.startswith("-") or a == "npx":
                continue
            # same precedence as upstream: the length test picks which half of the condition applies
            if a.startswith("@") or ((not a.startswith("/") and not a.startswith(".") and "/" not in a[:20])
                                     if len(a) > 20 else "/" not in a):
                if not re.search(r"@\d+\.\d+", a) and OFFICIAL_SCOPE not in a:
                    yield "AGENT-030", "critical", "args[%d]" % i, "Unpinned package '%s' (rug-pull risk); pin @x.y.z" % a
                break
    if command == "uvx":
        for i, a in enumerate(args):
            if not isinstance(a, str) or a.startswith("-"):
                continue
            if not re.search(r"[=@]\d+\.\d+", a):
                yield "AGENT-030", "critical", "args[%d]" % i, "Unpinned uvx package '%s'; pin a version" % a
            break
    if url.startswith("http://"):
        yield "AGENT-030", "critical", "url", "Server URL uses unencrypted http://"
    # AGENT-031 secrets in env (values are never echoed) and blanket grants
    for k, v in env.items():
        if not isinstance(v, str) or k.upper() in SAFE_ENV or not SENSITIVE_ENV.search(k):
            continue
        if v and not (v.startswith("$") or (v.startswith("%") and v.endswith("%"))):
            if PLACEHOLDER.search(v):
                yield "AGENT-031", "medium", "env." + k, "Placeholder value for sensitive key '%s'" % k
            else:
                yield "AGENT-031", "high", "env." + k, "Hardcoded value for sensitive key '%s'; use ${%s}" % (k, k)
    sub = grants.get("config") if isinstance(grants.get("config"), dict) else {}
    cmds = sub.get("allowedCommands", [])
    if isinstance(cmds, list) and ("*" in cmds or "**" in cmds):
        yield "AGENT-031", "critical", "config.allowedCommands", "Wildcard '*' command permission allows any command"
    allow = grants.get("alwaysAllow", [])
    if allow is True or (isinstance(allow, list) and "*" in allow):
        yield "AGENT-031", "high", "alwaysAllow", "'alwaysAllow' grants every permission"
    # AGENT-032 stdio without sandbox
    if mode == "stdio":
        cmd, joined = command.lower(), " ".join(str(a) for a in args).lower()
        both = cmd + " " + joined
        if not any(s in both for s in SANDBOX) and OFFICIAL_SCOPE not in joined and (
                any(r in both for r in RISKY) or cmd in ("python", "python3")
                or (cmd == "node" and any(k in both for k in ("shell", "exec", "eval", "code", "repl")))):
            yield "AGENT-032", "medium", "command", "stdio server runs code without a sandbox; consider a container"
    # AGENT-033 remote transport without auth
    if mode in ("sse", "streamable-http") and not any(a in k.lower() for k in env for a in AUTH_ENV) \
            and not ("@" in url and "://" in url):
        yield "AGENT-033", "high", "headers", "Remote %s server has no auth configured" % mode


POISON = {cat: [(re.compile(p), d) for p, d in pats] for cat, pats in {
    "instruction_override": [
        (r"(?i)ignore\s+(previous|all|above|prior)\s+(instructions?|rules?|constraints?)", "instruction override"),
        (r"(?i)forget\s+(everything|all|previous)", "memory wipe directive"),
        (r"(?i)you\s+(?:must|should|need\s+to)\s+(?:always|never)", "behavioral override"),
        (r"(?i)override\s+(safety|security|policy|restrictions?)", "safety override"),
        (r"(?i)disregard\s+(all|any|previous)", "disregard directive")],
    "hidden_instruction": [
        ("[\u200b-\u200f\u2028-\u202f\u2060-\u206f]", "zero-width/invisible characters"),
        (r"<!--.*?-->", "HTML comment"), (r"\{%.*?%\}", "template injection"), (r"\$\{.*?\}", "variable interpolation")],
    "command_injection": [
        (r"(?i)(?:run|execute|eval|exec|system|shell)\s*\(", "function call in description"),
        (r"`[^`]+`", "backtick execution"), (r"\$\([^)]+\)", "subshell execution"),
        (r";\s*(?:rm|wget|curl|cat\s+/etc)", "command chaining")],
    "data_exfiltration": [
        (r"(?i)send\s+(?:all|the|user|private|secret)(?:\s+\w+)*\s+(?:data|info|keys?|tokens?)\s+to",
         "data send directive"),
        (r"(?i)(?:upload|post|transmit)\s+(?:to|at)\s+https?://", "upload to URL"),
        (r"(?i)include\s+(?:api|secret|private)\s*key", "key inclusion directive")],
    "privilege_escalation": [
        (r"(?i)grant\s+(?:admin|root|full)\s+(?:access|permission|privilege)", "privilege grant"),
        (r"(?i)(?:disable|bypass|skip)\s+(?:auth|authentication|authorization|verification)", "auth bypass"),
        (r"(?i)(?:sudo|as\s+root|with\s+admin)", "elevated execution")],
}.items()}


def poison(text):
    """First matching pattern per category, like agent-audit's ToolDescriptionAnalyzer."""
    if not text or not text.strip():
        return []
    hits = (next(("%s pattern: %s" % (cat, d) for rx, d in pats if rx.search(text)), None) for cat, pats in POISON.items())
    return [h for h in hits if h]


def tool_lists(doc):
    """(owner, tools) pairs: per-server tools, then top-level tools, then capabilities.tools."""
    sect, caps = doc.get("mcpServers", {}), doc.get("capabilities", {})
    out = [(n, c.get("tools", [])) for n, c in sect.items() if isinstance(c, dict)] if isinstance(sect, dict) else []
    return out + [("_global_", doc.get("tools", [])),
                  ("_capabilities_", caps.get("tools", []) if isinstance(caps, dict) else [])]


def agent_file_rules(doc):
    """Yield (rule, severity, server, field, title) for one file, in agent-audit's order."""
    servers = servers_for_agent(doc)
    if len(servers) > 10:
        yield "AGENT-042", "medium", "_global_", "mcpServers", \
            "%d servers configured (threshold 10): least privilege" % len(servers)
    for name, cfg in servers:
        for rule, sev, fld, title in agent_server_rules(str(name), cfg, cfg if "mcpServers" in doc else {}):
            yield rule, sev, str(name), fld, title
    lists = tool_lists(doc)
    for owner, tools in lists[-2:] + lists[:-2]:  # the schema check visits top-level lists first
        for t in tools if isinstance(tools, list) else []:
            if not isinstance(t, dict):
                continue
            tn, schema = t.get("name", "unknown"), t.get("inputSchema") or {}
            if schema.get("additionalProperties") is True:
                yield "AGENT-040", "medium", tn, "inputSchema", "additionalProperties: true lets callers inject parameters"
            props = schema.get("properties", {})
            for p, d in (props.items() if isinstance(props, dict) else ()):
                if isinstance(d, dict) and "type" not in d:
                    yield "AGENT-040", "low", tn, "inputSchema.properties." + p, "Parameter '%s' has no type" % p
            if not schema and t.get("description") and any(k in str(t["description"]).lower() for k in (
                    "query", "search", "execute", "run", "write", "create", "update", "delete")):
                yield "AGENT-040", "low", tn, "inputSchema", "Tool takes input but defines no inputSchema"
    for owner, tools in lists:
        for t in tools if isinstance(tools, list) else []:
            if not isinstance(t, dict):
                continue
            tn = t.get("name", "unknown")
            for hit in poison(tn) + poison(t.get("description", "")):
                yield "AGENT-056", "high", owner, "tools." + str(tn), "Tool '%s' metadata has %s" % (tn, hit)
            schema = t.get("inputSchema", {})
            for p, d in (schema.get("properties", {}).items() if isinstance(schema, dict) else ()):
                for hit in poison(d.get("description", "")) if isinstance(d, dict) else ():
                    yield "AGENT-057", "high", owner, "tools.%s.%s" % (tn, p), "Argument '%s' of '%s' has %s" % (p, tn, hit)


def shadowing(entries):
    """AGENT-055 across all files: one tool name served by two servers, or two near-identical names."""
    registry, owners = {}, set()
    for e in entries:
        if not e.get("agent"):
            continue
        sect, top = e["doc"].get("mcpServers", {}), e["doc"].get("tools")
        pairs = [(n, c["tools"]) for n, c in sect.items() if isinstance(c, dict) and isinstance(c.get("tools"), list)
                 and c["tools"]] if isinstance(sect, dict) else []
        pairs += [("_config_" + e["path"], top)] if isinstance(top, list) and top else []
        for owner, tools in pairs:
            owners.add(owner)
            for t in tools:
                registry.setdefault(t.get("name", "").lower().strip(), {})[owner] = 1
    if len(owners) < 2:
        return
    for tool, srv in registry.items():
        if len(srv) > 1:
            yield "AGENT-055", "high", next(iter(srv)), "tools." + tool, \
                "Tool '%s' is registered by %s" % (tool, ", ".join(srv))
    names = list(registry)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if len(a) > 5 and len(b) > 5 and set(registry[a]) != set(registry[b]) and distance(a, b) <= 2:
                yield "AGENT-055", "medium", next(iter(registry[a])), "tools." + a, \
                    "Tools '%s' and '%s' look alike across servers" % (a, b)

# ---------------------------------------------------------------- text rules
TEXT_RULES = [(i, s, re.compile(p, re.I), t) for i, s, p, t in [
    ("en.override", "high", r"ignore\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|messages?)", "Instruction-override wording"),
    ("en.hide_from_user", "high", r"do\s+not\s+(?:tell|inform|notify|reveal|disclose|mention)[^.\n]{0,40}user", "Ask to hide behaviour from the user"),
    ("en.role_change", "medium", r"(?:you\s+are\s+now|new\s+instructions?\s*:|system\s+prompt|act\s+as\s+(?:if|an?))", "Role / prompt redefinition"),
    ("en.exfiltrate", "high", r"(?:send|upload|post|forward|leak)[^.\n]{0,32}(?:api[_ -]?key|token|password|credential|secret)", "Instruction to move credentials"),
    ("en.bypass", "high", r"(?:bypass|disable|turn\s+off)[^.\n]{0,16}(?:approval|confirmation|safety|guardrail|logging|filter|sandbox)", "Safety-control bypass wording"),
    ("en.silent", "high", r"(?:silently|covertly)\s+(?:execute|run|call|send|read)|without\s+(?:asking|informing|notifying)\s+the\s+user", "Silent execution wording"),
    ("en.prepend_call", "low", r"(?:before|prior\s+to)\s+(?:any|answering|responding|other)[^.\n]{0,32}(?:first\s+(?:call|run|read|execute)|call\s+the)", "Mandatory pre-call instruction"),
    ("en.internal_note", "medium", r"this\s+(?:message|note|instruction|section)\s+is\s+(?:hidden|internal|not\s+for\s+the\s+user)", "Hidden-instruction marker"),
    ("zh.override", "high", "\u5ffd\u7565(?:\u6389)?(?:\u4e4b\u524d|\u4ee5\u4e0a|\u4e0a\u8ff0|\u5148\u524d|\u524d\u9762|\u6240\u6709|\u5168\u90e8|\u4efb\u4f55)(?:\u7684)?(?:\u4e4b\u524d|\u4ee5\u4e0a|\u4e0a\u8ff0|\u5148\u524d|\u524d\u9762|\u6240\u6709|\u5168\u90e8|\u4efb\u4f55|\u65e2\u6709|\u5df2\u6709)?(?:\u6307\u4ee4|\u63d0\u793a|\u89c4\u5219|\u8bf4\u660e|\u8bbe\u5b9a|\u8981\u6c42|\u7ea6\u675f)", "Instruction-override wording (Chinese)"),
    ("zh.hide_from_user", "high", "(?:\u4e0d\u8981|\u52ff|\u522b)(?:\u5411|\u5bf9|\u8ddf)?(?:\u7528\u6237|\u4f7f\u7528\u8005|\u5ba2\u6237)?(?:\u900f\u9732|\u544a\u77e5|\u901a\u77e5|\u63d0\u53ca|\u8bf4\u660e|\u66b4\u9732)|(?:\u5bf9|\u5411)(?:\u7528\u6237|\u5ba2\u6237)?(?:\u4fdd\u5bc6|\u9690\u7792)", "Ask to hide behaviour from the user (Chinese)"),
    ("zh.exfiltrate", "high", "(?:\u53d1\u9001|\u4e0a\u4f20|\u63d0\u4ea4|\u56de\u4f20|\u5916\u4f20|\u8f6c\u53d1|POST)[^\u3002\\n]{0,16}(?:\u5bc6\u94a5|\u4ee4\u724c|\u53e3\u4ee4|\u51ed\u636e|\u79c1\u94a5|\u5bc6\u7801|api[_ -]?key|token)", "Instruction to move credentials (Chinese)"),
    ("zh.read_sensitive", "medium", "(?:\u8bfb\u53d6|\u6253\u5f00|\u5217\u51fa|\u904d\u5386|\u4e0a\u4f20)[^\u3002\\n]{0,16}(?:id_rsa|\\.ssh|\\.aws|\\.config|\u51ed\u636e|\u5bc6\u94a5|\u94b1\u5305)", "Points at sensitive paths or credentials (Chinese)"),
    ("zh.role_change", "medium", "(?:\u4f60\u73b0\u5728\u662f|\u4ece\u73b0\u5728\u8d77\u4f60(?:\u662f|\u5c06)|\u5047\u88c5(?:\u4f60)?\u662f|\u626e\u6f14(?:\u4e00\u4e2a)?(?:\u65e0\u9650\u5236|\u8d8a\u6743|\u7ba1\u7406\u5458|root))", "Role / prompt redefinition (Chinese)"),
    ("zh.bypass", "high", "(?:\u7ed5\u8fc7|\u8df3\u8fc7|\u5ffd\u7565)[^\u3002\\n]{0,8}(?:\u5ba1\u6279|\u786e\u8ba4|\u6821\u9a8c|\u9a8c\u8bc1|\u5b89\u5168\u68c0\u67e5|\u6743\u9650|\u9650\u5236|\u6c99\u7bb1)", "Safety-control bypass wording (Chinese)"),
    ("zh.silent", "high", "(?:\u9759\u9ed8|\u6084\u6084|\u6697\u4e2d)(?:\u6267\u884c|\u8fd0\u884c|\u8c03\u7528|\u53d1\u9001|\u8bfb\u53d6)|\u4e0d(?:\u8be2\u95ee|\u901a\u77e5|\u63d0\u9192|\u544a\u77e5)\u7528\u6237(?:\u76f4\u63a5|\u5c31)(?:\u6267\u884c|\u8fd0\u884c|\u8c03\u7528)", "Silent execution wording (Chinese)"),
    ("zh.invalidate_prev", "medium", "(?:\u4ee5\u4e0a|\u4e4b\u524d|\u4e0a\u8ff0)(?:\u7684)?(?:\u5185\u5bb9|\u6307\u4ee4|\u5bf9\u8bdd|\u89c4\u5219)(?:\u5168\u90e8|\u90fd)?(?:\u65e0\u6548|\u4f5c\u5e9f|\u4e0d\u9002\u7528)", "Declares earlier context void (Chinese)"),
    ("zh.mandatory_call", "low", "(?:\u52a1\u5fc5|\u5fc5\u987b)(?:\u5148)?(?:\u8c03\u7528|\u6267\u884c|\u8fd0\u884c)[^\u3002\\n]{0,24}(?:\u4e4b\u524d|\u524d|\u9996\u5148)", "Mandatory pre-call instruction (Chinese)"),
    ("st.zero_width", "high", "[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]", "Invisible control characters"),
    ("st.long_base64", "medium", r"[A-Za-z0-9+/]{80,}={0,2}", "Very long base64-like string"),
    ("st.pipe_to_shell", "high", r"[|]\s*(?:ba)?sh\b", "Pipe into a shell"),
    ("st.dynamic_exec", "high", r"\b(?:eval|exec|execFile|spawn|system|vm\.runInNewContext|child_process|subprocess|os\.system|__import__)\s*\(", "Dynamic execution entry point"),
    ("st.powershell_encoded", "high", r"(?:-enc\b|-encodedcommand|powershell[^\n]{0,24}\s-c\b)", "PowerShell encoded or inline command"),
    ("st.base64_decode", "medium", r"(?:base64\s+(?:-d|--decode)|atob\s*\(|Buffer\.from\s*\([^)]{0,40}base64)", "Decode step before execution"),
    ("st.wildcard_bind", "medium", r"(?:0\.0\.0\.0|\[::\])(?::\d+)?", "Listens on every network interface"),
    ("st.root_path", "medium", r"^/$|^[A-Za-z]:\\$", "Filesystem access at the drive root"),
    ("st.home_dir", "medium", r"^/home/[^/]+$|^[A-Za-z]:\\Users\\[^\\]+$|^/Users/[^/]+$", "Filesystem access to the whole home folder"),
    ("st.dotenv", "medium", r"\.env\b", "Points at a .env credentials file"),
    ("st.exfil_endpoint", "medium", r"(?:pastebin\.com|transfer\.sh|webhook\.site|discord\.com/api/webhooks|requestbin|\bngrok\.)", "Common exfiltration / temporary receiver endpoint"),
]]
SECRETISH = re.compile(r"(token|secret|password|passwd|apikey|api_key|api-key|credential|access_key|auth)", re.I)
NON_TEXT_KEYS = {"command", "args", "url", "uri", "type", "transport", "env", "headers", "disabled", "enabled",
                 "cwd", "name", "timeout"}
OFFICIAL = ("filesystem fetch memory time git github gitlab slack google-drive google-maps sqlite postgres everything "
            "pdf redshift puppeteer playwright brave-search sequentialthinking aws-kb-retrieval").split()
OFFICIAL = ["@modelcontextprotocol/server-" + p for p in OFFICIAL]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def excerpt(text, start, end, width=96):
    lo, hi = max(0, start - width // 2), min(len(text), end + width // 2)
    shown = "".join(c if unicodedata.category(c)[0] != "C" else "\\u%04x" % ord(c) for c in text[lo:hi])
    return ("\u2026" if lo else "") + shown + ("\u2026" if hi < len(text) else "")


def distance(a, b, cap=2):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def text_rules(name, cfg):
    """Yield (rule, severity, field, title, excerpt) for one server entry."""
    url = str(cfg.get("url") or cfg.get("uri") or "")
    args = [str(a) for a in (cfg.get("args") or [])]
    command = str(cfg.get("command") or "")
    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
    headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
    declared = str(cfg.get("type") or cfg.get("transport") or "").lower()
    remote = declared in {"http", "https", "sse", "streamable-http", "streamable_http"} or bool(url)
    out = []
    for k, v in env.items():
        if SECRETISH.search(str(k)) and str(v).strip():
            out.append(("st.secret_in_config", "high", "env.%s" % k, "Credential written inline in the config", ""))
    local = any(h in url for h in ("localhost", "127.0.0.1", "::1"))
    if remote and not headers and not local:
        out.append(("st.remote_no_auth", "medium", "headers", "Remote server declares no auth header", ""))
    if remote and url.lower().startswith("http://") and not local:
        out.append(("st.plaintext_http", "high", "url", "Remote server over plaintext http", url))
    for cand in [name] + [a for a in args if "/" in a or "@" in a]:
        low = cand.strip().lower()
        if len(low) < 6 or low in OFFICIAL:
            continue
        near = next((k for k in OFFICIAL if distance(low, k.lower()) <= 2), None)
        if near:
            out.append(("st.typosquat", "high", "name/args", "Package name is a near miss of official '%s'" % near, cand))
        elif low.startswith("@modelcontextprotocol/"):
            out.append(("st.unknown_official_scope", "medium", "name/args",
                        "Uses the official @modelcontextprotocol scope but is not a known official package", cand))
    texts = sorted((str(k), v) for k, v in cfg.items()
                   if isinstance(v, str) and k not in NON_TEXT_KEYS and not SECRETISH.search(str(k)))
    pairs = ([("command", command)] if command else []) + [("args[%d]" % i, a) for i, a in enumerate(args)] \
        + ([("url", url)] if url else []) + texts
    for rid, sev, rx, title in TEXT_RULES:
        for fld, text in pairs:
            m = rx.search(text)
            if m:
                out.append((rid, sev, fld, title, excerpt(text, m.start(), m.end())))
    out.sort(key=lambda f: (SEV_RANK[f[1]], f[0]))
    return out


# ---------------------------------------------------------------- report
TWINS = {"st.secret_in_config": "AGENT-031", "st.plaintext_http": "AGENT-030", "st.remote_no_auth": "AGENT-033",
         "st.root_path": "AGENT-029", "st.home_dir": "AGENT-029"}


def scan_file(client, path):
    entry = {"client": client, "path": path, "servers": 0, "findings": []}
    try:
        doc = load(path)
    except (OSError, ValueError) as e:
        entry["error"] = str(e)
        return entry
    # agent-audit reads only .json/.yaml files and skips OpenAPI specs
    agent_ok = path.lower().endswith((".json", ".yaml", ".yml")) and not is_openapi(doc)
    entry["doc"], entry["agent"] = doc, agent_ok
    txt = servers_for_text(doc)
    entry["servers"] = len({str(n) for n, _ in servers_for_agent(doc)} | set(txt))
    found = [{"rule": r, "severity": s, "server": n, "field": fld, "title": t}
             for r, s, n, fld, t in (agent_file_rules(doc) if agent_ok else ())]
    for name, cfg in txt.items():
        for r, s, fld, t, ex in text_rules(name, cfg):
            twin = next((f for f in found if f["rule"] == TWINS.get(r) and f["server"] == name
                         and f["field"] == fld and r not in f.get("also", [])), None)
            if twin:
                twin.setdefault("also", []).append(r)
                continue
            found.append({"rule": r, "severity": s, "server": name, "field": fld, "title": t, "excerpt": ex})
    entry["findings"] = found
    return entry


def rule_ids(f):
    return [f["rule"]] + f.get("also", [])


TEXT_SEV = {r[0]: r[1] for r in TEXT_RULES}
TEXT_SEV.update({"st.secret_in_config": "high", "st.remote_no_auth": "medium", "st.plaintext_http": "high",
                 "st.typosquat": "high", "st.unknown_official_scope": "medium"})


def summarize(files):
    findings = [f for e in files for f in e["findings"]]
    risk = sum(RISK_WEIGHT[TEXT_SEV[r]] for f in findings for r in rule_ids(f) if not r.startswith("AGENT-"))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES[:4]}
    return {"risk": risk, "counts": counts}


def print_text(files, summary):
    print("mcpcheck - %d config files, %d servers (offline, read-only)" % (len(files), sum(e["servers"] for e in files)))
    c = summary["counts"]
    print("risk %d - %d critical, %d high, %d medium, %d low\n"
          % (summary["risk"], c["critical"], c["high"], c["medium"], c["low"]))
    for e in files:
        print("  %s  %s" % (e["client"], e["path"]))
        if "error" in e:
            print("    !! " + e["error"])
        for f in sorted(e["findings"], key=lambda f: (f["server"], SEV_RANK[f["severity"]])):
            print("    %-8s %-22s %-32s %s" % (f["severity"].upper(), f["server"][:22], " + ".join(rule_ids(f)),
                                             f["title"]))
            if f.get("excerpt"):
                print("             " + f["excerpt"])
        if not e["findings"] and "error" not in e:
            print("    ok")
        print()
    print("env and header values are never printed - key names only.")


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description="Offline security audit of MCP client configs.")
    ap.add_argument("configs", nargs="*", help="config files (default: every known client config)")
    ap.add_argument("--project", help="also check project-level files (.mcp.json, .cursor/mcp.json, ...) in DIR")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--fail-on", choices=SEVERITIES[:4], help="exit 1 when a finding this severe or worse exists")
    args = ap.parse_args(argv)
    targets = discover(args.configs, args.project)
    if not targets:
        print("No MCP config found. Pass a file, or --project DIR.")
        return 2
    files = [scan_file(c, p) for c, p in targets]
    first = next((e for e in files if e.get("agent")), None)
    if first:  # like agent-audit, cross-file shadowing is reported on the first parsed file
        first["findings"] += [{"rule": r, "severity": s, "server": n, "field": fld, "title": t}
                              for r, s, n, fld, t in shadowing(files)]
    for e in files:
        e.pop("doc", None)
        e.pop("agent", None)
    summary = summarize(files)
    if args.json:
        print(json.dumps({"summary": summary, "files": files}, indent=2, ensure_ascii=False))
    else:
        print_text(files, summary)
    if any("error" in e for e in files):
        return 2
    if args.fail_on and any(SEV_RANK[f["severity"]] <= SEV_RANK[args.fail_on] for e in files for f in e["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
