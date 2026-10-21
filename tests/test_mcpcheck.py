"""mcpcheck must find what both upstream auditors find, fixture by fixture."""
import collections
import functools
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join("tests", "fixtures")
with open(os.path.join(ROOT, "tests", "upstream.json"), encoding="utf-8") as f:
    UPSTREAM = json.load(f)


def run(*args):
    p = subprocess.run([sys.executable, "mcpcheck.py", *args], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8")
    return p.returncode, p.stdout


@functools.lru_cache(maxsize=None)
def scan(name):
    code, out = run(os.path.join(FIX, name), "--json")
    return code, json.loads(out)


def shadow_free(rows):
    # agent-audit picks the AGENT-055 server from a set, so its name is not stable across runs
    return [r[:2] if r[0] == "AGENT-055" else r[:3] for r in rows]


class MatchesUpstream(unittest.TestCase):
    def test_agent_rules_match_agent_audit(self):
        for name, up in UPSTREAM.items():
            _, rep = scan(name)
            mine = [[f["rule"], f["severity"], f["server"]]
                    for f in rep["files"][0]["findings"] if f["rule"].startswith("AGENT-")]
            self.assertEqual(shadow_free(mine), shadow_free(up["agent"]["findings"]), name)

    def test_text_rules_match_mcp_checkup(self):
        for name, up in UPSTREAM.items():
            if up["checkup"]["error"]:
                continue
            _, rep = scan(name)
            mine = collections.Counter((r, f["server"]) for f in rep["files"][0]["findings"]
                                       for r in [f["rule"]] + f.get("also", []) if not r.startswith("AGENT-"))
            want = collections.Counter((r, s) for r, _, s, _, _ in up["checkup"]["findings"])
            self.assertEqual(mine, want, name)
            self.assertEqual(rep["summary"]["risk"], up["checkup"]["risk"], name)

    def test_unfolded_text_findings_keep_field_and_excerpt(self):
        _, rep = scan("mixed.json")
        got = {(f["rule"], f["server"], f["field"], f["excerpt"]) for f in rep["files"][0]["findings"] if "excerpt" in f}
        want = {(r, s, fld, ex) for r, _, s, fld, ex in UPSTREAM["mixed.json"]["checkup"]["findings"]}
        self.assertTrue(got <= want and got, got - want)

    def test_twin_findings_fold_into_one_line(self):
        _, rep = scan("aa-vulnerable-config.json")
        key = [f for f in rep["files"][0]["findings"] if f["field"] == "env.API_KEY"]
        self.assertEqual([(f["rule"], f.get("also")) for f in key], [("AGENT-031", ["st.secret_in_config"])])

    def test_shadowing_across_two_files(self):
        _, out = run(os.path.join(FIX, "aa-rule-056.json"), os.path.join(FIX, "aa-rule-057.json"), "--json")
        rules = [f["rule"] for e in json.loads(out)["files"] for f in e["findings"]]
        self.assertNotIn("AGENT-055", rules)  # different tool names: no shadowing
        _, out = run(os.path.join(FIX, "aa-rule-055.json"), "--json")
        self.assertIn("AGENT-055", [f["rule"] for f in json.loads(out)["files"][0]["findings"]])

    def test_grants_only_checked_under_mcpServers(self):
        # agent-audit reads alwaysAllow/allowedCommands only from mcpServers entries
        entry = {"command": "node", "args": ["./s.js"], "alwaysAllow": ["*"], "config": {"allowedCommands": ["*"]}}
        with tempfile.TemporaryDirectory() as tmp:
            for key, want in (("mcpServers", 2), ("servers", 0)):
                path = os.path.join(tmp, key + ".json")
                with open(path, "w") as f:
                    json.dump({key: {"x": entry}}, f)
                _, out = run(path, "--json")
                got = [f for f in json.loads(out)["files"][0]["findings"] if f["rule"] == "AGENT-031"]
                self.assertEqual(len(got), want, key)

    def test_broken_json_is_reported_not_crashed(self):
        code, rep = scan("broken.json")
        self.assertEqual(code, 2)
        self.assertIn("invalid JSON", rep["files"][0]["error"])

    def test_fail_on_gate(self):
        self.assertEqual(run(os.path.join(FIX, "zed.json"), "--fail-on", "high")[0], 0)
        self.assertEqual(run(os.path.join(FIX, "aa-vulnerable-demo.json"), "--fail-on", "critical")[0], 1)

    def test_secret_values_never_printed(self):
        for name, secrets in (("mixed.json", ("hunter2hunter2", "AKIAABCDEFGHIJKLMNOP")),
                              ("aa-vulnerable-config.json", ("sk-1234", "super_secret_password_123"))):
            _, out = run(os.path.join(FIX, name))
            for secret in secrets:
                self.assertNotIn(secret, out)


if __name__ == "__main__":
    unittest.main()
