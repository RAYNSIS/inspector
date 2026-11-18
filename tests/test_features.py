"""Rule patches, only_added, only_removed, compaction-aware turns, check/rules commands, packaging consistency."""
from __future__ import annotations

import io
import json
import os
import re
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from raynsis_inspector import __version__, audit, cli, engine, transcript  # noqa: E402
from tests.test_engine import Base, _dump, _write_transcript, human, say, tool_result, tool_use  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def compact_summary(text="Summary of earlier work."):
    return {"type": "user", "isCompactSummary": True,
            "message": {"role": "user", "content": transcript.COMPACT_PREFIX + " that ran out of context.\n\n" + text}}


class Patching(Base):
    def core(self, rid):
        rules, errors = engine.load_rules([cli.CORE_RULES])
        self.assertEqual(errors, [])
        return {r["id"]: r for r in rules}[rid]

    def test_partial_rule_changes_one_field_and_keeps_the_rest(self):
        p = os.path.join(self.tmp.name, "p.json")
        _dump({"rules": [{"id": "tool.no-force-push", "action": "warn"}]}, p)
        rules, errors = engine.load_rules([cli.CORE_RULES, p])
        self.assertEqual(errors, [])
        r = {x["id"]: x for x in rules}["tool.no-force-push"]
        self.assertEqual(r["action"], "warn")
        self.assertEqual(r["pattern"], self.core("tool.no-force-push")["pattern"])

    def test_plus_key_adds_a_project_test_command(self):
        # shadow-mode false alarm 18.11: a project gate script ran the tests but was not recognised
        p = os.path.join(self.tmp.name, "p.json")
        _dump({"rules": [{"id": "reply.tests-pass-needs-run", "needs_turn+": "panel_gates\\.sh"}]}, p)
        rules, errors = engine.load_rules([cli.CORE_RULES, p])
        self.assertEqual(errors, [])
        r = {x["id"]: x for x in rules}["reply.tests-pass-needs-run"]
        quiet = engine.reply_hits([r], "77/77 tests passed.", ["Bash: {\"command\": \"./panel_gates.sh --wait\"}"])
        self.assertEqual(quiet, [])
        self.assertTrue(engine.reply_hits([r], "77/77 tests passed.", ["Edit: {\"file_path\": \"a.py\"}"]))
        self.assertTrue(engine.reply_hits([r], "All tests pass.", []), "default test commands still required")

    def test_joined_regex_scopes_each_side_flags(self):
        joined = engine.join_regex("(?i)pytest", "(?s)make\\s+verify")
        self.assertTrue(re.search(joined, "PYTEST -q"))
        self.assertTrue(re.search(joined, "make verify"))
        self.assertFalse(re.search(joined, "MAKE VERIFY"), "the base's (?i) must not leak into the extension")

    def test_verbose_flag_in_an_extension_cannot_disarm_the_core_pattern(self):
        # security review 18.11: "(?x)" on the extension used to turn the whole joined pattern verbose,
        # which silently broke the private-key branch of tool.no-secret-in-command
        p = os.path.join(self.tmp.name, "p.json")
        _dump({"rules": [{"id": "tool.no-secret-in-command", "pattern+": "(?x) my_token"}]}, p)
        rules, errors = engine.load_rules([cli.CORE_RULES, p])
        self.assertEqual(errors, [])
        r = [x for x in rules if x["id"] == "tool.no-secret-in-command"]
        key = "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIE"
        self.assertTrue(engine.tool_hits(r, "Write", {"file_path": "k.pem", "content": key}))

    def test_bad_patch_values_are_errors_not_crashes(self):
        p = os.path.join(self.tmp.name, "p.json")
        _dump({"rules": [{"id": "tool.no-force-push", "pattern+": 5}], "disable": 5}, p)
        rules, errors = engine.load_rules([cli.CORE_RULES, p])
        self.assertEqual(len(errors), 2)
        self.assertIn("tool.no-force-push", [r["id"] for r in rules], "core rules keep enforcing")

    def test_null_removes_a_field(self):
        p = os.path.join(self.tmp.name, "p.json")
        _dump({"rules": [{"id": "reply.done-needs-action", "unless": None}]}, p)
        rules, _ = engine.load_rules([cli.CORE_RULES, p])
        r = {x["id"]: x for x in rules}["reply.done-needs-action"]
        self.assertNotIn("unless", r)
        self.assertTrue(engine.reply_hits([r], "I fixed that earlier, in the previous turn.", []))

    def test_invalid_patch_is_reported_and_the_core_rule_survives(self):
        p = os.path.join(self.tmp.name, "p.json")
        _dump({"rules": [{"id": "tool.no-force-push", "pattern": "("}]}, p)
        rules, errors = engine.load_rules([cli.CORE_RULES, p])
        self.assertEqual(len(errors), 1)
        r = {x["id"]: x for x in rules}["tool.no-force-push"]
        self.assertEqual(r["pattern"], self.core("tool.no-force-push")["pattern"])

    def test_wrong_types_are_rejected_not_crashing(self):
        bad = [{"id": "a", "event": "tool", "action": "deny", "message": "m", "pattern": 5},
               {"id": "b", "event": "tool", "action": "deny", "message": "m", "pattern": "x", "tools": [1]},
               {"id": "c", "event": "tool", "action": "deny", "message": "m", "pattern": "x", "only_added": "yes"},
               {"id": ["d"], "event": "tool", "action": "deny", "message": "m", "pattern": "x"}]
        for rule in bad:
            self.assertTrue(engine.validate(rule), rule)
        p = os.path.join(self.tmp.name, "p.json")
        _dump({"rules": "not a list"}, p)
        rules, errors = engine.load_rules([p])
        self.assertEqual((rules, len(errors)), ([], 1))

    def test_tools_as_a_single_string_is_one_tool_not_a_substring(self):
        r = {"id": "x", "event": "tool", "action": "deny", "message": "m", "pattern": "a", "tools": "MultiEdit"}
        self.assertFalse(engine.applies(r, "tool", "Edit"))
        self.assertTrue(engine.applies(r, "tool", "MultiEdit"))


class OnlyAdded(Base):
    def rule(self):
        rules, _ = engine.load_rules([cli.CORE_RULES])
        return [r for r in rules if r["id"] == "tool.no-test-skip"]

    def test_multiedit_edits_are_compared(self):
        inp = {"file_path": "t.py", "edits": [{"old_string": "def test_a():", "new_string": "@pytest.mark.skip\ndef test_a():"}]}
        self.assertTrue(engine.tool_hits(self.rule(), "MultiEdit", inp))

    def test_write_over_an_existing_test_file_through_the_hook(self):
        path = os.path.join(self.tmp.name, "test_x.py")
        with open(path, "w") as f:
            f.write("def test_x():\n    assert run()\n")
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Write", "cwd": self.tmp.name,
                             "tool_input": {"file_path": path, "content": "@pytest.mark.skip\ndef test_x():\n    assert run()\n"}})
        self.assertIn("tool.no-test-skip", out["systemMessage"])
        self.assertNotIn("hookSpecificOutput", out, "warn rules never block")

    def test_write_of_a_new_file_is_not_weakening(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Write", "cwd": self.tmp.name,
                             "tool_input": {"file_path": os.path.join(self.tmp.name, "test_new.py"),
                                            "content": "@pytest.mark.skip\ndef test_new(): ..."}})
        self.assertIsNone(out)

    def test_prior_is_not_read_for_huge_files(self):
        path = os.path.join(self.tmp.name, "big.py")
        with open(path, "w") as f:
            f.write("x" * (cli.PRIOR_MAX_BYTES + 1))
        self.assertNotIn("_prior", cli.with_prior({"file_path": path, "content": "y"}))
        self.assertNotIn("_prior", cli.with_prior({"file_path": "/nonexistent/f.py", "content": "y"}))
        self.assertNotIn("_prior", cli.with_prior({"file_path": path}))


class OnlyRemoved(Base):
    def rule(self, rid="tool.no-test-function-delete"):
        rules, _ = engine.load_rules([cli.CORE_RULES])
        return [r for r in rules if r["id"] == rid]

    def test_multiedit_that_drops_a_test_is_caught(self):
        inp = {"file_path": "t.py", "edits": [{"old_string": "def test_a():\n    assert a()\n", "new_string": ""},
                                              {"old_string": "x = 1", "new_string": "x = 2"}]}
        self.assertTrue(engine.tool_hits(self.rule(), "MultiEdit", inp))

    def test_moving_a_test_inside_one_multiedit_is_not_a_removal(self):
        inp = {"file_path": "t.py", "edits": [{"old_string": "def test_a():\n    assert a()\n", "new_string": ""},
                                              {"old_string": "# end", "new_string": "def test_a():\n    assert a()\n# end"}]}
        self.assertFalse(engine.tool_hits(self.rule(), "MultiEdit", inp))

    def test_write_that_drops_a_test_through_the_hook(self):
        path = os.path.join(self.tmp.name, "test_x.py")
        with open(path, "w") as f:
            f.write("def test_x():\n    assert run()\n\ndef test_y():\n    assert other()\n")
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Write", "cwd": self.tmp.name,
                             "tool_input": {"file_path": path, "content": "def test_y():\n    assert other()\n"}})
        self.assertIn("tool.no-test-function-delete", out["systemMessage"])
        self.assertNotIn("hookSpecificOutput", out, "warn rules never block")

    def test_write_of_a_new_file_removes_nothing(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Write", "cwd": self.tmp.name,
                             "tool_input": {"file_path": os.path.join(self.tmp.name, "test_new.py"),
                                            "content": "def test_new():\n    assert new()\n"}})
        self.assertIsNone(out)

    def test_flag_types_and_conflict_are_rejected(self):
        base = {"id": "r", "event": "tool", "action": "warn", "message": "m", "pattern": "x"}
        self.assertTrue(engine.validate(dict(base, only_removed="yes")))
        self.assertTrue(engine.validate(dict(base, only_added=True, only_removed=True)))
        self.assertFalse(engine.validate(dict(base, only_removed=True)))

    def test_deleting_a_test_file_from_the_shell_warns_without_blocking(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "cwd": self.tmp.name,
                             "tool_input": {"command": "rm tests/test_api.py && pytest"}})
        self.assertIn("tool.no-test-file-delete", out["systemMessage"])
        self.assertNotIn("hookSpecificOutput", out, "warn rules never block")


class Compaction(Base):
    def stop(self, entries, reply=None, extra=None):
        tp = os.path.join(self.tmp.name, "t.jsonl")
        _write_transcript(tp, entries)
        payload = {"hook_event_name": "Stop", "session_id": "s", "transcript_path": tp, "cwd": self.tmp.name}
        if reply is not None:
            payload["last_assistant_message"] = reply
        payload.update(extra or {})
        return self.hook(payload)

    def test_claim_right_after_compaction_is_not_judged(self):
        # replay 18.11: 5 of 5 Turkish "fixed" hits were the first reply after a compaction
        rc, out = self.stop([compact_summary(), say("All tests pass and the bug has been fixed.")])
        self.assertIsNone(out)
        ev = audit.read_jsonl("evals.jsonl")[-1]
        self.assertNotIn("reply.tests-pass-needs-run", ev["evaluated"])
        self.assertIn("reply.unopened-link", ev["evaluated"])

    def test_link_from_the_summary_counts_as_seen_but_invented_links_do_not(self):
        rc, out = self.stop([compact_summary("We read https://docs.tool.dev/a earlier."),
                             say("See https://docs.tool.dev/a")])
        self.assertIsNone(out)
        rc, out = self.stop([compact_summary(), say("See https://docs.tool.dev/never")])
        self.assertIn("reply.unopened-link", out["reason"])

    def test_new_human_message_after_compaction_starts_a_judged_turn(self):
        rc, out = self.stop([compact_summary(), human("are we done?"), say("All tests pass.")])
        self.assertEqual(out["decision"], "block")

    def test_subagent_reply_is_judged_on_its_own_transcript(self):
        sub = os.path.join(self.tmp.name, "agent.jsonl")
        _write_transcript(sub, [human("run the tests"), tool_use("Bash", {"command": "pytest"}), tool_result("5 passed")])
        rc, out = self.stop([human("delegate it"), say("waiting")], reply="All tests pass.",
                            extra={"hook_event_name": "SubagentStop", "agent_transcript_path": sub})
        self.assertIsNone(out)


class Commands(Base):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(list(argv))
        return rc, buf.getvalue()

    def test_check_exit_codes(self):
        self.assertEqual(self.run_cli("check", "bash", "rm -rf ~")[0], 1)
        self.assertEqual(self.run_cli("check", "bash", "ls -la")[0], 0)
        rc, out = self.run_cli("check", "reply", "All tests pass.", "--turn", "Bash: pytest -q")
        self.assertEqual(rc, 0)
        self.assertIn("pass: no rule fired", out)
        rc, out = self.run_cli("check", "tool", "Edit", "--input", '{"file_path": "x/.claude/settings.json"}')
        self.assertEqual(rc, 1)
        self.assertIn("tool.guardrails-read-only", out)

    def test_warn_hit_prints_but_does_not_fail(self):
        rc, out = self.run_cli("check", "tool", "Edit", "--input",
                               json.dumps({"file_path": "t.py", "old_string": "def t():", "new_string": "@pytest.mark.skip\ndef t():"}))
        self.assertEqual(rc, 0)
        self.assertIn("WARN tool.no-test-skip", out)

    def test_version_flag(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()) as buf:
                cli.main(["--version"])
        self.assertIn(__version__, buf.getvalue())

    def test_gitignore_written_with_the_first_log(self):
        audit.log_eval("s", "tool", [], [])
        with open(os.path.join(audit.home(), ".gitignore")) as f:
            body = f.read()
        self.assertIn("*.jsonl", body)
        self.assertNotIn("rules.json", body.split("\n", 1)[1], "project rules stay committable")


class NarrowCodePage(Base):
    """Windows pipes default to cp1252: a Turkish message must not crash the hook into failing open."""

    def test_turkish_block_survives_cp1252_stdin_and_stdout(self):
        tp = os.path.join(self.tmp.name, "t.jsonl")
        _write_transcript(tp, [human("düzelt"), say("Düzelttim, tüm testler geçti. Á")])
        raw = json.dumps({"hook_event_name": "Stop", "session_id": "s", "transcript_path": tp, "cwd": self.tmp.name},
                         ensure_ascii=False).encode("utf-8")
        stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="cp1252")
        out_bytes = io.BytesIO()
        stdout = io.TextIOWrapper(out_bytes, encoding="cp1252", errors="strict")
        with redirect_stdout(stdout):
            rc = cli.hook(stdin)
        stdout.flush()
        out = json.loads(out_bytes.getvalue().decode("ascii"))
        self.assertEqual(rc, 0)
        self.assertEqual(out["decision"], "block")
        self.assertIn("Testlerin geçtiğini", out["reason"])
        self.assertEqual([r for r in audit.read_jsonl("audit.jsonl") if r.get("event") == "engine_error"], [])

    def test_payload_that_is_not_an_object_fails_loud(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.hook(io.StringIO("[1, 2]"))
        self.assertIn("ENGINE ERROR", buf.getvalue())


class Packaging(unittest.TestCase):
    def read_json(self, *parts):
        with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
            return json.load(f)

    def test_one_version_everywhere(self):
        plugin = self.read_json(".claude-plugin", "plugin.json")
        market = self.read_json(".claude-plugin", "marketplace.json")
        self.assertEqual(plugin["version"], __version__)
        self.assertEqual([p["version"] for p in market["plugins"] if p["name"] == plugin["name"]], [__version__])
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            self.assertIn("## %s" % __version__, f.read())

    def test_hooks_call_the_bundled_launcher(self):
        hooks = self.read_json("hooks", "hooks.json")["hooks"]
        for event in ("PreToolUse", "Stop", "SubagentStop"):
            cmds = [h["command"] for group in hooks[event] for h in group["hooks"]]
            self.assertTrue(all("${CLAUDE_PLUGIN_ROOT}/bin/raynsis-inspector" in c and c.endswith(" hook") for c in cmds), cmds)
        self.assertTrue(os.path.exists(os.path.join(ROOT, "bin", "raynsis-inspector")))

    def test_readme_rule_table_matches_the_rules(self):
        buf = io.StringIO()
        cli.rules_table(paths=cli.packaged_rules(), markdown=True, out=buf)
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertTrue(buf.getvalue().strip() in readme, "README rule table is stale: run `raynsis-inspector rules --markdown`")

    def test_rule_files_hold_no_raw_secret_looking_strings(self):
        # GitHub secret scanning reads raw text: examples escape one character as \uXXXX,
        # so the file never shows a key while json.load still gives the rule the real string.
        rules, _ = engine.load_rules([cli.CORE_RULES])
        secret = {r["id"]: r for r in rules}["tool.no-secret-in-command"]["pattern"]
        for path in cli.packaged_rules():
            with open(path, encoding="utf-8") as f:
                raw = f.read()
            m = re.search(secret, raw)
            self.assertIsNone(m, "%s: raw secret-looking text %r" % (os.path.basename(path), m and m.group(0)))

    def test_every_rule_file_is_packaged(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
            self.assertIn('raynsis_inspector = ["rules/*.json"]', f.read())


if __name__ == "__main__":
    unittest.main()
