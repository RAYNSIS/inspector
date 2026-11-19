from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from raynsis_inspector import audit, cli, engine, transcript  # noqa: E402


def _dump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def _write_transcript(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def human(text):
    return {"type": "user", "message": {"role": "user", "content": text}}


def tool_use(name, inp):
    return {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t", "name": name, "input": inp}]}}


def tool_result(text):
    return {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t", "content": text}]}}


def say(text):
    return {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_env = dict(os.environ)
        self.old_cwd = os.getcwd()
        os.environ["RAYNSIS_INSPECTOR_HOME"] = os.path.join(self.tmp.name, ".raynsis-inspector")
        for k in ("RAYNSIS_INSPECTOR_RULES", "RAYNSIS_INSPECTOR_DISABLE", "RAYNSIS_INSPECTOR_FAIL_CLOSED",
                  "RAYNSIS_INSPECTOR_SHADOW", "CLAUDE_PROJECT_DIR"):
            os.environ.pop(k, None)

    def tearDown(self):
        os.chdir(self.old_cwd)
        os.environ.clear()
        os.environ.update(self.old_env)
        self.tmp.cleanup()

    def hook(self, payload):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.hook(io.StringIO(json.dumps(payload)))
        out = buf.getvalue().strip()
        return rc, (json.loads(out) if out else None)


class CoreRules(Base):
    def test_every_core_rule_passes_its_own_examples(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.test_rules([cli.CORE_RULES]), 0)

    def test_rule_without_hit_example_fails_test_rules(self):
        p = os.path.join(self.tmp.name, "r.json")
        _dump([{"id": "x", "event": "tool", "action": "warn", "pattern": "a", "message": "m"}], p)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.test_rules([p]), 1)


class Loading(Base):
    def test_invalid_rule_is_skipped_and_others_still_enforce(self):
        # production lesson: one rule missing 'message' took every gate down for nine hours
        p = os.path.join(self.tmp.name, "r.json")
        _dump({"rules": [
            {"id": "broken", "event": "tool", "action": "deny", "pattern": "x"},
            {"id": "bad-regex", "event": "tool", "action": "deny", "pattern": "(", "message": "m"},
            {"id": "ok", "event": "tool", "action": "deny", "pattern": "danger", "message": "m"},
        ]}, p)
        rules, errors = engine.load_rules([p])
        self.assertEqual([r["id"] for r in rules], ["ok"])
        self.assertEqual(len(errors), 2)
        self.assertTrue(engine.tool_hits(rules, "Bash", {"command": "danger"}))

    def test_later_file_overrides_and_disables(self):
        a, b = os.path.join(self.tmp.name, "a.json"), os.path.join(self.tmp.name, "b.json")
        _dump([{"id": "r1", "event": "tool", "action": "deny", "pattern": "x", "message": "m"},
                   {"id": "r2", "event": "tool", "action": "deny", "pattern": "y", "message": "m"}], a)
        _dump({"rules": [{"id": "r1", "event": "tool", "action": "warn", "pattern": "x", "message": "m"}],
                   "disable": ["r2"]}, b)
        rules, errors = engine.load_rules([a, b])
        self.assertEqual(errors, [])
        self.assertEqual([(r["id"], r["action"]) for r in rules], [("r1", "warn")])

    def test_env_disable(self):
        os.environ["RAYNSIS_INSPECTOR_DISABLE"] = "tool.no-force-push"
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                             "tool_input": {"command": "git push --force"}, "cwd": self.tmp.name})
        self.assertIsNone(out)


class ToolHook(Base):
    def test_deny_json_and_audit_lines(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
                             "tool_input": {"command": "rm -rf ~"}, "cwd": self.tmp.name})
        self.assertEqual(rc, 0)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("tool.no-recursive-delete-home", hso["permissionDecisionReason"])
        hits = audit.read_jsonl("audit.jsonl")
        evals = audit.read_jsonl("evals.jsonl")
        self.assertEqual([h["rule"] for h in hits], ["tool.no-recursive-delete-home"])
        self.assertEqual(len(evals), 1)
        self.assertIn("tool.no-force-push", evals[0]["evaluated"])  # denominator recorded

    def test_clean_call_prints_nothing_but_counts(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
                             "tool_input": {"command": "ls -la"}, "cwd": self.tmp.name})
        self.assertIsNone(out)
        self.assertEqual(len(audit.read_jsonl("evals.jsonl")), 1)
        self.assertEqual(audit.read_jsonl("audit.jsonl"), [])


class ReplyHook(Base):
    def stop(self, entries, reply=None, active=False):
        tp = os.path.join(self.tmp.name, "t.jsonl")
        _write_transcript(tp, entries)
        payload = {"hook_event_name": "Stop", "session_id": "s2", "transcript_path": tp,
                   "stop_hook_active": active, "cwd": self.tmp.name}
        if reply is not None:
            payload["last_assistant_message"] = reply
        return self.hook(payload)

    def test_tests_pass_without_run_is_blocked(self):
        rc, out = self.stop([human("fix it"), tool_use("Edit", {"file_path": "a.py"}), say("All tests pass.")])
        self.assertEqual(out["decision"], "block")
        self.assertIn("reply.tests-pass-needs-run", out["reason"])

    def test_tests_pass_with_run_this_turn_is_allowed(self):
        rc, out = self.stop([human("fix it"), tool_use("Bash", {"command": "pytest -q"}), tool_result("3 passed"),
                             say("All tests pass.")])
        self.assertIsNone(out)

    def test_run_in_previous_turn_does_not_count(self):
        rc, out = self.stop([human("run tests"), tool_use("Bash", {"command": "pytest"}), say("ok"),
                             human("and now?"), say("All tests pass.")])
        self.assertEqual(out["decision"], "block")

    def test_stop_hook_active_never_blocks_twice(self):
        rc, out = self.stop([human("x"), say("All tests pass.")], active=True)
        self.assertNotIn("decision", out)
        self.assertIn("reply.tests-pass-needs-run", out["systemMessage"])

    def test_link_seen_in_tool_result_or_pasted_by_human_is_allowed(self):
        rc, out = self.stop([human("is https://shop.dev/p/42 up?"), tool_use("WebFetch", {"url": "https://docs.tool.dev/a"}),
                             tool_result("200"), say("https://shop.dev/p/42 and https://docs.tool.dev/a are fine.")])
        self.assertIsNone(out)

    def test_invented_link_is_blocked(self):
        rc, out = self.stop([human("docs?"), tool_use("Bash", {"command": "ls"}), say("See https://docs.tool.dev/never-opened")])
        self.assertIn("reply.unopened-link", out["reason"])

    def test_link_written_to_a_file_by_the_agent_is_not_evidence(self):
        rc, out = self.stop([human("docs?"), tool_use("Write", {"file_path": "n.md", "content": "https://docs.tool.dev/made-up"}),
                             tool_result("ok"), say("See https://docs.tool.dev/made-up")])
        self.assertIn("reply.unopened-link", out["reason"])

    def test_payload_reply_wins_over_transcript(self):
        rc, out = self.stop([human("x"), tool_use("Bash", {"command": "ls"}), say("old draft")], reply="All tests pass.")
        self.assertEqual(out["decision"], "block")


class Transcript(Base):
    def test_hook_feedback_and_tool_results_are_not_human_turns(self):
        tp = os.path.join(self.tmp.name, "t.jsonl")
        _write_transcript(tp, [human("go"), tool_use("Bash", {"command": "make test"}), tool_result("ok"),
                               {"type": "user", "message": {"content": [{"type": "text", "text": "Stop hook feedback: fix"}]}},
                               say("done")])
        self.assertEqual([a["tool"] for a in transcript.turn_activity(tp)], ["Bash"])

    def test_missing_transcript_is_empty_not_error(self):
        self.assertEqual(transcript.turn_activity("/nonexistent/x.jsonl"), [])
        self.assertEqual(transcript.session_text(""), "")


class FailLoud(Base):
    def test_crash_warns_once_per_window_and_counts(self):
        first = audit.fail_loud(KeyError("message"), now=1000.0)
        second = audit.fail_loud(KeyError("message"), now=1060.0)
        third = audit.fail_loud(KeyError("message"), now=1700.0)
        self.assertEqual((bool(first), bool(second), bool(third)), (True, False, True))
        self.assertIn("NOT enforcing", first)
        self.assertIn("3 times", third)
        errors = [r for r in audit.read_jsonl("audit.jsonl") if r.get("event") == "engine_error"]
        self.assertEqual(len(errors), 3)

    def test_bad_payload_fails_open_but_loud(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.hook(io.StringIO("not json"))
        self.assertEqual(rc, 0)
        self.assertIn("ENGINE ERROR", buf.getvalue())

    def test_fail_closed_denies_tool_calls(self):
        os.environ["RAYNSIS_INSPECTOR_FAIL_CLOSED"] = "1"
        os.environ["RAYNSIS_INSPECTOR_RULES"] = os.path.join(self.tmp.name, "r.json")
        _dump([], os.environ["RAYNSIS_INSPECTOR_RULES"])
        original = engine.tool_hits
        engine.tool_hits = lambda *a: 1 / 0
        try:
            rc, out = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                 "tool_input": {"command": "ls"}, "cwd": self.tmp.name})
        finally:
            engine.tool_hits = original
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("ENGINE ERROR", out["systemMessage"])  # warning and deny in ONE object


class PackagedAndShadow(Base):
    def test_all_packaged_rule_sets_pass_their_examples(self):
        paths = cli.packaged_rules()
        self.assertEqual(paths[0], cli.CORE_RULES)
        self.assertTrue(any(p.endswith("tr.json") for p in paths))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.test_rules(paths), 0)

    def test_shadow_logs_but_prints_nothing(self):
        os.environ["RAYNSIS_INSPECTOR_SHADOW"] = "1"
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                             "tool_input": {"command": "rm -rf ~"}, "cwd": self.tmp.name})
        self.assertIsNone(out)
        hits = audit.read_jsonl("audit.jsonl")
        self.assertEqual(hits[0]["rule"], "tool.no-recursive-delete-home")
        self.assertTrue(hits[0]["shadow"])

    def test_shadow_engine_error_is_logged_not_printed(self):
        os.environ["RAYNSIS_INSPECTOR_SHADOW"] = "1"
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.hook(io.StringIO("not json"))
        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(audit.read_jsonl("audit.jsonl")[0]["event"], "engine_error")

    def test_turkish_reply_rule_blocks(self):
        tp = os.path.join(self.tmp.name, "t.jsonl")
        _write_transcript(tp, [human("düzelt"), say("Düzelttim, tüm testler geçti.")])
        rc, out = self.hook({"hook_event_name": "Stop", "session_id": "s", "transcript_path": tp, "cwd": self.tmp.name})
        self.assertIn("reply.tr.tests-pass-needs-run", out["reason"])
        self.assertIn("reply.tr.done-needs-action", out["reason"])


class Stats(Base):
    def test_dedupe_window(self):
        rule = {"id": "r", "action": "deny"}
        for t in (0, 100, 900, 950):
            audit._append("audit.jsonl", {"session": "s", "event": "tool", "rule": "r", "action": "deny", "t": 1000 + t})
        audit._append("audit.jsonl", {"session": "other", "event": "tool", "rule": "r", "action": "deny", "t": 1050})
        for _ in range(10):
            audit.log_eval("s", "tool", ["r"], [])
        table = cli.stats(window=600, out=io.StringIO())
        self.assertEqual(table["r"], {"checked": 10, "raw": 5, "unique": 3})
        del rule

    def _seed(self, now):
        """Two real sessions and one rule-testing session; one old row and one row without a time."""
        for sess, n_eval, hit_times in (("real-1", 6, [now - 50]), ("real-2", 3, []), ("probe-9", 4, [now - 40, now - 30])):
            for _ in range(n_eval):
                audit._append("evals.jsonl", {"session": sess, "event": "tool", "evaluated": ["r"], "hits": [], "t": now - 60})
            for t in hit_times:
                audit._append("audit.jsonl", {"session": sess, "event": "tool", "rule": "r", "action": "deny", "t": t})
        audit._append("evals.jsonl", {"session": "real-1", "event": "tool", "evaluated": ["r"], "hits": [], "t": now - 10 * 86400})
        audit._append("audit.jsonl", {"session": "real-1", "event": "tool", "rule": "r", "action": "deny", "t": now - 10 * 86400})
        with open(os.path.join(audit.home(), "evals.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"session": "real-2", "event": "tool", "evaluated": ["r"], "hits": []}) + "\n")

    def test_unfiltered_output_is_unchanged(self):
        self._seed(time.time())
        buf = io.StringIO()
        table = cli.stats(out=buf)
        self.assertEqual(table["r"], {"checked": 15, "raw": 4, "unique": 3})
        self.assertNotIn("filtered out", buf.getvalue())

    def test_exclude_session_drops_checks_and_hits(self):
        self._seed(time.time())
        buf = io.StringIO()
        table = cli.stats(out=buf, exclude=["probe"])
        self.assertEqual(table["r"], {"checked": 11, "raw": 2, "unique": 2})
        self.assertIn("filtered out: 4 evaluations, 2 hits", buf.getvalue())
        self.assertEqual(cli.stats(out=io.StringIO(), exclude=["probe", "real-1"])["r"],
                         {"checked": 4, "raw": 0, "unique": 0})
        self.assertEqual(cli.stats(out=io.StringIO(), exclude=[""])["r"]["checked"], 15)  # an empty prefix excludes nothing

    def test_since_keeps_recent_rows_only(self):
        self._seed(time.time())
        buf = io.StringIO()
        table = cli.stats(out=buf, since=1)
        # the 10 day old check and hit go, and so does the check that carries no time
        self.assertEqual(table["r"], {"checked": 13, "raw": 3, "unique": 2})
        self.assertIn("filtered out: 2 evaluations, 1 hits", buf.getvalue())
        self.assertEqual(cli.stats(out=io.StringIO(), since=0.5, exclude=["probe"])["r"],
                         {"checked": 9, "raw": 1, "unique": 1})

    def test_stats_flags_on_the_command_line(self):
        self._seed(time.time())
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["stats", "--exclude-session", "probe", "--since", "1"])
        self.assertEqual(rc, 0)
        self.assertIn("filtered out: 6 evaluations, 3 hits", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
