"""0.2.2 security pass: untrusted failure.json, the running package as a guardrail, shell rules on every shell tool."""
from __future__ import annotations

import io
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from raynsis_inspector import audit, cli, engine  # noqa: E402
from tests.test_engine import Base, _dump  # noqa: E402


class PlantedState(Base):
    """failure.json lives in the project: a cloned repository can ship one."""

    def plant(self, state):
        home = audit.ensure_home()
        with open(os.path.join(home, "failure.json"), "w", encoding="utf-8") as f:
            f.write(state if isinstance(state, str) else json.dumps(state))

    def key(self, exc):
        return audit._key("engine_error", type(exc).__name__ + str(exc)[:80])

    def test_future_timestamps_cannot_silence_an_engine_error(self):
        exc = ValueError("boom")
        far = time.time() + 10 ** 9
        self.plant({self.key(exc): {"count": 1, "last": far, "last_warned": far}})
        self.assertIn("ENGINE ERROR", audit.fail_loud(exc))

    def test_wrong_types_do_not_crash_the_warning(self):
        exc = ValueError("boom")
        for bad in ({self.key(exc): {"count": "x", "last": "y", "last_warned": [1]}}, {self.key(exc): 5}, [1, 2], "not json",
                    {self.key(exc): {"count": True, "last": float("inf"), "last_warned": float("nan")}}):
            self.plant(bad)
            self.assertIn("ENGINE ERROR", audit.fail_loud(exc), repr(bad)[:60])

    def test_many_poisoned_keys_do_not_break_trimming(self):
        state = {"k%d" % i: {"last": ("x" if i % 2 else i), "count": i} for i in range(260)}
        self.plant(state)
        self.assertIn("ENGINE ERROR", audit.fail_loud(ValueError("boom")))
        with open(os.path.join(audit.home(), "failure.json"), encoding="utf-8") as f:
            self.assertLessEqual(len(json.load(f)), 101)

    def test_oversized_state_is_ignored(self):
        self.plant(json.dumps({"pad": {"x": "a" * (audit.STATE_MAX_BYTES + 10)}}))
        self.assertIn("ENGINE ERROR", audit.fail_loud(ValueError("boom")))

    @unittest.skipUnless(hasattr(os, "symlink") and os.path.exists("/dev/zero"), "needs /dev/zero")
    def test_state_that_is_a_link_to_a_device_is_not_read(self):
        home = audit.ensure_home()
        os.symlink("/dev/zero", os.path.join(home, "failure.json"))
        t = time.time()
        self.assertIn("ENGINE ERROR", audit.fail_loud(ValueError("boom")))
        self.assertLess(time.time() - t, 2)

    def test_throttle_still_quiets_a_repeat_within_ten_minutes(self):
        exc = ValueError("boom")
        self.assertIn("ENGINE ERROR", audit.fail_loud(exc, now=1000.0))
        self.assertEqual(audit.fail_loud(exc, now=1100.0), "")
        self.assertIn("3 times", audit.fail_loud(exc, now=1000.0 + audit.WARN_EVERY_S + 200), "the quiet repeat is still counted")

    def test_weakening_notice_survives_a_planted_state(self):
        project = os.path.join(self.tmp.name, "proj")
        os.makedirs(os.path.join(project, ".raynsis-inspector"))
        os.environ["CLAUDE_PROJECT_DIR"] = project
        os.environ["RAYNSIS_INSPECTOR_HOME"] = os.path.join(project, ".raynsis-inspector")
        _dump({"rules": [{"id": "tool.no-force-push", "action": "warn"}]},
              os.path.join(project, ".raynsis-inspector", "rules.json"))
        self.plant({"k%d" % i: {"last": ("x" if i % 2 else 10 ** 12), "last_warned": 10 ** 12} for i in range(260)})
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash", "cwd": project,
                             "tool_input": {"command": "ls"}})
        self.assertIn("tool.no-force-push", out["systemMessage"])


class OwnFiles(Base):
    """The running engine and its packaged rules are guardrails wherever they are installed."""

    def edit(self, path, tool="Edit"):
        return self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": tool, "cwd": self.tmp.name,
                          "permission_mode": "default",
                          "tool_input": {"file_path": path, "old_string": "\"deny\"", "new_string": "\"warn\""}})

    def test_editing_the_packaged_rules_asks_the_human(self):
        rc, out = self.edit(cli.CORE_RULES)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIn("tool.guardrails-read-only", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_editing_the_engine_asks_for_write_too(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Write", "cwd": self.tmp.name,
                             "permission_mode": "default",
                             "tool_input": {"file_path": os.path.abspath(engine.__file__), "content": "def tool_hits(*a): return []\n"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_a_link_into_the_package_is_followed(self):
        link = os.path.join(self.tmp.name, "rules-link")
        try:
            os.symlink(os.path.dirname(cli.CORE_RULES), link)
        except OSError:
            self.skipTest("cannot create a symlink here")
        rc, out = self.edit(os.path.join(link, "core.json"))
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_other_files_are_left_alone(self):
        rc, out = self.edit(os.path.join(self.tmp.name, "raynsis_inspector", "rules", "core.json"))
        self.assertIsNone(out)

    def test_the_human_can_switch_the_guard_off(self):
        os.environ["RAYNSIS_INSPECTOR_DISABLE"] = "tool.guardrails-read-only"
        rc, out = self.edit(cli.CORE_RULES)
        self.assertIsNone(out)

    def test_reading_the_package_is_fine(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Read", "cwd": self.tmp.name,
                             "tool_input": {"file_path": cli.CORE_RULES}})
        self.assertIsNone(out)


class EveryShellTool(Base):
    def run_cmd(self, tool, command):
        return self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": tool, "cwd": self.tmp.name,
                          "permission_mode": "default", "tool_input": {"command": command}})

    def test_monitor_runs_a_shell_command_and_gets_the_same_rules(self):
        for command in ("rm -rf ~", "git push --force origin main", "npm publish", "git commit --no-verify -m x",
                        "dd if=/dev/zero of=/dev/sda"):
            rc, out = self.run_cmd("Monitor", command)
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", command)
        rc, out = self.run_cmd("Monitor", "echo x > .claude/settings.json")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_every_rule_for_bash_also_covers_monitor(self):
        rules, _ = engine.load_rules(cli.packaged_rules())
        for r in rules:
            if "Bash" in (r.get("tools") or []):
                self.assertIn("Monitor", r["tools"], r["id"])

    def test_dry_run_switched_off_is_a_real_publish(self):
        for command in ("npm publish --dry-run=false", "gh release create v1.0.0 -n 'notes'", "npm publish # --dry-run"):
            rc, out = self.run_cmd("Bash", command)
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", command)
        for command in ("npm publish --dry-run", "cargo publish -n"):
            self.assertIsNone(self.run_cmd("Bash", command)[1], command)


class AskTheHuman(Base):
    """0.3.0: a guardrail edit is put to the human as a permission prompt instead of a flat deny,
    so people who maintain their own hooks with the agent can keep doing it, one approval at a time."""

    GUARD_IDS = ("tool.guardrails-read-only", "tool.guardrails-read-only-shell", "tool.guardrails-read-only-mcp")

    def call(self, tool, tool_input, mode="default"):
        payload = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": tool, "cwd": self.tmp.name,
                   "tool_input": tool_input}
        if mode is not None:
            payload["permission_mode"] = mode
        return self.hook(payload)

    def test_it_asks_only_where_claude_code_shows_the_prompt(self):
        write = {"file_path": "/repo/.claude/settings.json", "content": "{}"}
        for mode in ("default", "acceptEdits", "plan", "auto"):
            self.assertEqual(self.call("Write", write, mode)[1]["hookSpecificOutput"]["permissionDecision"], "ask", mode)
        # bypassPermissions let a Write under .claude/ through although a hook said "ask" (measured 19.11.2026)
        for mode in ("bypassPermissions", "dontAsk", "someFutureMode", "", None, 5):
            hso = self.call("Write", write, mode)[1]["hookSpecificOutput"]
            self.assertEqual(hso["permissionDecision"], "deny", repr(mode))
            self.assertIn("tool.guardrails-read-only", hso["permissionDecisionReason"], repr(mode))
            self.assertIn("switches to another permission mode", hso["permissionDecisionReason"], repr(mode))

    def test_an_ordinary_deny_has_no_mode_note(self):
        hso = self.call("Bash", {"command": "cat .env"}, "bypassPermissions")[1]["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertNotIn("permission mode", hso["permissionDecisionReason"])

    def test_the_three_guardrail_rules_ask(self):
        rules = {r["id"]: r for r in engine.load_rules(cli.packaged_rules())[0]}
        self.assertEqual([rules[i]["action"] for i in self.GUARD_IDS], ["ask"] * 3)
        self.assertEqual(sorted(r["id"] for r in rules.values() if r["action"] == "ask"), sorted(self.GUARD_IDS))

    def test_a_hook_edit_becomes_a_permission_prompt(self):
        for tool, tool_input in (("Edit", {"file_path": "/home/u/.claude/hooks/guard.py", "old_string": "a", "new_string": "b"}),
                                 ("Write", {"file_path": "/repo/.claude/settings.json", "content": "{}"}),
                                 ("Bash", {"command": "cp new.json ~/.claude/settings.json"}),
                                 ("mcp__fs__write_file", {"path": "/repo/.claude/hooks/x.sh", "content": "true"})):
            rc, out = self.call(tool, tool_input)
            hso = out["hookSpecificOutput"]
            self.assertEqual((rc, hso["hookEventName"], hso["permissionDecision"]), (0, "PreToolUse", "ask"), tool)
            self.assertTrue(hso["permissionDecisionReason"].startswith("RAYNSIS Inspector asks you first:"), tool)
            self.assertIn("Approve it only if you asked for this change", hso["permissionDecisionReason"], tool)

    def test_a_deny_in_the_same_call_wins(self):
        rc, out = self.call("Bash", {"command": "rm -rf ~; echo x > .claude/settings.json"})
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("tool.no-recursive-delete-home", hso["permissionDecisionReason"])

    def test_shadow_mode_prints_nothing_but_logs_the_hit(self):
        os.environ["RAYNSIS_INSPECTOR_SHADOW"] = "1"
        rc, out = self.call("Write", {"file_path": "/repo/.claude/settings.json", "content": "{}"})
        self.assertIsNone(out)
        rows = [r for r in audit.read_jsonl("audit.jsonl") if r.get("rule") == "tool.guardrails-read-only"]
        self.assertEqual([(r["action"], r.get("shadow")) for r in rows], [("ask", True)])

    def test_the_human_can_make_it_a_hard_deny_again(self):
        strict = os.path.join(self.tmp.name, "strict.json")
        _dump({"rules": [{"id": i, "action": "deny"} for i in self.GUARD_IDS]}, strict)
        os.environ["RAYNSIS_INSPECTOR_RULES"] = strict
        rc, out = self.call("Write", {"file_path": "/repo/.claude/settings.json", "content": "{}"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_ask_is_for_tool_rules_only(self):
        self.assertEqual(engine.validate({"id": "r", "event": "reply", "action": "ask", "message": "m", "pattern": "x"}),
                         ["r: action 'ask' is for tool rules only (a reply has no permission prompt)"])
        self.assertEqual(engine.validate({"id": "t", "event": "tool", "action": "ask", "message": "m", "pattern": "x"}), [])

    def test_check_exits_1_on_an_ask(self):
        sink = io.StringIO()
        self.assertEqual(cli.check("bash", "echo x > .claude/settings.json", out=sink), 1)
        self.assertIn("ASK  tool.guardrails-read-only-shell", sink.getvalue())


if __name__ == "__main__":
    unittest.main()
