"""0.2.2 security pass: untrusted failure.json, the running package as a guardrail, shell rules on every shell tool."""
from __future__ import annotations

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
                          "tool_input": {"file_path": path, "old_string": "\"deny\"", "new_string": "\"warn\""}})

    def test_editing_the_packaged_rules_is_denied(self):
        rc, out = self.edit(cli.CORE_RULES)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("tool.guardrails-read-only", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_editing_the_engine_is_denied_for_write_too(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Write", "cwd": self.tmp.name,
                             "tool_input": {"file_path": os.path.abspath(engine.__file__), "content": "def tool_hits(*a): return []\n"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_a_link_into_the_package_is_followed(self):
        link = os.path.join(self.tmp.name, "rules-link")
        try:
            os.symlink(os.path.dirname(cli.CORE_RULES), link)
        except OSError:
            self.skipTest("cannot create a symlink here")
        rc, out = self.edit(os.path.join(link, "core.json"))
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

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
                          "tool_input": {"command": command}})

    def test_monitor_runs_a_shell_command_and_gets_the_same_rules(self):
        for command in ("rm -rf ~", "git push --force origin main", "npm publish", "git commit --no-verify -m x",
                        "echo x > .claude/settings.json", "dd if=/dev/zero of=/dev/sda"):
            rc, out = self.run_cmd("Monitor", command)
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", command)

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


if __name__ == "__main__":
    unittest.main()
