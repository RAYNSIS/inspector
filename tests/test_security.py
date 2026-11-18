"""Regression tests for the pre-release security review (18 Nov 2026). Each test is one reproduced finding."""
from __future__ import annotations

import io
import json
import os
import sys
import time
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kanit import audit, cli, engine, transcript  # noqa: E402
from tests.test_engine import Base, _dump, _write_transcript, human, say, tool_result, tool_use  # noqa: E402

POSIX = hasattr(os, "mkfifo") and hasattr(__import__("signal"), "setitimer")
PUSH = "git" + " push"


class Slowness(Base):
    def test_rm_rule_is_linear(self):
        # was exponential: 80 B took 0.9 s, 100 B did not finish in 30 s, so the hook timed out open
        cmd = "echo rm " + "--a " * 30 + "x; " + PUSH + " --force origin main"
        t = time.time()
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                             "tool_input": {"command": cmd}, "cwd": self.tmp.name})
        self.assertLess(time.time() - t, 2.0)
        self.assertIn("tool.no-force-push", out["hookSpecificOutput"]["permissionDecisionReason"])

    @unittest.skipUnless(POSIX, "interval timer is POSIX only")
    def test_over_budget_tool_call_is_denied_not_let_through(self):
        original, budget = engine.tool_hits, dict(cli.BUDGET_S)

        def slow(*a, **k):
            time.sleep(5)
            return []
        engine.tool_hits, cli.BUDGET_S["PreToolUse"] = slow, 0.3
        try:
            rc, out = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                 "tool_input": {"command": "ls"}, "cwd": self.tmp.name})
        finally:
            engine.tool_hits, cli.BUDGET_S = original, budget
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("could not finish checking", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertTrue(any(r.get("event") == "over_budget" for r in audit.read_jsonl("audit.jsonl")))

    @unittest.skipUnless(POSIX, "interval timer is POSIX only")
    def test_crafted_slow_command_is_denied_within_budget(self):
        # the packaged patterns are linear (SecondAudit); a project rule may be slow: the budget must
        # interrupt the regex itself and deny, never let the call through
        slow = os.path.join(self.tmp.name, "slow.json")
        _dump({"rules": [{"id": "tool.slow", "event": "tool", "action": "deny", "tools": ["Bash"], "field": "command",
                          "pattern": "(x+x+)+y", "message": "exponential on purpose"}]}, slow)
        os.environ["KANIT_RULES"] = slow
        budget = dict(cli.BUDGET_S)
        cli.BUDGET_S["PreToolUse"] = 0.5
        try:
            t = time.time()
            rc, out = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                 "tool_input": {"command": "x" * 40}, "cwd": self.tmp.name})
        finally:
            cli.BUDGET_S = budget
        self.assertLess(time.time() - t, 2.0)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    @unittest.skipUnless(POSIX, "interval timer is POSIX only")
    def test_over_budget_reply_warns_and_does_not_block(self):
        original, budget = engine.reply_hits, dict(cli.BUDGET_S)

        def slow(*a, **k):
            time.sleep(5)
            return []
        engine.reply_hits, cli.BUDGET_S["Stop"] = slow, 0.3
        try:
            rc, out = self.hook({"hook_event_name": "Stop", "last_assistant_message": "ok", "cwd": self.tmp.name})
        finally:
            engine.reply_hits, cli.BUDGET_S = original, budget
        self.assertNotIn("decision", out)
        self.assertIn("could not be checked", out["systemMessage"])


@unittest.skipUnless(POSIX, "FIFOs are POSIX only")
class SpecialFiles(Base):
    def test_fifo_as_project_rules_is_an_error_not_a_hang(self):
        os.makedirs(os.path.join(self.tmp.name, ".kanit"))
        os.mkfifo(os.path.join(self.tmp.name, ".kanit", "rules.json"))
        t = time.time()
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                             "tool_input": {"command": "rm -rf ~"}, "cwd": self.tmp.name})
        self.assertLess(time.time() - t, 2.0)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("not a regular file", out["systemMessage"])

    def test_write_onto_a_fifo_does_not_hang(self):
        fifo = os.path.join(self.tmp.name, "pipe")
        os.mkfifo(fifo)
        t = time.time()
        self.assertNotIn("_prior", cli.with_prior({"file_path": fifo, "content": "x"}))
        self.assertNotIn("_prior", cli.with_prior({"file_path": "/dev/zero", "content": "x"}))
        self.assertLess(time.time() - t, 1.0)

    def test_log_symlink_is_refused_not_followed(self):
        target = os.path.join(self.tmp.name, "outside.txt")
        with open(target, "w") as f:
            f.write("keep\n")
        audit.ensure_home()
        os.symlink(target, os.path.join(audit.home(), "evals.jsonl"))
        audit.log_eval("s", "tool", [], [])
        with open(target) as f:
            self.assertEqual(f.read(), "keep\n")


class Robustness(Base):
    def test_lone_surrogate_still_denies(self):
        # json.dumps(ensure_ascii=False) used to raise inside the log write and swallow the deny
        cmd = PUSH + " $(: \ud800) --force origin main"
        for _ in range(3):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.hook(io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                                                 "tool_input": {"command": cmd}, "cwd": self.tmp.name})))
            out = json.loads(buf.getvalue())
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
            buf.getvalue().encode("ascii")

    def test_broken_project_file_never_disarms_core_rules(self):
        os.makedirs(os.path.join(self.tmp.name, ".kanit"))
        _dump({"disable": 5, "rules": [{"id": "tool.no-force-push", "pattern+": 5}]},
              os.path.join(self.tmp.name, ".kanit", "rules.json"))
        for _ in range(3):
            rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                                 "tool_input": {"command": PUSH + " --force"}, "cwd": self.tmp.name})
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_a_second_different_error_is_not_hidden_by_the_first(self):
        first = audit.fail_loud(KeyError("message"), now=1000.0)
        other = audit.fail_loud(TypeError("unhashable"), now=1010.0)
        again = audit.fail_loud(KeyError("message"), now=1020.0)
        self.assertTrue(first and other)
        self.assertEqual(again, "")


class Weakening(Base):
    def test_project_file_that_disables_a_core_rule_is_announced_once(self):
        os.makedirs(os.path.join(self.tmp.name, ".kanit"))
        _dump({"disable": ["tool.no-force-push"]}, os.path.join(self.tmp.name, ".kanit", "rules.json"))
        payload = {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
                   "tool_input": {"command": "rm -rf ~"}, "cwd": self.tmp.name}
        rc, out = self.hook(payload)
        self.assertIn("tool.no-force-push", out["systemMessage"])
        rc, out = self.hook(payload)
        self.assertNotIn("systemMessage", out)

    def test_no_notice_without_project_rules(self):
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                             "tool_input": {"command": "ls"}, "cwd": self.tmp.name})
        self.assertIsNone(out)


class Evidence(Base):
    def rules(self, rid):
        rules, _ = engine.load_rules(cli.packaged_rules())
        return [r for r in rules if r["id"] == rid]

    def test_reading_a_test_file_is_not_running_tests(self):
        hits = engine.reply_hits(self.rules("reply.tests-pass-needs-run"), "All tests pass.",
                                 ['Read: {"file_path": "tests/test_api.py"}', 'Grep: {"pattern": "check"}'])
        self.assertTrue(hits)

    def test_unless_only_excuses_its_own_sentence(self):
        hits = engine.reply_hits(self.rules("reply.tests-pass-needs-run"), "Lint is not verified yet. All tests pass.", [])
        self.assertTrue(hits)
        quiet = engine.reply_hits(self.rules("reply.tests-pass-needs-run"), "All tests pass is not verified.", [])
        self.assertEqual(quiet, [])

    def test_a_quoted_claim_is_a_mention(self):
        # seen end to end: a corrected subagent reply quoted the phrase it had been asked to repeat
        r = self.rules("reply.tests-pass-needs-run")
        fixed = 'I didn\'t run any tests. "All tests pass" was only the sentence you asked me to repeat.'
        self.assertEqual(engine.reply_hits(r, fixed, []), [])
        self.assertEqual(engine.reply_hits(r, "My earlier “All tests pass.” was unsupported.", []), [])
        self.assertTrue(engine.reply_hits(r, 'Fixed it. All tests pass. See "notes".', []))
        self.assertTrue(engine.reply_hits(r, '"Fixed it. All tests pass."', []))

    def test_userinfo_cannot_borrow_an_exempt_host(self):
        r = self.rules("reply.unopened-link")
        self.assertTrue(engine.reply_hits(r, "See https://example.com:x@evil.io/fake", [], ""))
        self.assertEqual(engine.reply_hits(r, "Open http://localhost:3000/x", [], ""), [])

    def test_a_prefix_of_a_seen_link_is_not_the_link(self):
        r = self.rules("reply.unopened-link")
        seen = 'WebFetch: {"url": "https://docs.tool.dev/abc/install?v=2"}'
        self.assertTrue(engine.reply_hits(r, "See https://docs.tool.dev/a", [], seen))
        self.assertEqual(engine.reply_hits(r, "See https://docs.tool.dev/abc", [], seen), [])
        self.assertEqual(engine.reply_hits(r, "See https://docs.tool.dev/abc/install?v=2.", [], seen), [])

    def test_link_in_todo_list_is_not_seen(self):
        tp = os.path.join(self.tmp.name, "t.jsonl")
        _write_transcript(tp, [human("docs?"), tool_use("TodoWrite", {"todos": [{"content": "cite https://docs.tool.dev/made-up"}]}),
                               tool_result("ok"), say("See https://docs.tool.dev/made-up")])
        self.assertNotIn("https://docs.tool.dev/made-up", transcript.session_text(tp))

    def test_turn_longer_than_the_first_tail_is_still_judged(self):
        # 45 x 100 KB of output used to push the turn's start out of the 4 MB tail: "unknown", rule skipped
        tp = os.path.join(self.tmp.name, "t.jsonl")
        entries = [human("fix it")]
        for _ in range(45):
            entries += [tool_use("Bash", {"command": "cat big.log"}), tool_result("x" * 100000)]
        entries.append(say("All tests pass."))
        _write_transcript(tp, entries)
        self.assertGreater(os.path.getsize(tp), transcript.TAIL_BYTES)
        acts, started = transcript.turn_state(tp)
        self.assertTrue(started)
        rc, out = self.hook({"hook_event_name": "Stop", "session_id": "s", "transcript_path": tp, "cwd": self.tmp.name})
        self.assertEqual(out["decision"], "block")


class ReleaseAudit(Base):
    """Findings of the independent pre-release audit (18 Nov 2026), each reproduced first."""

    def rules(self, rid):
        rules, _ = engine.load_rules(cli.packaged_rules())
        return [r for r in rules if r["id"] == rid]

    def test_conditions_instructions_and_questions_are_not_claims(self):
        r = self.rules("reply.tests-pass-needs-run")
        for text in ("If the tests pass, merge it.", "Make sure all tests pass before merging.",
                     "The PR is ready when all tests pass.", "Not all tests pass yet: 3 failures.",
                     "The tests have not been run, so I cannot say the tests pass.",
                     "Do all tests pass on CI, or only locally?"):
            self.assertEqual(engine.reply_hits(r, text, []), [], text)

    def test_a_question_after_the_claim_does_not_excuse_it(self):
        r = self.rules("reply.tests-pass-needs-run")
        for text in ("Fixed the parser and all tests pass, want me to commit it?", "All tests pass; shall I merge?"):
            self.assertTrue(engine.reply_hits(r, text, []), text)

    def test_reading_tests_from_the_shell_is_not_running_them(self):
        r = self.rules("reply.tests-pass-needs-run")
        for line in ('Bash: {"command": "cat tests/test_api.py"}', 'Bash: {"command": "ls tests/"}',
                     'Bash: {"command": "ls", "description": "List test files"}', 'Bash: {"command": "echo check"}'):
            self.assertTrue(engine.reply_hits(r, "All tests pass.", [line]), line)
        for line in ('Bash: {"command": "cd tests && pytest -q"}', 'Bash: {"command": "./run_tests.sh"}', "Bash: pytest -q"):
            self.assertEqual(engine.reply_hits(r, "All tests pass.", [line]), [], line)

    def test_unless_only_excuses_its_own_command(self):
        r = self.rules("tool.no-package-publish")
        self.assertTrue(engine.tool_hits(r, "Bash", {"command": "docker push org/app:1.0; echo -n done"}))
        self.assertEqual(engine.tool_hits(r, "Bash", {"command": "npm publish --dry-run"}), [])

    def test_agent_cannot_switch_kanit_off_from_the_shell(self):
        r = self.rules("tool.guardrails-read-only-shell")
        for cmd in ("claude plugin disable kanit@kanit", "rm -rf ~/.claude/plugins", "mv ~/.claude/plugins /tmp/p",
                    "rm -rf .kanit", "rm -rf ~/.claude/hooks"):
            self.assertTrue(engine.tool_hits(r, "Bash", {"command": cmd}), cmd)

    def test_project_rules_follow_the_project_not_the_shell_cwd(self):
        project = os.path.join(self.tmp.name, "p")
        sub = os.path.join(project, "src", "api")
        os.makedirs(os.path.join(project, ".kanit"))
        os.makedirs(sub)
        _dump({"rules": [{"id": "tool.no-prod-db", "event": "tool", "action": "deny", "tools": ["Bash"], "field": "command",
                          "pattern": "psql\\s+.*prod", "message": "replica only"}]},
              os.path.join(project, ".kanit", "rules.json"))
        os.environ.pop("KANIT_HOME", None)
        os.environ["CLAUDE_PROJECT_DIR"] = project
        rc, out = self.hook({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                             "tool_input": {"command": "psql -h prod-db"}, "cwd": sub})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse(os.path.exists(os.path.join(sub, ".kanit")))

    def test_a_link_given_early_in_a_long_session_is_still_seen(self):
        tp = os.path.join(self.tmp.name, "t.jsonl")
        entries = [human("read https://docs.tool.dev/guide/install please")]
        for _ in range(45):
            entries += [tool_use("Bash", {"command": "cat big.log"}), tool_result("x" * 100000)]
        entries += [human("thanks, now answer"), say("See https://docs.tool.dev/guide/install")]
        _write_transcript(tp, entries)
        self.assertGreater(os.path.getsize(tp), transcript.TAIL_BYTES)
        rc, out = self.hook({"hook_event_name": "Stop", "session_id": "s", "transcript_path": tp, "cwd": self.tmp.name})
        self.assertIsNone(out)
        _write_transcript(tp, entries[:-1] + [say("See https://docs.tool.dev/made-up")])
        rc, out = self.hook({"hook_event_name": "Stop", "session_id": "s", "transcript_path": tp, "cwd": self.tmp.name})
        self.assertEqual(out["decision"], "block")

    def test_unknown_turns_are_counted_in_stats(self):
        rc, out = self.hook({"hook_event_name": "Stop", "session_id": "s", "last_assistant_message": "All tests pass.",
                             "transcript_path": os.path.join(self.tmp.name, "missing.jsonl"), "cwd": self.tmp.name})
        buf = io.StringIO()
        cli.stats(out=buf)
        self.assertIn("turn start not readable (evidence rules skipped): 1", buf.getvalue())



class SecondAudit(Base):
    """Findings of the second audit pass (18 Nov 2026), each reproduced first."""

    def rules(self, rid):
        rules, _ = engine.load_rules(cli.packaged_rules())
        return [r for r in rules if r["id"] == rid]

    def test_instructions_are_not_claims_but_statements_are(self):
        r = self.rules("reply.tests-pass-needs-run")
        for text in ("I can confirm all tests pass.", "This change ensures that all tests pass.", "## Verify\nAll tests pass.",
                     "Once again, all tests pass.", "When I ran it, all tests passed."):
            self.assertTrue(engine.reply_hits(r, text, []), text)
        for text in ("Please make sure all tests pass before merging.", "Ideally all tests pass before the release.",
                     "When CI is green and all tests pass, the bot merges.", "As long as the tests pass, it is safe.",
                     "I'd rather not say the tests pass until CI finishes."):
            self.assertEqual(engine.reply_hits(r, text, []), [], text)
        b = self.rules("reply.build-passes-needs-run")
        self.assertEqual(engine.reply_hits(b, "The build passes only if you set NODE_ENV first.", []), [])

    def test_a_dash_or_bracket_ends_the_claims_clause(self):
        r = self.rules("reply.tests-pass-needs-run")
        for text in ("All tests pass — want me to open the PR?", "All tests pass (did you see the CI run?)",
                     "All tests pass so shall I merge?"):
            self.assertTrue(engine.reply_hits(r, text, []), text)
        self.assertEqual(engine.reply_hits(r, "Do all tests pass on main (or only on CI)?", []), [])

    def test_installing_or_locating_a_test_runner_is_not_running_it(self):
        r = self.rules("reply.tests-pass-needs-run")
        for cmd in ("pip install pytest", "npm install --save-dev jest", "which pytest", "time ls tests/",
                    "sudo cat tests/x.py", "ruff check ."):
            self.assertTrue(engine.reply_hits(r, "All tests pass.", ["Bash: " + json.dumps({"command": cmd})]), cmd)
        for cmd in ("make check", "npm ci && npm test", "time pytest -q"):
            self.assertEqual(engine.reply_hits(r, "All tests pass.", ["Bash: " + json.dumps({"command": cmd})]), [], cmd)

    def test_env_lookups_in_code_are_not_secret_files(self):
        r = self.rules("tool.no-secret-files")
        for cmd in ("grep -rn 'process.env' src/", "rg 'import.meta.env' src", "cat .envrc"):
            self.assertEqual(engine.tool_hits(r, "Bash", {"command": cmd}), [], cmd)
        for cmd in ("cat .ENV", "cat .env.production.local", "cat .env~", "cat config/prod.env"):
            self.assertTrue(engine.tool_hits(r, "Bash", {"command": cmd}), cmd)

    def test_more_ways_to_switch_kanit_off_are_denied(self):
        r = self.rules("tool.guardrails-read-only-shell")
        for cmd in ("mv ~/.claude/plugins{,.off}", "mv .kanit{,.bak}", "if true; then rm -rf .kanit; fi",
                    "{ rm -rf ~/.claude/hooks; }", "`rm -rf .kanit`", "trash ~/.claude/plugins",
                    "npx @anthropic-ai/claude-code plugin disable kanit@kanit", 'rm -rf "$CLAUDE_CONFIG_DIR/plugins"'):
            self.assertTrue(engine.tool_hits(r, "Bash", {"command": cmd}), cmd)
        self.assertEqual(engine.tool_hits(r, "Bash", {"command": "git rm --cached .claude/settings.local.json"}), [])

    def test_tool_rules_are_linear_on_one_huge_segment(self):
        # was quadratic: 60 KB of "dd " took 41 s, of PUSH + " -" 14 s, so only the time budget stopped them
        rules, _ = engine.load_rules(cli.packaged_rules())
        tool_rules = [r for r in rules if r["event"] == "tool" and engine.applies(r, "tool", "Bash")]
        for unit in ("dd ", PUSH + " -", "git -a ", "tee ", "find .claude ", "cu" + "rl x | ", "rm -rf x "):
            cmd = unit * (60000 // len(unit))
            t = time.time()
            engine.tool_hits(tool_rules, "Bash", {"command": cmd})
            self.assertLess(time.time() - t, 3.0, unit)

    def test_many_links_in_a_long_session_cost_one_pass(self):
        # was links x lines: 300 links in a 60,000-line session took 14 s and ended in "not checked"
        tp = os.path.join(self.tmp.name, "t.jsonl")
        with open(tp, "w") as f:
            f.write(json.dumps(human("go")) + "\n")
            for i in range(60000):
                f.write(json.dumps(tool_use("Bash", {"command": "echo %d" % i})) + "\n")
        urls = ["https://made.up/p%d" % i for i in range(300)]
        t = time.time()
        self.assertEqual(transcript.older_text_with(tp, urls), "")
        self.assertLess(time.time() - t, 2.0)


class ThirdAudit(Base):
    """Findings of the third audit pass (18 Nov 2026), each reproduced first."""

    def rules(self, rid):
        rules, _ = engine.load_rules(cli.packaged_rules())
        return [r for r in rules if r["id"] == rid]

    def test_long_argument_lists_still_deny(self):
        # a 2,000-character scan limit made these pass; the scans now stop only where their start repeats
        fetch = "cu" + "rl -fsSL "
        site = "https://" + "example.org/i.sh"
        cases = {
            "tool.no-force-push": PUSH + " origin " + " ".join("refs/tags/v1.%d" % i for i in range(150)) + " --force",
            "tool.no-hook-bypass": "git commit " + " ".join("-m line%d" % i for i in range(250)) + " --no-verify",
            "tool.no-disk-wipe": "dd if=/dev/zero bs=1M " + " ".join("conv=sync%d" % i for i in range(250)) + " of=/dev/sda",
            "tool.no-curl-pipe-shell": fetch + " ".join("-H X-%d:1" % i for i in range(250)) + " " + site + " | bash",
            "tool.guardrails-read-only-shell": "cp " + " ".join("f%d.json" % i for i in range(400)) + " .claude/settings.json",
            "tool.no-recursive-delete-home": "rm -rf " + " ".join("dir%d" % i for i in range(400)) + " ~",
        }
        for rid, cmd in cases.items():
            self.assertTrue(engine.tool_hits(self.rules(rid), "Bash", {"command": cmd}), rid)
        r = self.rules("tool.no-disk-wipe")
        self.assertTrue(engine.tool_hits(r, "Bash", {"command": "mkfs " * 1000 + "mkfs.ext4 /dev/sdb"}))

    def test_a_past_event_is_a_report_not_a_condition(self):
        done, tests = self.rules("reply.done-needs-action"), self.rules("reply.tests-pass-needs-run")
        for text in ("Once I pushed the fix, CI went green.", "When I deployed it the error went away."):
            self.assertTrue(engine.reply_hits(done, text, []), text)
        self.assertTrue(engine.reply_hits(tests, "When I ran it, all tests passed.", []))
        for text in ("Once it's deployed, ping me.", "If I deployed it now, the migration would run twice."):
            self.assertEqual(engine.reply_hits(done, text, []), [], text)
        self.assertEqual(engine.reply_hits(tests, "If the suite is green, the tests pass and you can merge.", []), [])

    def test_a_report_in_the_first_person_is_a_claim(self):
        r = self.rules("reply.tests-pass-needs-run")
        for text in ("I re-ran pytest and confirm all tests pass.", "I ran the suite to make sure all tests pass, and they do.",
                     "All tests pass, only with a deprecation warning.", "If I'm honest, all tests pass."):
            self.assertTrue(engine.reply_hits(r, text, []), text)
        for text in ("Pull the branch and make sure all tests pass.", "I'll fix the import and make sure all tests pass.",
                     "The README claims all tests pass on Windows, which I can't verify."):
            self.assertEqual(engine.reply_hits(r, text, []), [], text)


if __name__ == "__main__":
    unittest.main()
