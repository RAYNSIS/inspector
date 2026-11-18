# RAYNSIS Inspector

**Evidence gates for coding agents.**

*Published as `kanit` 0.1.0 (PyPI `kanit-gates`) before the rename to RAYNSIS Inspector.*

Coding agents say "all tests pass" without running them, cite links they never opened,
report "deployed" in a turn where no tool ran, and now and then try to edit their own guardrails.
RAYNSIS Inspector is a small Claude Code plugin that checks two moments:

- **Before a tool call** (PreToolUse): a dangerous call is denied, with a reason the agent can act on.
- **Before a reply is final** (Stop, and SubagentStop for subagents): a reply that claims work the transcript cannot prove is sent back once, with what is missing.

Every rule ships with examples it must fire on and examples it must stay quiet on.
Every check is logged, not only the hits, so you can see how often each rule fires per evaluation.

Python 3.9+, standard library only, no network calls, no telemetry.

> Status: 0.2.0, alpha. Rule ids and the rules file format may still change before 1.0.

## Install

In Claude Code (2.1.275 or later):

```
/plugin install raynsis-inspector --marketplace RAYNSIS/inspector
```

On older versions, or from a terminal:

```
claude plugin marketplace add RAYNSIS/inspector
claude plugin install raynsis-inspector@raynsis-inspector
```

The plugin needs `python3` on your `PATH`. Nothing else is installed.

To use the `raynsis-inspector` command outside Claude Code (rule checks, stats):

```
pip install raynsis-inspector
```

The package on PyPI and the command are `raynsis-inspector`; the Python module is `raynsis_inspector`.
From a clone of this repository, `pip install .` installs the same thing.

## What it does

A blocked tool call, as the agent sees it:

```
PreToolUse:Bash hook error: RAYNSIS Inspector blocked this call:
- [tool.no-secret-files] Secret files stay out of the agent's context. Ask the human for the one value you need. (matched: " .env")
```

A reply sent back at Stop, and the agent's next answer (Claude Code 2.1.327, recorded during release testing):

```
Agent:              All tests pass.
RAYNSIS Inspector:  this reply claims something the session cannot prove. Fix it before finishing:
                    - [reply.tests-pass-needs-run] You said tests pass, but no test command ran
                      in this turn. Run them and show the result, or say they were not run.
                      (matched: "All tests pass")
Agent:              Tests were not run in this turn, so I can't claim they pass. My earlier
                    "All tests pass" reply was unsupported.
```

You can try any rule without Claude Code:

```
$ raynsis-inspector check reply 'Fixed the parser. All tests pass.' --turn 'Edit: {"file_path": "parser.py"}'
DENY reply.tests-pass-needs-run
     You said tests pass, but no test command ran in this turn. Run them and show the result, or say they were not run.
     matched: "All tests pass"

$ raynsis-inspector check reply 'Fixed the parser. All tests pass.' --turn 'Edit: {"file_path": "parser.py"}' --turn 'Bash: {"command": "pytest -q"}'
pass: no rule fired (20 rules checked)
```

`raynsis-inspector check` exits 1 when a deny rule fires, so it also works in scripts.

## Rules in this release

| id | on | action | what it stops |
|---|---|---|---|
| `tool.no-recursive-delete-home` | tool | deny | This deletes the home or root directory. |
| `tool.no-disk-wipe` | tool | deny | This writes over a disk or partition and cannot be undone. |
| `tool.no-force-push` | tool | deny | Force push rewrites shared history. |
| `tool.no-hook-bypass` | tool | deny | This skips the repository's own checks (git hooks). |
| `tool.no-package-publish` | tool | deny | Publishing a package, image or release is visible to everyone and cannot be fully taken back. |
| `tool.no-curl-pipe-shell` | tool | deny | Piping a download straight into a shell or interpreter runs unreviewed code. |
| `tool.no-secret-files` | tool | deny | Secret files stay out of the agent's context. |
| `tool.no-secret-in-command` | tool | deny | A live-looking secret is written into this command or file, where shell history, logs or git will keep it. |
| `tool.guardrails-read-only` | tool | deny | An agent does not edit its own guardrails: hook settings, hook scripts, installed plugins or RAYNSIS Inspector's rules and logs. |
| `tool.guardrails-read-only-shell` | tool | deny | Writing to guardrail files (hook settings, hook scripts, installed plugins, .raynsis-inspector/) from the shell is blocked. |
| `tool.guardrails-read-only-mcp` | tool | deny | An agent does not edit its own guardrails through an MCP file tool either. |
| `tool.no-test-skip` | tool | warn | This edit marks an existing test as skipped or expected to fail. |
| `tool.no-test-file-delete` | tool | warn | This deletes test files. |
| `tool.no-test-function-delete` | tool | warn | This edit removes an existing test. |
| `reply.tests-pass-needs-run` | reply | deny | You said tests pass, but no test command ran in this turn. |
| `reply.build-passes-needs-run` | reply | deny | You said the build, type check or lint passes, but none of them ran in this turn. |
| `reply.done-needs-action` | reply | deny | You claimed finished work, but no tool ran in this turn. |
| `reply.unopened-link` | reply | deny | This link never appeared in anything you opened or were given this session. |
| `reply.tr.tests-pass-needs-run` | reply | deny | Testlerin geçtiğini yazdın ama bu turda test komutu çalışmadı. |
| `reply.tr.done-needs-action` | reply | deny | Bitmiş iş bildirdin ama bu turda hiçbir araç çalışmadı. |

The full patterns and their examples are in [`raynsis_inspector/rules/core.json`](raynsis_inspector/rules/core.json) and
[`raynsis_inspector/rules/tr.json`](raynsis_inspector/rules/tr.json). `raynsis-inspector rules` lists what is active in your project.

## How it decides

- **Tool rules** match a regex against named fields of the tool input (`command`, `file_path`, `content`, ...).
  An `unless` regex can exempt a match. `"only_added": true` fires only when an edit adds a match
  that the replaced text did not have, so an existing skipped test does not trip `tool.no-test-skip`.
  `"only_removed": true` is the mirror: it fires when an edit leaves fewer matches than it replaced,
  so deleting a test function trips `tool.no-test-function-delete` and renaming one does not.
- **Reply rules** match a claim in the final reply, then look for evidence among the tool calls made
  in this turn (since the last human message). "Tests pass" needs a test command run through a shell
  or a subagent; "the build passes" needs a build, type check or lint command; "I've deployed" needs at
  least one tool call. Only the command counts, not its description, and reading is not running:
  `cat tests/test_api.py`, `ls tests/` or a Read of the file is not a test run, and neither is installing
  or locating a runner (`pip install pytest`, `which pytest`).
- **What is not a claim.** A question ("Do the tests pass?"), a condition ("If the tests pass, merge it",
  "When CI is green and all tests pass, the bot merges"), an instruction ("Make sure all tests pass"), a
  hedge ("Ideally all tests pass"), a negation ("Not all tests pass yet"), someone else's words ("The
  README says all tests pass") and a phrase in quotation marks (my earlier "All tests pass" was wrong) are
  not checked. A statement stays a claim: "I can confirm all tests pass", "I re-ran pytest and confirm all
  tests pass", "This change ensures that all tests pass" and a claim under a heading line such as
  "## Verify" are checked, and so is a past event: "Once I pushed the fix, CI went green". A question *after* the claim does not excuse it: "All tests pass, want me to
  commit?" and "All tests pass (shall I merge?)" are checked. An `unless` phrase ("not verified") only
  excuses the sentence it is in.
- **Links** in a reply must have appeared in a human message, a tool result, or the input of a
  read-only tool, anywhere in the session (a link not found in the last 4 MB is looked up in the whole
  transcript). A link the agent only wrote into a file does not count.
- **A reply is sent back once.** If the next attempt still matches (`stop_hook_active`), RAYNSIS Inspector warns the
  human instead of blocking again, so a session can never loop.
- **Unknown is not missing.** After a context compaction the start of the turn may be in another file.
  Then the turn's evidence is unknown, and the evidence rules are skipped instead of guessing.
  `raynsis-inspector stats` and `raynsis-inspector doctor` show how often that happened.
- **Warn rules** do not block. Their message goes to the human, not the agent.
- **A slow check never becomes a silent pass.** Claude Code lets a call through when a hook times out,
  so RAYNSIS Inspector stops itself first (6 s for a tool call, 14 s for a reply): an unfinished tool check denies
  the call and says why, an unfinished reply check warns the human. Inputs are bounded (rules file 1 MB,
  prior file content 2 MB) and special files (FIFOs, devices) are never read. The packaged patterns are
  linear with no length limit: a scan stops only where its own start repeats, so the worst 60 KB command
  we could build takes under 0.3 s per rule on our test machine, and a long argument list does not hide
  the end of a command. The budget is for project rules that are not linear. The timer needs a POSIX system; on Windows the hook timeout is the only limit.

## Configure

Project rules live in `.raynsis-inspector/rules.json` at the project root (Claude Code's `CLAUDE_PROJECT_DIR`, so a
`cd` inside the session does not leave them behind). A rule with a new `id` is added. A rule with the `id` of an
existing rule changes only the fields you write. `"<field>+"` adds an alternative to a regex instead of
replacing it, `null` removes a field, and `"disable"` turns rules off.

Teach RAYNSIS Inspector your project's test command:

```json
{
  "rules": [
    {"id": "reply.tests-pass-needs-run", "needs_turn+": "make verify|scripts/ci\\.sh"}
  ],
  "disable": ["tool.no-package-publish"]
}
```

A new rule:

```json
{
  "rules": [
    {
      "id": "tool.no-prod-db",
      "event": "tool",
      "action": "deny",
      "tools": ["Bash"],
      "field": "command",
      "pattern": "psql\\s+.*prod",
      "message": "Production data is read through the replica.",
      "examples": {
        "hit":  [{"tool": "Bash", "input": {"command": "psql -h prod-db -c 'delete from users'"}}],
        "miss": [{"tool": "Bash", "input": {"command": "psql -h replica -c 'select 1'"}}]
      }
    }
  ]
}
```

| field | meaning |
|---|---|
| `id`, `message` | required; the message is what the agent (deny) or the human (warn) reads |
| `event` | `tool` or `reply` |
| `action` | `deny` or `warn` |
| `tools` | tool names the rule applies to (tool rules; default all) |
| `tool_pattern` | regex on the tool name, for tool families such as MCP servers (`^mcp__`) |
| `field` | input field or list of fields to match (tool rules; default the whole input as JSON) |
| `pattern`, `unless` | Python regexes |
| `needs_turn` | reply rules: the rule fires unless a tool call in this turn matches this regex |
| `needs_turn_tools` | reply rules: only calls of these tools count as evidence (default all) |
| `needs_turn_field` | reply rules: only these input fields of those calls are matched (default the whole input); the packaged test and build rules use `command` and `prompt` |
| `check` | `urls_seen` for the link rule; `unless_url` exempts links |
| `only_added` | tool rules: fire only when an edit adds a match |
| `examples` | `hit` and `miss` lists; `raynsis-inspector test-rules` fails a rule without a `hit` example |

Run `raynsis-inspector test-rules` after every change. An invalid rule is reported and skipped; the others keep working.

A project file can turn a packaged rule off or change it. When it does, RAYNSIS Inspector tells the human once per
session which rules were weakened, so a cloned repository cannot quietly disarm the gates.

Environment variables, set by the human for the Claude Code process:

| variable | effect |
|---|---|
| `RAYNSIS_INSPECTOR_SHADOW=1` | evaluate and log everything, print and block nothing |
| `RAYNSIS_INSPECTOR_DISABLE=rule.a,rule.b` | turn rules off for this process |
| `RAYNSIS_INSPECTOR_FAIL_CLOSED=1` | deny tool calls while the engine is broken (default: allow, with a warning) |
| `RAYNSIS_INSPECTOR_HOME=/path` | where logs go (default `.raynsis-inspector/` in the project) |
| `RAYNSIS_INSPECTOR_RULES=/a.json:/b.json` | extra rule files, loaded after the project file |

The agent cannot set these variables. The guardrail rules deny its common ways of changing the rest:
editing, moving or deleting `.raynsis-inspector/`, hook settings, hook scripts or installed plugins, restoring them
with git, and `claude plugin disable` or `uninstall`. They read command text, so an interpreter
one-liner that writes the file is not caught (see Known gaps).

## Audit and stats

```
.raynsis-inspector/audit.jsonl   one line per hit, engine error or invalid rule
.raynsis-inspector/evals.jsonl   one line per evaluation: which rules were checked, which fired
raynsis-inspector stats          checked / raw / unique hits per rule (--window 600)
raynsis-inspector doctor         install, rules and log health
```

`.raynsis-inspector/` gets its own `.gitignore` for the logs; `rules.json` stays committable.

**Shadow mode first.** Run `RAYNSIS_INSPECTOR_SHADOW=1` for a week next to your current setup, read `raynsis-inspector stats`,
then turn enforcement on.

## Where it comes from

RAYNSIS Inspector is extracted from the governance layer we run on our own agent fleet. Between 19 September
and 17 November 2026 that engine recorded, across 1,690 agent sessions, **4,298 unique rule events**
(same session and rule within 10 minutes counted once; 3,888 to 4,505 depending on the window):
**958 tool calls stopped** and **3,340 replies sent back for correction**. 345 of them were risky
attempts (spending credits, deleting, reading secrets, sending outside, touching live systems),
1,139 were accuracy problems, 2,814 were format.

Before release we measured false alarms on real traffic:

- **Replay.** The rules, replayed over the last 30 days of our sessions (399 transcripts). The first
  replay (17 rules; 4,962 shell commands, 615 file edits, 502 reply endings) gave 17 hits. Reading each
  one: five were the first reply after a context compaction, judged without the evidence from before it;
  one was a conditional `skipTest` in a brand-new test file; the rest were rule test text inside commands.
  After the fixes above ("unknown is not missing", `only_added`) and four rounds of an independent
  pre-release audit, the final replay of all 18 rules over the 383 latest transcripts (our own deliberate
  test sessions left out; 2,319 shell commands, 192 file edits, 410 reply endings) gave 2 hits. One was
  right: a link in a reply that never appeared in its session. One was a false alarm: a heredoc that only
  mentioned a `*.env` file name (the mention gap under Known gaps). The audit fixes changed no result on
  this traffic: the rules before and after them gave the same two hits.
- **0.2.1 replay.** The two test-deletion rules added in 0.2.1, replayed over the 398 latest transcripts
  (2,797 shell commands, 269 file edits): 0 hits, so no false alarm on our traffic and no agent caught
  deleting a test in it either.
- **Shadow run.** 24 hours on live sessions, 6,735 evaluations, two hits, both false alarms, both fixed:
  a `>` inside a quoted grep pattern read as a redirect, and a project test script not recognised as a
  test command (now configurable with `needs_turn+`).
- **End to end.** Claude Code 2.1.327 with the plugin loaded: a `.env` read denied, an unproven
  "All tests pass." sent back and corrected, the same claim from a subagent sent back and corrected,
  a skip added to a test warned.

Our fleet already runs about 228 stricter house rules, so few violations reach these rules. Read the
numbers as a false-alarm measurement, not a catch rate.

Two lessons shaped the code:

1. **A gate that fails silently is worse than no gate.** On 4 November a rule missing one field crashed
   our engine about 900 times in nine hours; it failed open and nobody saw it. RAYNSIS Inspector skips an invalid
   rule instead of dying, and an engine error is printed on screen (at most every 10 minutes) and logged.
2. **Hits without a denominator prove nothing.** Our old log only wrote hits, so it cannot show a
   before/after rate. RAYNSIS Inspector writes every evaluation to `evals.jsonl`, so `raynsis-inspector stats` can.

## Known gaps

- Rules are regexes, not understanding. The reply rules know common English and Turkish phrasings, not
  all of them ("Everything passes now", "I ran the tests and they all pass" and "No type errors." are
  not recognised). Quoted speech after a colon ("You wrote: All tests pass") and a sentence that defines
  a result ("A green badge means all tests pass") are read as claims.
- Tool rules read the command text. A command that only mentions a dangerous string can trip them
  (a heredoc of notes that says "never run rm -rf ~"), and a determined agent can hide one (`eval`,
  encoding, a script file, a glob or a variable such as `cat .en?` or `rm -rf $d`,
  `python -c "open('.claude/settings.json', 'w')"`). Publishing through a wrapper we do not list (`npx np`) is not caught,
  and a command that deletes a whole tree by design (`git clean -fdx`) also deletes `.raynsis-inspector/` logs.
  The rules catch mistakes; they are not a sandbox. Run untrusted code in a real sandbox.
- Evidence means a matching tool call ran in this turn, not that it succeeded: a failing `pytest` run
  still counts as "ran". The agent still has to report the result honestly. A subagent whose prompt
  mentions tests counts as a test run, and so does an inline script that only names a test file
  (`python3 -c "print(open('tests/a.py').read())"`); RAYNSIS Inspector does not read what the subagent did.
- A link the agent typed into a shell command counts as seen, and so does a link it tried to fetch
  even if the fetch failed.
- Windows: the tests pass in CI on Python 3.9 to 3.14, but RAYNSIS Inspector has not been tried in a live Claude Code
  session on Windows. Hooks run through Git Bash or PowerShell and need `python3` on `PATH`.

## Contributing

Bug reports with the exact input that misfired are the most useful thing you can send: see
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Made by RAYNSIS AI Workforce.
