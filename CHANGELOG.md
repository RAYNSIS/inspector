# Changelog

All notable changes to RAYNSIS Inspector (named kanit up to 0.1.0). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.5

The first report from a Windows machine: after install every tool call printed a hook error and nothing
was checked. The hooks called `python3`, which on a python.org install is a Microsoft Store shortcut
that prints an install hint and fails; the real interpreter there is `python`.

- Hooks now start through `hooks/run.sh`, a POSIX shell launcher that finds a working Python 3.9+:
  a real `python3` is used directly, a `python3` under `WindowsApps` is probed first, then `python`,
  then `py -3`. With none it says so on stderr and prints no decision.
- `.gitattributes` keeps the launcher's line endings LF, so a Windows checkout with `core.autocrlf` cannot break it.
- CI runs the launcher under Git Bash on Windows, once as is and once behind a dead `python3` shortcut.
- README: the install note and the Windows limitation say what is needed (Git for Windows, any of the
  three Python names) and what is still unconfirmed (a live Windows session).

No rule or engine change. Cost on our test machine: the extra shell adds about 8 ms to a hook call.

## 0.2.4

- README: a "Try it in the first minute" step right under Install. Rules fire rarely in ordinary work
  (in our own logs, 19 hits in 395 sessions over 30 days), so a new install looked like it did nothing.
  The step is one prompt that makes a gate speak; a test keeps the documented command a deny.
- The plugin icon: `.claude-plugin/icon.png`, a square 1024 px PNG. A test reads its size from the file.
- README status line no longer names a single old version.

No rule or engine change.

## 0.2.3

Suggested by a reader: count which rules fire most to see where the agent cuts corners. `stats` already
did the counting; reading our own table showed what it lacked.

- `raynsis-inspector stats` takes `--exclude-session PREFIX` (repeatable) and `--since DAYS`. Both filter
  the checks and the hits together, so the rate stays honest. Sessions that test the rules fire them on
  purpose: in our own log they were 128 of 144 hit lines and led the table. Output without the flags is
  unchanged.

## 0.2.2

Security pass: a source review of the engine and all 20 rules. Every item below was reproduced with a
local probe first, then fixed with examples and tests.

Rules that could be passed with an ordinary command:

- `tool.no-package-publish` excused anything containing `--dry-run` or ` -n `. `npm publish --dry-run=false`,
  `gh release create v1 -n "notes"` (`-n` is `--notes`), `npm publish # --dry-run` and a quoted
  `'--dry-run'` were all let through as dry runs. `-n` now counts only for `cargo publish`, `=false` is a
  real publish, and a flag inside a comment or quotes is ignored. `cargo publish -n` at the end of a
  command is no longer denied.
- Shell rules listed `Bash` and `PowerShell` only. The `Monitor` tool also runs a shell command, and
  `rm -rf ~`, a force push or a publish through it passed every rule. All eight shell rules now list it.
- `tool.no-recursive-delete-home` missed `rm ~ -rf` (flags last, GNU), `rm -rf $HOME/..`,
  `find ~ -delete`, `find / -exec rm` and PowerShell (`Remove-Item -Recurse -Force ~`,
  `rm -r -fo $env:USERPROFILE`, `Remove-Item C:\ -Recurse`). A `find` narrowed by `-name`, `-mtime`,
  `-empty` and the like is left alone.
- `tool.no-hook-bypass` now also denies removing or disarming the hook itself: `rm .git/hooks/pre-commit`,
  `chmod -x .git/hooks/pre-commit`, `mv .husky .husky.off`. `*.sample` hooks and `chmod +x` are fine.
- `tool.no-test-file-delete` now also warns on emptying a test file (`: > tests/test_a.py`,
  `truncate -s 0`, `cp /dev/null`, `echo '' >`), `shred`, moving it out of the runner's sight
  (`mv tests/test_a.py /tmp/`, renaming it to a non-test name) and `find tests ... -delete`.
- `tool.guardrails-read-only-shell` now also denies `dd of=`, `curl -o` and `wget -O` into guardrail
  files, and `pip uninstall raynsis-inspector`.
- `tool.no-secret-files` now also covers `~/.config/gh/hosts.yml` and `~/.docker/config.json`.

Engine:

- The running package is a guardrail wherever it is installed. `tool.guardrails-read-only` matched
  `.claude/plugins/` paths only, so with a pip install or a `--plugin-dir` checkout the agent could edit
  `rules/core.json` or `engine.py` with the Edit tool, and no "rules were weakened" notice followed
  because the notice compares against that same file. Edit, Write, MultiEdit and NotebookEdit on the
  running package (and on a checkout's `hooks/`, `bin/`, `.claude-plugin/`) are now denied.
- `failure.json` is no longer trusted. It lives in the project, so a cloned repository can ship one:
  timestamps in the future silenced the engine-error warning for good, and a file with mixed types
  crashed the throttle and with it the hook. Future times, wrong types, oversized files and links to
  devices now read as "never warned".

Not changed, by design (see Known gaps in the README): deploy tools, `git push --delete`, `env` and
`printenv`, and anything hidden behind `eval`, a variable, a glob or an interpreter one-liner.

## 0.2.1

Two warn rules for the agent that turns a failing suite green by deleting the test.

- `tool.no-test-file-delete`: `rm`, `git rm`, `unlink`, `del` or `Remove-Item` on a test file
  (`test_*.py`, `*_test.go`, `*.test.ts`, `*.spec.js`, `FooTest.java`, ...) or a whole `tests/`,
  `__tests__/` or `spec/` folder. `git rm --cached` and caches such as `tests/__pycache__` are left alone.
- `tool.no-test-function-delete`: an Edit, MultiEdit or Write that leaves fewer test definitions
  (`def test_*`, `func Test*`, `it(...)`, `test(...)`, `@Test`) than the text it replaces. Renaming or
  moving a test inside one edit does not count.
- Rules can now say `"only_removed": true`, the mirror of `"only_added"`: the rule fires only when the
  replaced text has more matches than the new text.

Both rules warn and never block: deleting a test can be the right change, so the agent is told to
say which test and why.

## 0.2.0

Renamed from kanit to RAYNSIS Inspector. No rule behaviour changed.

- PyPI package: `kanit-gates` → `raynsis-inspector`.
- Command: `kanit` → `raynsis-inspector`; `python -m kanit` → `python -m raynsis_inspector`.
- Python module: `kanit` → `raynsis_inspector`.
- Claude Code plugin and marketplace: `kanit@kanit` → `raynsis-inspector@raynsis-inspector`;
  the hook launcher `bin/kanit` → `bin/raynsis-inspector`.
- Repository: `RAYNSIS/kanit` → `RAYNSIS/inspector` (GitHub redirects the old links).
- Project folder: `.kanit/` (`rules.json`, audit logs, `failure.json`) → `.raynsis-inspector/`.
- Environment variables: `KANIT_SHADOW`, `KANIT_DISABLE`, `KANIT_FAIL_CLOSED`, `KANIT_HOME`, `KANIT_RULES`
  → `RAYNSIS_INSPECTOR_SHADOW`, `RAYNSIS_INSPECTOR_DISABLE`, `RAYNSIS_INSPECTOR_FAIL_CLOSED`,
  `RAYNSIS_INSPECTOR_HOME`, `RAYNSIS_INSPECTOR_RULES`.
- Messages begin with "RAYNSIS Inspector" instead of "kanit".
- The guardrail rules protect `.raynsis-inspector/` exactly as they protected `.kanit/`; rule ids are
  unchanged, and their examples use the new names (plus `claude plugin disable raynsis-inspector`).

Upgrading from kanit 0.1.0: the old names are not read. Move `.kanit/rules.json` to
`.raynsis-inspector/rules.json`, rename any `KANIT_*` variables, and replace the plugin
(`kanit@kanit` → `raynsis-inspector@raynsis-inspector`) or the pip package (`kanit-gates` →
`raynsis-inspector`).

## 0.1.0 (published as kanit, PyPI `kanit-gates`)

First public release.

- Claude Code plugin: PreToolUse, Stop and SubagentStop hooks, one bundled launcher, no dependencies.
- A subagent's reply is judged on the subagent's own transcript.
- 16 core rules and 2 Turkish reply rules, each with `hit` and `miss` examples checked by `kanit test-rules`.
- Reply rules send a reply back once and then only warn, so a session never loops.
- Evidence rules are skipped when the start of the turn is not in the transcript (after a compaction).
- Project rules in `.kanit/rules.json`: add rules, change one field of a packaged rule, extend a regex
  with `"<field>+"`, remove a field with `null`, `"disable"` rules.
- `only_added` for tool rules: fire only when an edit adds a match.
- Audit log of hits and of every evaluation; `kanit stats` reports checked, raw and unique hits per rule.
- Commands: `kanit check`, `kanit rules`, `kanit test-rules`, `kanit stats`, `kanit doctor`.
- Shadow mode (`KANIT_SHADOW=1`), fail-closed mode (`KANIT_FAIL_CLOSED=1`), loud and rate-limited
  warnings when the engine fails.

Hardening from the pre-release security review, each with a regression test in `tests/test_security.py`:

- Time budget: a tool check that cannot finish in 6 s denies the call instead of timing out open;
  a reply check that cannot finish in 14 s warns the human.
- The home-delete pattern no longer backtracks exponentially on long option lists.
- The rules file, prior file content and transcripts are read only if they are regular files and
  within size limits; a FIFO or `/dev/zero` cannot hang the hook.
- Logs are written as ASCII JSON with `O_NOFOLLOW`; a lone surrogate in a command no longer drops a deny,
  and a planted symlink in `.kanit/` is not followed. Logs rotate at 20 MB.
- A malformed project file (`"disable": 5`, a non-string regex extension) is reported and skipped;
  the packaged rules keep enforcing. A project file that disables or changes a packaged rule is
  announced to the human once per session.
- Reading or searching a test file no longer counts as running tests (`needs_turn_tools`).
- An `unless` phrase only excuses the sentence it appears in; a claim in quotation marks is a mention.
- Links: `user@host` cannot borrow an exempt host, a shorter prefix of a seen link is not the link,
  and links in a todo list are not "seen".
- A turn longer than 4 MB is followed back up to 64 MB before its evidence is called unknown.
- Guardrail files are protected from MCP file tools too (`tool.guardrails-read-only-mcp`, `tool_pattern`).
- Each distinct engine error has its own warning throttle, so a second error is not hidden by the first.

Fixes from the independent pre-release audit, with a test or a rule example for each:

- The agent can no longer switch kanit off from the shell: `claude plugin disable|uninstall`, deleting or
  moving `~/.claude/plugins`, `~/.claude/hooks`, `.claude` or `.kanit` (no trailing slash needed),
  `git checkout -- .kanit/rules.json` and `find .kanit -delete` are denied.
- Reply rules no longer read conditions, instructions and negations as claims ("If the tests pass,
  merge it", "Make sure all tests pass", "Not all tests pass yet", "Testler geçtiğinde"). A question
  only excuses its own clause: "All tests pass, want me to commit?" is checked.
- Evidence: `cat`, `ls`, `grep` and other read-only shell commands on test files are not test runs, and a
  Bash call's `description` is ignored (new rule field `needs_turn_field`).
- More claims recognised: "The test suite passes", "pytest is green", "All checks pass", "Deployed to
  production.", "Merged.", "The fix is deployed", "Testler başarıyla geçti", "Commit ettim". Fewer false
  claims: "I've pushed back", "fixed-width", "fixed by design", "I fixed that last week".
- Tool rules catch `cat .env;echo` and `glob: ".env*"`, `*.env` files, `git -C repo push --force`,
  `git push --mirror`, `git commit -n`, `git config core.hooksPath`, `python -m twine upload`,
  `NPM_TOKEN=x npm publish`, `docker image push`, `docker buildx build --push`, `gh release upload`,
  `bash <(curl ...)`, `sh -c "$(curl ...)"`, `rm -rf ${HOME}` and `rm -rf ./build ~`; and no longer
  fire on `./gradlew publishToMavenLocal`, `mvn -Dmaven.deploy.skip=true`, a push to a local registry,
  `curl ... | python3 script.py`, `cp .env.example .env` or `--env-file .env`.
- An `unless` on a tool rule only excuses its own command segment.
- Project rules and logs are found at `CLAUDE_PROJECT_DIR`, not the shell's current directory.
- A link given early in a long session is found in the whole transcript, not only in the last 4 MB.
- `kanit stats` and `kanit doctor` report reply checks whose turn could not be read.

Fixes from the second audit pass, with a test or a rule example for each:

- Every packaged tool pattern is linear with no length limit. A scan stops only where its own start
  repeats, so 60 KB of `dd dd dd ...` takes milliseconds instead of 41 s, the worst 60 KB command we built
  takes under 0.3 s per rule, and every command the old patterns denied is still denied (560 commands
  compared, long argument lists included). The 6 s budget remains for project rules.
- A link check in a long session reads the transcript once, whatever the number of links: 300 links in
  a 60,000-line session took 14 s and ended in "not checked".
- A statement is a claim even with a verb of checking in it: "I can confirm all tests pass", "This change
  ensures that all tests pass", and a claim under a heading line ("## Verify"). Instructions ("Please make
  sure all tests pass"), hedges ("Ideally", "In theory", "The goal is that"), conditional clauses ("When CI
  is green and all tests pass, ...") and "only if" conditions are not claims.
- A dash, a bracket or "so" ends a claim's clause: "All tests pass (did you see the CI run?)" is checked.
- More claims recognised: "I just deployed it", "We've deployed the hotfix", "It's been merged", "Deploy
  complete", "Hotfix is live", "128 passed, 0 failed", "Tests: OK", "Build: successful", "Compiles without
  warnings", "No lint errors remain", "Testler sorunsuz geçti", "Sürümü yayınladık". Turkish "kurdum" is
  a claim only for an install ("Paketi kurdum"), not "Bir plan kurdum".
- Evidence: installing or locating a runner (`pip install pytest`, `npm install --save-dev jest`,
  `which pytest`), `nl`, `sudo cat` and `time ls` are not test runs, and `ruff check` is not a test run.
- `.env` files: `.ENV`, `.env.production.local`, `.env.local.bak` and `.env~` are caught; `process.env`
  and `import.meta.env` in a search are not a file.
- Guardrails catch brace expansion (`mv .kanit{,.bak}`), commands after `then`, `do`, `{` or a backtick,
  `trash`, `npx @anthropic-ai/claude-code plugin disable` and `$CLAUDE_CONFIG_DIR`; `git rm --cached` of a
  settings file is allowed.
- Tool rules catch `rm -rf "$HOME"/*`, `"${HOME:?}"/*`, `~/{*,.*}`, `cd ~ && rm -rf *`, a quoted
  `"+main"` or `"--force"` push, `| bash /dev/stdin`, `` bash -c "`curl ...`" ``, `curl ... | grep ... | sh`
  and `env -u VAR npm publish`; and no longer fire on `git commit -uno` or `SKIP=1 git status`.

Fixes from the third audit pass:

- A past event after "once", "when", "after" or "before" is a report, not a condition: "Once I pushed the
  fix, CI went green" and "When I ran it, all tests passed" are checked; "If I deployed it now, ..." is not.
- A first-person report is a claim: "I re-ran pytest and confirm all tests pass", "I ran the suite to make
  sure all tests pass, and they do". "All tests pass, only with a deprecation warning" is a claim; only
  "only if/when/after" right after the claim makes it a condition.
- Not claims: a sentence opened by a present-tense condition ("If the suite is green, the tests pass and
  you can merge"), someone else's words ("The README claims ..."), "I haven't checked", "which I can't
  verify", "according to", "in the ideal case", and "asks you to state that all tests pass".
- `git commit -m "a message" -n` is caught: an option may take one argument before the `-n`.
- `rm -rf` with a long list of paths that ends in `~` is caught (the old patterns stopped after 64 paths).

Fixes from the fourth audit pass:

- More claims: "Bütün birim testleri başarıyla geçiyor", "The suite has been green for three runs", "The flaky
  test is fixed", "The bug is resolved".
- Not claims: definitions ("Tests pass or fail per shard", "The suite passes when every required check
  reports success"), and a done claim whose sentence says "I haven't checked", "upstream" or "in 3.1".
