# Contributing to RAYNSIS Inspector

Thank you for helping. Two kinds of reports matter most here, because they are the ones we cannot
find on our own fleet:

- **False alarm:** a rule fired on something harmless.
- **Miss:** a rule stayed quiet on something it is meant to stop.

For either, please send the exact input. `raynsis-inspector check` reproduces most cases without Claude Code:

```
raynsis-inspector check bash '<the command>'
raynsis-inspector check tool Edit --input '{"file_path": "...", "old_string": "...", "new_string": "..."}'
raynsis-inspector check reply '<the reply>' --turn 'Bash: {"command": "pytest"}'
```

Paste the command and its output into the issue. Remove secrets and private paths first.

## Changing or adding a rule

1. Edit `raynsis_inspector/rules/core.json` (or `tr.json` for Turkish reply rules).
2. Add at least one `hit` example and the `miss` examples that show what must stay quiet.
   A false-alarm fix should add the input that misfired as a `miss` example.
   Secret-looking examples (API keys, private key headers) must write one character as a JSON escape,
   for example `"ghp\u005f..."`, so GitHub secret scanning does not flag the rules file.
   The value RAYNSIS Inspector reads is unchanged, and a test fails if raw secret-looking text appears.
3. Run the checks:

   ```
   python3 -m raynsis_inspector test-rules
   python3 -m unittest discover -s tests -t .
   ```

4. If a rule's message changed, update the table in `README.md` with `python3 -m raynsis_inspector rules --markdown`
   (a test fails while they differ).

New rules should be general: useful in most repositories, cheap to evaluate, and quiet on normal work.
Team-specific rules belong in a project's `.raynsis-inspector/rules.json`.

## Code

- Python 3.9 and later, standard library only. No new dependencies.
- A hook must print at most one JSON object and must never crash silently: errors go through
  `audit.fail_loud`.
- Keep `engine.py` free of file and network access.

## Pull requests

Small and focused. Describe what misfired or was missed, and show `test-rules` and the unit tests passing.
By contributing you agree that your contribution is licensed under the Apache License 2.0.

Please follow the [code of conduct](CODE_OF_CONDUCT.md).
