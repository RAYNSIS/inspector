# Security policy

## Reporting

Please report security problems privately through GitHub: the **Security** tab of this repository,
then **Report a vulnerability**. Do not open a public issue for them.

We aim to acknowledge a report within 3 working days and to ship a fix or a documented mitigation
within 30 days.

## What counts as a security problem

- RAYNSIS Inspector fails open without saying so: a crash, hang or timeout that lets a call through with no warning.
- A regex that can be made slow enough to hit the hook timeout (ReDoS) and let a call through.
  The packaged tool patterns are meant to be linear: the worst 60 KB command we could build takes under
  0.3 s per rule on our test machine. An input that makes a packaged pattern slow is in scope. On POSIX
  the 6 s budget interrupts any match (a slow project rule included) and denies the call; a slow input
  that is *allowed* after the budget, or any slowness on Windows, is in scope.
- Output injection: input that changes the hook decision RAYNSIS Inspector prints, or adds fields to it.
- A way for the agent to edit RAYNSIS Inspector's own rules or logs, or the hook settings, that the guardrail rules should catch.
- RAYNSIS Inspector reading, logging or sending data it should not (it makes no network calls).

## What is a normal issue

Tool rules are regexes over command text; they catch mistakes and are not a sandbox (see
"Known gaps" in the README). A new phrasing that slips past a rule is useful to know: please open a
regular issue with the input, labelled as a miss.

## Supported versions

Security fixes go into the latest release.
