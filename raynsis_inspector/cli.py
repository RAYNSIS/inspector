"""Command line: hook | test-rules | stats | doctor."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import sys
import time

from . import __version__, audit, engine, transcript

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
CORE_RULES = os.path.join(RULES_DIR, "core.json")


def packaged_rules() -> list:
    """core.json first, then the other packaged rule sets (e.g. tr.json) in name order."""
    extra = sorted(os.path.join(RULES_DIR, f) for f in os.listdir(RULES_DIR) if f.endswith(".json") and f != "core.json")
    return [CORE_RULES] + extra


def shadow() -> bool:
    """RAYNSIS_INSPECTOR_SHADOW=1: evaluate and log everything, print nothing.
    For trying RAYNSIS Inspector on real traffic."""
    return os.environ.get("RAYNSIS_INSPECTOR_SHADOW") == "1"


def rule_paths() -> list:
    """Packaged rules, then project rules (.raynsis-inspector/rules.json), then RAYNSIS_INSPECTOR_RULES (os.pathsep list)."""
    paths = packaged_rules()
    project = os.path.join(audit.project_dir(), ".raynsis-inspector", "rules.json")
    if os.path.exists(project):
        paths.append(project)
    paths.extend(p for p in os.environ.get("RAYNSIS_INSPECTOR_RULES", "").split(os.pathsep) if p)
    return paths


def _disabled() -> list:
    # set by the human in the environment of the hook process; the agent cannot change it
    return [x.strip() for x in os.environ.get("RAYNSIS_INSPECTOR_DISABLE", "").split(",") if x.strip()]


def _emit(obj: dict) -> None:
    # ASCII-only JSON: the hook's stdout may use any code page (cp1252 on Windows); \uXXXX always prints
    print(json.dumps(obj, ensure_ascii=True))


def _read_payload(stream) -> dict:
    """Claude Code sends UTF-8. Read bytes when we can, so the console code page never decides."""
    buf = getattr(stream, "buffer", None)
    raw = buf.read().decode("utf-8", "replace") if buf is not None else stream.read()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("hook payload is not a JSON object")
    return payload


PRIOR_MAX_BYTES = 2 * 1024 * 1024
# Claude Code lets a call through when a hook times out (10 s PreToolUse, 20 s Stop here), so RAYNSIS Inspector
# stops itself first and decides on purpose instead of timing out open.
BUDGET_S = {"PreToolUse": 6.0, "Stop": 14.0, "SubagentStop": 14.0}
DEFAULT_BUDGET_S = 6.0


class OverBudget(Exception):
    """Raised by the timer when evaluation takes longer than the event's budget."""


def _arm(seconds: float) -> None:
    if not hasattr(signal, "setitimer"):  # Windows: no interval timer, Claude Code's own timeout applies
        return

    def _expired(signum, frame):
        raise OverBudget()

    signal.signal(signal.SIGALRM, _expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)


def _disarm() -> None:
    if hasattr(signal, "setitimer"):
        signal.setitimer(signal.ITIMER_REAL, 0)


def with_prior(tool_input: dict) -> dict:
    """For a Write that replaces an existing file, add its current text as "_prior", so "only_added"
    rules compare against what is already there. Missing, unreadable, special (FIFO, device) or very
    large files count as empty."""
    path = tool_input.get("file_path")
    if "content" not in tool_input or not isinstance(path, str) or not path:
        return tool_input
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > PRIOR_MAX_BYTES:
            return tool_input
        with open(path, encoding="utf-8", errors="replace") as f:
            return dict(tool_input, _prior=f.read(PRIOR_MAX_BYTES + 1))
    except (OSError, ValueError):
        return tool_input


def weakened(rules: list) -> list:
    """Packaged rules that project files or RAYNSIS_INSPECTOR_RULES turned off or changed (RAYNSIS_INSPECTOR_DISABLE is the
    human's own switch and is not counted). The agent may find a way to write .raynsis-inspector/rules.json, so
    the human is told whenever it weakens the packaged set."""
    base = {r["id"]: r for r in engine.load_rules(packaged_rules())[0]}
    final = {r["id"]: r for r in rules}
    return sorted(rid for rid in base if final.get(rid) != base[rid])


def _weakened_note(session: str) -> str:
    extra = rule_paths()[len(packaged_rules()):]
    if not extra:
        return ""
    ids = weakened(engine.load_rules(rule_paths())[0])
    if not ids:
        return ""
    digest = hashlib.sha256()
    for p in extra:
        try:
            digest.update(engine.read_rules_file_bytes(p))
        except (OSError, ValueError):
            digest.update(p.encode("utf-8", "replace"))
    text = ("RAYNSIS Inspector: project rules turn off or change %d packaged rule(s): %s. If you did not make this change, "
            "check %s." % (len(ids), ", ".join(ids[:8]) + (" ..." if len(ids) > 8 else ""), ", ".join(extra)))
    return audit.notice(session + ":" + digest.hexdigest(), text)


def run_hook(payload: dict) -> int:
    if payload.get("cwd") and isinstance(payload["cwd"], str) and os.path.isdir(payload["cwd"]):
        os.chdir(payload["cwd"])
    event_name = payload.get("hook_event_name", "")
    session = str(payload.get("session_id", ""))
    rules, errors = engine.load_rules(rule_paths(), _disabled())
    note = audit.rule_errors(errors)
    extra_log = {}

    if event_name == "PreToolUse":
        event, tool = "tool", str(payload.get("tool_name", ""))
        applicable = [r for r in rules if engine.applies(r, event, tool)]
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {}
        if any(r.get("only_added") for r in applicable):
            tool_input = with_prior(tool_input)
        hits = engine.tool_hits(applicable, tool, tool_input)
    elif event_name in ("Stop", "SubagentStop"):
        event = "reply"
        applicable = [r for r in rules if engine.applies(r, event)]
        # a subagent's reply is judged on the subagent's own transcript
        path = payload.get("agent_transcript_path") or payload.get("transcript_path") or ""
        path = path if isinstance(path, str) else ""
        reply = payload.get("last_assistant_message")
        reply = reply if isinstance(reply, str) and reply else transcript.last_reply(path)
        acts, started = transcript.turn_state(path)
        if not started:
            # the turn began outside what we can read (compaction, very long turn): its evidence is
            # unknown, so rules that need this turn's tool calls are not applied rather than misfiring
            applicable = [r for r in applicable if not r.get("needs_turn")]
            extra_log["turn_unknown"] = True
        turn = ["%s: %s" % (a["tool"], a["text"]) for a in acts]
        seen = transcript.session_text(path) if any(r.get("check") == "urls_seen" for r in applicable) else ""
        hits = engine.reply_hits(applicable, reply, turn, seen)
        if any(r.get("check") == "urls_seen" for r, _ in hits) and transcript.longer_than_tail(path):
            # a link given early in a long session is outside the tail we read: look it up in the whole file
            seen += "\n" + transcript.older_text_with(path, engine.URL_RE.findall(reply))
            hits = engine.reply_hits(applicable, reply, turn, seen)
    else:
        if note and not shadow():
            _emit({"systemMessage": note})
        return 0

    audit.log_eval(session, event, [r["id"] for r in applicable], [r["id"] for r, _ in hits], **extra_log)
    for r, excerpt in hits:
        audit.log_hit(session, event, r, excerpt, shadow=shadow())
    if shadow():
        return 0
    out = engine.decide(hits, event, bool(payload.get("stop_hook_active"))) or {}
    for extra in (note, _weakened_note(session)):
        if extra:
            out["systemMessage"] = (out.get("systemMessage", "") + "\n" + extra).strip()
    if out:
        _emit(out)
    return 0


def _over_budget(payload: dict) -> int:
    event_name = payload.get("hook_event_name", "") if isinstance(payload, dict) else ""
    budget = BUDGET_S.get(event_name, DEFAULT_BUDGET_S)
    audit._append("audit.jsonl", {"session": str(payload.get("session_id", "")) if isinstance(payload, dict) else "",
                                  "event": "over_budget", "hook": event_name, "budget_s": budget})
    if shadow():
        return 0
    if event_name == "PreToolUse":
        _emit({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": ("RAYNSIS Inspector could not finish checking this call within %.0f s "
                                         "(a very large or unusual input). Split the command, or write long "
                                         "content with the Write tool." % budget)}})
    else:
        _emit({"systemMessage": "RAYNSIS Inspector warning: this reply could not be checked within %.0f s "
                                "and was not checked." % budget})
    return 0


def hook(stream=None) -> int:
    payload = {}
    try:
        _arm(DEFAULT_BUDGET_S)
        payload = _read_payload(stream or sys.stdin)
        _arm(BUDGET_S.get(payload.get("hook_event_name"), DEFAULT_BUDGET_S))
        return run_hook(payload)
    except OverBudget:
        _disarm()
        return _over_budget(payload)
    except Exception as e:  # fail loud, then fail open (or closed when asked); one JSON object only
        _disarm()
        out = {}
        warning = audit.fail_loud(e)
        if warning:
            out["systemMessage"] = warning
        if os.environ.get("RAYNSIS_INSPECTOR_FAIL_CLOSED") == "1" and isinstance(payload, dict) \
                and payload.get("hook_event_name") == "PreToolUse":
            out["hookSpecificOutput"] = {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                         "permissionDecisionReason": "RAYNSIS Inspector engine error and "
                                                                     "RAYNSIS_INSPECTOR_FAIL_CLOSED=1: %r" % e}
        # in shadow mode the error is still in audit.jsonl and `raynsis-inspector doctor`
        if out and not shadow():
            _emit(out)
        return 0
    finally:
        _disarm()


def check(kind: str, text: str, tool: str = "", tool_input=None, turn=(), seen: str = "", out=None) -> int:
    """Dry run without Claude Code: which active rules fire on this tool call or reply.

    Exit code: 1 when a deny rule fires, 0 otherwise (warn hits are printed but do not fail)."""
    w = out or sys.stdout
    rules, errors = engine.load_rules(rule_paths(), _disabled())
    for e in errors:
        w.write("PROBLEM %s\n" % e)
    if kind == "reply":
        hits = engine.reply_hits([r for r in rules if engine.applies(r, "reply")], text, list(turn), seen)
    else:
        if kind == "bash":
            tool, tool_input = "Bash", {"command": text}
        hits = engine.tool_hits([r for r in rules if engine.applies(r, "tool", tool)], tool, tool_input or {})
    for r, excerpt in hits:
        w.write('%-4s %s\n     %s\n     matched: "%s"\n' % (r["action"].upper(), r["id"], r["message"], excerpt[:80]))
    if not hits:
        w.write("pass: no rule fired (%d rules checked)\n" % len(rules))
    return 1 if any(r["action"] == "deny" for r, _ in hits) else 0


def _first_sentence(msg: str) -> str:
    cut = msg.find(". ")
    return msg if cut < 0 else msg[:cut + 1]


def rules_table(paths=None, markdown: bool = False, out=None) -> int:
    """List active rules. --markdown prints the table used in README.md (a test keeps them equal)."""
    w = out or sys.stdout
    rules, errors = engine.load_rules(paths or rule_paths(), _disabled())
    if markdown:
        w.write("| id | on | action | what it stops |\n|---|---|---|---|\n")
        for r in rules:
            w.write("| `%s` | %s | %s | %s |\n" % (r["id"], r["event"], r["action"], _first_sentence(r["message"]).replace("|", "\\|")))
    else:
        for r in rules:
            w.write("%-34s %-5s %-4s %s\n" % (r["id"], r["event"], r["action"], _first_sentence(r["message"])))
    for e in errors:
        w.write("PROBLEM %s\n" % e)
    return 1 if errors else 0


def _fires(rule: dict, example: dict) -> bool:
    if rule["event"] == "tool":
        return bool(engine.tool_hits([rule], example.get("tool", "Bash"), example.get("input") or {}))
    return bool(engine.reply_hits([rule], example.get("reply", ""), example.get("turn") or [], example.get("seen", "")))


def test_rules(paths=None) -> int:
    """Every rule must prove itself: at least one example it fires on, all misses stay quiet."""
    rules, errors = engine.load_rules(paths or rule_paths())
    failures = list(errors)
    n_examples = 0
    for r in rules:
        ex = r.get("examples") or {}
        if not ex.get("hit"):
            failures.append("%s: no 'hit' example; a rule that never proves it fires is not a gate" % r["id"])
        for e in ex.get("hit") or []:
            n_examples += 1
            if not _fires(r, e):
                failures.append("%s: should fire on %s" % (r["id"], json.dumps(e, ensure_ascii=False)[:120]))
        for e in ex.get("miss") or []:
            n_examples += 1
            if _fires(r, e):
                failures.append("%s: should NOT fire on %s" % (r["id"], json.dumps(e, ensure_ascii=False)[:120]))
    for f in failures:
        print("FAIL " + f)
    print("rules %d · examples %d · failures %d" % (len(rules), n_examples, len(failures)))
    return 1 if failures else 0


def stats(window: int = 600, out=None) -> dict:
    """Per rule: times checked, raw hits, unique hits (same session + rule within `window` s = one)."""
    table = {}
    evals = audit.read_jsonl("evals.jsonl")
    for row in evals:
        for rid in row.get("evaluated") or []:
            table.setdefault(rid, {"checked": 0, "raw": 0, "unique": 0})["checked"] += 1
    last = {}
    for row in sorted(audit.read_jsonl("audit.jsonl"), key=lambda x: x.get("t", 0)):
        rid = row.get("rule")
        if not rid:
            continue
        s = table.setdefault(rid, {"checked": 0, "raw": 0, "unique": 0})
        s["raw"] += 1
        key = (row.get("session"), rid)
        if row.get("t", 0) - last.get(key, -1e18) > window:
            s["unique"] += 1
        last[key] = row.get("t", 0)
    w = out or sys.stdout
    w.write("%-36s %8s %6s %7s %7s\n" % ("rule", "checked", "raw", "unique", "rate"))
    for rid, s in sorted(table.items(), key=lambda kv: -kv[1]["unique"]):
        rate = "%.2f%%" % (100.0 * s["unique"] / s["checked"]) if s["checked"] else "n/a"
        w.write("%-36s %8d %6d %7d %7s\n" % (rid, s["checked"], s["raw"], s["unique"], rate))
    replies = [r for r in evals if r.get("event") == "reply"]
    if replies:
        w.write("\nreply checks: %d · turn start not readable (evidence rules skipped): %d\n"
                % (len(replies), sum(1 for r in replies if r.get("turn_unknown"))))
    return table


def doctor() -> int:
    problems = []
    print("RAYNSIS Inspector %s · python %s" % (__version__, sys.version.split()[0]))
    if sys.version_info < (3, 9):
        problems.append("python >= 3.9 required")
    rules, errors = engine.load_rules(rule_paths(), _disabled())
    problems.extend(errors)
    print("rules: %d active from %s" % (len(rules), ", ".join(rule_paths())))
    try:
        audit.ensure_home()
        probe = os.path.join(audit.home(), ".probe")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        print("audit log: %s (writable)" % audit.home())
    except OSError as e:
        problems.append("audit dir not writable: %s" % e)
    errs = [r for r in audit.read_jsonl("audit.jsonl") if r.get("event") == "engine_error" and r.get("t", 0) > time.time() - 86400]
    if errs:
        problems.append("%d engine errors in the last 24 h, last: %s" % (len(errs), errs[-1].get("error")))
    day = [r for r in audit.read_jsonl("evals.jsonl") if r.get("event") == "reply" and r.get("t", 0) > time.time() - 86400]
    unknown = sum(1 for r in day if r.get("turn_unknown"))
    if unknown:
        print("note: %d of %d reply checks in the last 24 h could not read the start of the turn (no transcript, "
              "or a compaction); evidence rules were skipped for them" % (unknown, len(day)))
    for p in problems:
        print("PROBLEM " + p)
    print("ok" if not problems else "%d problem(s)" % len(problems))
    return 1 if problems else 0


def main(argv=None) -> int:
    for s in (sys.stdout, sys.stderr):  # human output on a narrow code page: replace, never crash
        try:
            s.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="raynsis-inspector", description="Evidence gates for coding agents.")
    ap.add_argument("--version", action="version", version="RAYNSIS Inspector " + __version__)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("hook", help="read a Claude Code hook payload on stdin")
    c = sub.add_parser("check", help="dry run: which rules fire on a shell command, tool call or reply",
                       description="Examples:  raynsis-inspector check bash 'git push --force'   "
                                   "raynsis-inspector check reply 'All tests pass.' --turn 'Edit: app.py'   "
                                   "raynsis-inspector check tool Write --input '{\"file_path\": \".env\"}'")
    c.add_argument("kind", choices=("bash", "tool", "reply"))
    c.add_argument("text", help="the shell command, the tool name (kind tool) or the reply text")
    c.add_argument("--input", default="{}", help="tool input as JSON (kind tool)")
    c.add_argument("--turn", action="append", default=[], help="a tool call made this turn, e.g. 'Bash: pytest' (repeatable)")
    c.add_argument("--seen", default="", help="text the agent saw this session (for the link rule)")
    r = sub.add_parser("rules", help="list active rules")
    r.add_argument("--markdown", action="store_true", help="print the README table")
    t = sub.add_parser("test-rules", help="check every rule against its own examples")
    t.add_argument("paths", nargs="*")
    s = sub.add_parser("stats", help="per-rule checked / hit counts from the audit log")
    s.add_argument("--window", type=int, default=600, help="dedupe window in seconds (default 600)")
    sub.add_parser("doctor", help="check install, rules and audit log")
    a = ap.parse_args(argv)
    if a.cmd == "hook":
        return hook()
    if a.cmd == "check":
        if a.kind == "tool":
            try:
                tool_input = json.loads(a.input)
            except ValueError as e:
                ap.error("--input is not valid JSON: %s" % e)
            if not isinstance(tool_input, dict):
                ap.error("--input must be a JSON object")
            return check("tool", "", tool=a.text, tool_input=tool_input)
        return check(a.kind, a.text, turn=a.turn, seen=a.seen)
    if a.cmd == "rules":
        return rules_table(markdown=a.markdown)
    if a.cmd == "test-rules":
        return test_rules(a.paths or None)
    if a.cmd == "stats":
        stats(a.window)
        return 0
    if a.cmd == "doctor":
        return doctor()
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
