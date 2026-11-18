"""Append-only audit log and loud failure reporting.

Lesson from production (04.11.2026): our engine crashed on a missing rule field ~906 times
in nine hours and failed open; every gate silently stopped working. Here a crash still lets
the session continue (unless KANIT_FAIL_CLOSED=1), but it is logged and shown on screen.
Logging itself never raises: a log that cannot be written must not take a decision down with it.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time

WARN_EVERY_S = 600
ROTATE_BYTES = 20 * 1024 * 1024  # a log above this is moved to <name>.1 (one generation kept)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def project_dir() -> str:
    """The project root. Claude Code sets CLAUDE_PROJECT_DIR for hooks; unlike the hook's `cwd` it does
    not follow a `cd` inside the session, so `cd src/api` cannot step out of the project's rules."""
    p = os.environ.get("CLAUDE_PROJECT_DIR")
    return p if p and os.path.isdir(p) else os.getcwd()


def home() -> str:
    return os.environ.get("KANIT_HOME") or os.path.join(project_dir(), ".kanit")


# Logs live next to the project's rules; keep them out of git, keep rules.json in.
GITIGNORE = "# written by kanit: logs stay local, rules.json is meant to be committed\n*.jsonl\n*.jsonl.1\nfailure.json\n"


def ensure_home() -> str:
    """Create the audit directory on first use, with a .gitignore so logs are never committed by accident."""
    h = home()
    os.makedirs(h, exist_ok=True)
    gi = os.path.join(h, ".gitignore")
    if not os.path.lexists(gi):
        fd = os.open(gi, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(GITIGNORE)
    return h


def _append(name: str, row: dict) -> None:
    path = os.path.join(home(), name)
    try:
        ensure_home()
        row = dict(row, t=row.get("t") or time.time())
        line = json.dumps(row, ensure_ascii=True) + "\n"  # ASCII: lone surrogates and odd code pages cannot break it
        try:
            if os.lstat(path).st_size > ROTATE_BYTES:
                os.replace(path, path + ".1")
        except OSError:
            pass
        # O_NOFOLLOW: a planted symlink (.kanit/evals.jsonl -> ~/.bashrc) is refused, not appended to
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _NOFOLLOW, 0o644)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:  # never raise, never swallow silently
        try:
            sys.stderr.write("kanit: audit write failed (%s): %r\n" % (path, e))
        except Exception:
            pass


def read_jsonl(name: str) -> list:
    path = os.path.join(home(), name)
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return rows


def log_hit(session: str, event: str, rule: dict, excerpt: str, shadow: bool = False) -> None:
    row = {"session": session, "event": event, "rule": rule["id"], "action": rule["action"], "excerpt": excerpt[:160]}
    if shadow:
        row["shadow"] = True
    _append("audit.jsonl", row)


def log_eval(session: str, event: str, evaluated: list, hits: list, **extra) -> None:
    """Denominator for every rule: how often it was checked, not only how often it fired."""
    _append("evals.jsonl", dict({"session": session, "event": event, "evaluated": evaluated, "hits": hits}, **extra))


def _throttle(key: str, now: float) -> tuple:
    """Count events per hour under `key`; return (show_warning_now, count_last_hour)."""
    path = os.path.join(home(), "failure.json")
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}
    s = state.get(key) if isinstance(state.get(key), dict) else {}
    if now - s.get("last", 0) > 3600:
        s["count"] = 0
    s["count"] = s.get("count", 0) + 1
    s["last"] = now
    show = now - s.get("last_warned", 0) > WARN_EVERY_S
    if show:
        s["last_warned"] = now
    state[key] = s
    if len(state) > 200:  # keep the newest keys only
        state = dict(sorted(state.items(), key=lambda kv: -(kv[1].get("last", 0) if isinstance(kv[1], dict) else 0))[:100])
    try:
        ensure_home()
        fd, tmp = tempfile.mkstemp(dir=home(), prefix=".failure-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, path)  # replaces a planted symlink instead of writing through it
    except Exception as e:
        try:
            sys.stderr.write("kanit: failure state write failed: %r\n" % e)
        except Exception:
            pass
    return show, s["count"]


def _key(kind: str, text: str) -> str:
    """One throttle per distinct problem: a second, different error is never hidden behind the first."""
    return "%s:%s" % (kind, hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16])


def fail_loud(exc: BaseException, now: float = 0.0) -> str:
    """Record an engine failure; return the on-screen warning ("" while throttled).

    The caller prints it inside its single JSON object: a hook must emit exactly one.
    """
    now = now or time.time()
    text = repr(exc)[:200]
    _append("audit.jsonl", {"event": "engine_error", "error": text})
    show, count = _throttle(_key("engine_error", type(exc).__name__ + str(exc)[:80]), now)
    if not show:
        return ""
    return ("kanit ENGINE ERROR: gates are NOT enforcing (%d times in the last hour). Last: %s. Log: %s"
            % (count, repr(exc)[:120], os.path.join(home(), "audit.jsonl")))


def rule_errors(errors: list, now: float = 0.0) -> str:
    """Invalid rules are skipped, never fatal; return a throttled warning text ("" when quiet)."""
    if not errors:
        return ""
    now = now or time.time()
    _append("audit.jsonl", {"event": "rule_error", "errors": errors[:20]})
    show, _ = _throttle(_key("rule_error", "\n".join(errors)), now)
    if not show:
        return ""
    return "kanit: %d invalid rule(s) skipped, the rest still enforce: %s" % (len(errors), "; ".join(errors[:3]))


def notice(key: str, text: str, now: float = 0.0) -> str:
    """A one-off notice for the human: returned the first time `key` is seen within the hour, then ""."""
    show, count = _throttle(_key("notice", key), now or time.time())
    return text if show and count == 1 else ""
