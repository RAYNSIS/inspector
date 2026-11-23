"""Append-only audit log and loud failure reporting.

Lesson from production (04.11.2026): our engine crashed on a missing rule field ~906 times
in nine hours and failed open; every gate silently stopped working. Here a crash still lets
the session continue (unless RAYNSIS_INSPECTOR_FAIL_CLOSED=1), but it is logged and shown on screen.
Logging itself never raises: a log that cannot be written must not take a decision down with it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time

WARN_EVERY_S = 600
STATE_MAX_BYTES = 1024 * 1024  # failure.json above this is ignored
ROTATE_BYTES = 20 * 1024 * 1024  # a log above this is moved to <name>.1 (one generation kept)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def project_dir() -> str:
    """The project root. Claude Code sets CLAUDE_PROJECT_DIR for hooks; unlike the hook's `cwd` it does
    not follow a `cd` inside the session, so `cd src/api` cannot step out of the project's rules."""
    p = os.environ.get("CLAUDE_PROJECT_DIR")
    return p if p and os.path.isdir(p) else os.getcwd()


def home() -> str:
    return os.environ.get("RAYNSIS_INSPECTOR_HOME") or os.path.join(project_dir(), ".raynsis-inspector")


# Logs live next to the project's rules; keep them out of git, keep rules.json in.
GITIGNORE = ("# written by RAYNSIS Inspector: logs stay local, rules.json is meant to be committed\n"
             "*.jsonl\n*.jsonl.1\nfailure.json\n")


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
        # O_NOFOLLOW: a planted symlink (.raynsis-inspector/evals.jsonl -> ~/.bashrc) is refused, not appended to
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _NOFOLLOW, 0o644)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:  # never raise, never swallow silently
        try:
            sys.stderr.write("RAYNSIS Inspector: audit write failed (%s): %r\n" % (path, e))
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


CONTEXT_CHARS = 120
_REDACT_INPUT = 2000  # text is cut to this before masking, so masking cost stays bounded
_MASK = "***"
# Each pattern keeps group 1 and replaces the rest of the match with ***. All are linear: no nested repeats.
_REDACTIONS = [
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"(?i)((?:authorization|proxy-authorization|cookie|set-cookie|x-[a-z0-9-]*(?:key|token|secret|auth)[a-z0-9-]*)\s*:\s*)[^\r\n\"']+"),
    re.compile(r"(?i)(\b(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{4,}"),
    re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]*:)[^\s/@]+(?=@)"),
    re.compile(r"((?:^|\s)-u\s*['\"]?[^\s:'\"]+:)[^\s'\"]+"),
    re.compile(r"(?i)((?<![\w-])--?[a-z0-9-]*(?:token|key|secret|passw(?:or)?d|pass|pwd|auth)[a-z0-9-]*(?:=|\s+)['\"]?)[^\s'\"]+"),
    re.compile(r"(?i)(\b[a-z0-9_]*(?:key|token|secret|passw(?:or)?d|pwd|credential)[a-z0-9_]*\s*[=:]\s*['\"]?)[^\s'\"]+"),
    re.compile(r"(\b(?:AKIA|ASIA|ghp_|gho_|ghu_|ghs_|github_pat_|sk-|xox[abprs]-|sk_live_|rk_live_|AIza)[A-Za-z0-9]{0,2})[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(\beyJ[A-Za-z0-9_-]{1,4})[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
]


def redact(text: str) -> str:
    """Mask secret values (KEY=value, --token x, auth headers, known token shapes) before a log line is written."""
    text = text or ""
    if len(text) > _REDACT_INPUT:
        text = text[:_REDACT_INPUT]
    for rx in _REDACTIONS:
        text = rx.sub(lambda m: m.group(1) + _MASK, text)
    return text


_CONTEXT_FIELDS = ("command", "file_path", "notebook_path", "path", "url", "pattern", "glob")


def tool_context(tool_input) -> str:
    """The first ~120 characters of what the tool was asked to do, masked. File contents are never logged."""
    if not isinstance(tool_input, dict):
        return ""
    for k in _CONTEXT_FIELDS:
        v = tool_input.get(k)
        if isinstance(v, str) and v.strip():
            text = " ".join(v[:_REDACT_INPUT].split())
            if len(v) > _REDACT_INPUT and " " in text:
                text = text.rsplit(" ", 1)[0]  # drop a half-cut last word before masking
            text = redact(text)
            return text if len(text) <= CONTEXT_CHARS else text[:CONTEXT_CHARS - 3] + "..."
    return ""


def log_hit(session: str, event: str, rule: dict, excerpt: str, shadow: bool = False,
            context: str = "", tool: str = "") -> None:
    row = {"session": session, "event": event, "rule": rule["id"], "action": rule["action"],
           "excerpt": redact(excerpt or "")[:160]}
    if context:
        row["context"] = redact(context)[:CONTEXT_CHARS]
    if tool:
        row["tool"] = tool[:64]
    if shadow:
        row["shadow"] = True
    _append("audit.jsonl", row)


def log_eval(session: str, event: str, evaluated: list, hits: list, **extra) -> None:
    """Denominator for every rule: how often it was checked, not only how often it fired."""
    _append("evals.jsonl", dict({"session": session, "event": event, "evaluated": evaluated, "hits": hits}, **extra))


def _past(v, now: float) -> float:
    """A stored time, or 0 when it is not a number or lies in the future (nan and inf included)."""
    return float(v) if type(v) in (int, float) and 0 <= v <= now else 0.0


def _throttle(key: str, now: float) -> tuple:
    """Count events per hour under `key`; return (show_warning_now, count_last_hour).

    failure.json sits inside the project, so a cloned repository can ship one. Nothing in it is trusted:
    a time in the future, a wrong type or an oversized or special file all read as "never warned", so a
    planted file can add a warning but can never silence one."""
    path = os.path.join(home(), "failure.json")
    state = {}
    try:
        st = os.stat(path)
        if stat.S_ISREG(st.st_mode) and st.st_size <= STATE_MAX_BYTES:  # not a device, a FIFO or a huge file
            with open(path, encoding="utf-8", errors="replace") as f:
                loaded = json.loads(f.read(STATE_MAX_BYTES + 1))
            if isinstance(loaded, dict):
                state = {k: v for k, v in loaded.items() if isinstance(v, dict)}
    except (OSError, ValueError, RecursionError):
        state = {}
    old = state.get(key, {})
    last, last_warned = _past(old.get("last"), now), _past(old.get("last_warned"), now)
    count = old.get("count")
    if type(count) is not int or not 0 <= count < 10 ** 9 or now - last > 3600:
        count = 0
    show = now - last_warned > WARN_EVERY_S
    s = {"count": count + 1, "last": now, "last_warned": now if show else last_warned}
    state[key] = s
    if len(state) > 200:  # keep the newest keys only
        state = dict(sorted(state.items(), key=lambda kv: -_past(kv[1].get("last"), now))[:100])
    try:
        ensure_home()
        fd, tmp = tempfile.mkstemp(dir=home(), prefix=".failure-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, path)  # replaces a planted symlink instead of writing through it
    except Exception as e:
        try:
            sys.stderr.write("RAYNSIS Inspector: failure state write failed: %r\n" % e)
        except Exception:
            pass
    return show, count + 1


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
    return ("RAYNSIS Inspector ENGINE ERROR: gates are NOT enforcing (%d times in the last hour). Last: %s. Log: %s"
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
    return "RAYNSIS Inspector: %d invalid rule(s) skipped, the rest still enforce: %s" % (len(errors), "; ".join(errors[:3]))


def notice(key: str, text: str, now: float = 0.0) -> str:
    """A one-off notice for the human: returned the first time `key` is seen within the hour, then ""."""
    show, count = _throttle(_key("notice", key), now or time.time())
    return text if show and count == 1 else ""
