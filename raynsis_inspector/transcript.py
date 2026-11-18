"""Read Claude Code transcripts (JSONL) without loading huge files into memory."""
from __future__ import annotations

import json
import os
import re
import stat

TAIL_BYTES = 4 * 1024 * 1024  # enough for a long session tail; bounded for speed
# when the turn's start is not in the tail, read further back before calling the turn "unknown"
TURN_TAILS = (TAIL_BYTES, 16 * 1024 * 1024, 64 * 1024 * 1024)

# user entries that are not a human turn (hook feedback, slash command echoes, meta notes,
# compaction summaries, background task notifications). Measured on 400 real sessions: treating
# the last two as human turns wiped the turn's evidence and produced false alarms.
COMPACT_PREFIX = "This session is being continued from a previous conversation"
_NOT_HUMAN_PREFIXES = ("Stop hook feedback", "<command-", "<local-command", "Caveat:", "<task-notification>",
                       "[SYSTEM NOTIFICATION", "<system-reminder>", COMPACT_PREFIX)


def _entries(path: str, tail_bytes: int = TAIL_BYTES) -> list:
    try:
        if not path or not stat.S_ISREG(os.stat(path).st_mode):
            return []
    except OSError:
        return []
    with open(path, "rb") as f:
        f.seek(0, 2)
        start = max(0, f.tell() - tail_bytes)
        f.seek(start)
        lines = f.read().decode("utf-8", "ignore").splitlines()
    if start and lines:
        lines = lines[1:]  # first line may be cut in half
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def human_text(entry: dict) -> str:
    """Text typed by the human in this entry, or "" when the entry is not a human turn."""
    if entry.get("type") != "user" or entry.get("isMeta"):
        return ""
    content = (entry.get("message") or {}).get("content")
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        if any(isinstance(x, dict) and x.get("type") == "tool_result" for x in content):
            return ""
        text = "\n".join(str(x.get("text") or "") for x in content if isinstance(x, dict) and x.get("type") == "text")
    else:
        return ""
    text = text.strip()
    return "" if text.startswith(_NOT_HUMAN_PREFIXES) else text


def _tool_calls(entry: dict) -> list:
    content = (entry.get("message") or {}).get("content")
    calls = []
    if entry.get("type") == "assistant" and isinstance(content, list):
        for x in content:
            if isinstance(x, dict) and x.get("type") == "tool_use":
                calls.append({"tool": str(x.get("name") or ""), "text": json.dumps(x.get("input") or {}, ensure_ascii=False)})
    return calls


def _tool_results(entry: dict) -> list:
    content = (entry.get("message") or {}).get("content")
    texts = []
    if entry.get("type") == "user" and isinstance(content, list):
        for x in content:
            if isinstance(x, dict) and x.get("type") == "tool_result":
                c = x.get("content")
                if isinstance(c, list):
                    c = "\n".join(str(y.get("text") or "") for y in c if isinstance(y, dict))
                texts.append(str(c or ""))
    return texts


def turn_state(path: str) -> tuple:
    """(tool calls since the last human message, whether that message was found).

    When the turn started outside what we can read (a compaction that moved earlier work to another
    file, or a turn longer than the tail we read), the second value is False: the evidence for this
    turn is unknown, and evidence rules must not treat "unknown" as "missing".
    """
    size = os.path.getsize(path) if path and os.path.isfile(path) else 0
    for tail in TURN_TAILS:
        acts, started = [], False
        for e in _entries(path, tail):
            if human_text(e):
                acts, started = [], True
            acts.extend(_tool_calls(e))
        if started or tail >= size:
            break
    return acts, started


def turn_activity(path: str) -> list:
    """Tool calls made since the last human message: [{"tool": name, "text": json input}]."""
    return turn_state(path)[0]


def _summary_text(entry: dict) -> str:
    """Text of a compaction summary: not a human turn, but the agent did read it."""
    if entry.get("type") != "user":
        return ""
    content = (entry.get("message") or {}).get("content")
    if isinstance(content, list):
        content = "\n".join(str(x.get("text") or "") for x in content if isinstance(x, dict) and x.get("type") == "text")
    if not isinstance(content, str):
        return ""
    return content if (entry.get("isCompactSummary") or content.lstrip().startswith(COMPACT_PREFIX)) else ""


# What the agent itself writes into a file is not evidence: otherwise an invented URL could be
# laundered by writing it to disk first. Known gap: echoing it in a shell command still counts.
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "TodoWrite")


def _seen_parts(e: dict) -> list:
    parts = [human_text(e) or _summary_text(e)]
    parts.extend(c["text"] for c in _tool_calls(e) if c["tool"] not in WRITE_TOOLS)
    parts.extend(_tool_results(e))
    return [p for p in parts if p]


def session_text(path: str) -> str:
    """What the agent actually saw (in the last TAIL_BYTES): human messages, tool results, inputs of
    non-writing tools."""
    parts = []
    for e in _entries(path):
        parts.extend(_seen_parts(e))
    return "\n".join(parts)


def longer_than_tail(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode) and os.path.getsize(path) > TAIL_BYTES
    except (OSError, TypeError):
        return False


def older_text_with(path: str, urls: list) -> str:
    """Seen text, from the whole transcript, of the entries that contain one of these URLs.

    Streams the file one line at a time and keeps only matching entries, so a 200 MB session costs
    a read, not 200 MB of memory. Used only when a reply has a link the tail does not explain."""
    keys = sorted({u.rstrip(".,;:!?*_)").split("#", 1)[0].rstrip("/") for u in urls if u})
    if not keys:
        return ""
    raw_keys = {k.encode("utf-8", "replace") for k in keys} | {k.replace("/", "\\/").encode("utf-8", "replace") for k in keys}
    # one pass per line whatever the number of links: lines without "http" are skipped by a byte search,
    # the rest are searched once for any key (a reply with 300 links costs about what one link costs)
    finder = re.compile(b"|".join(re.escape(k) for k in sorted(raw_keys, key=len, reverse=True)))
    out = []
    try:
        with open(path, "rb") as f:
            for line in f:
                if b"http" not in line or not finder.search(line):
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                text = "\n".join(_seen_parts(e)) if isinstance(e, dict) else ""
                if any(k in text for k in keys):
                    out.append(text)
    except OSError:
        return ""
    return "\n".join(out)


def last_reply(path: str) -> str:
    """Assistant text written since the last human message."""
    texts = []
    for e in _entries(path):
        if human_text(e):
            texts = []
        content = (e.get("message") or {}).get("content")
        if e.get("type") == "assistant" and isinstance(content, list):
            texts.extend(str(x.get("text")) for x in content if isinstance(x, dict) and x.get("type") == "text" and x.get("text"))
    return "\n".join(texts)
