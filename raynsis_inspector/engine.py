"""Rule loading, validation and evaluation. Evaluation is pure: no file or network access."""
from __future__ import annotations

import json
import os
import re
import stat
from urllib.parse import urlsplit

EVENTS = ("tool", "reply")
ACTIONS = ("deny", "ask", "warn")
CHECKS = ("urls_seen",)
REGEX_KEYS = ("pattern", "unless", "needs_turn", "unless_url", "tool_pattern")
STR_KEYS = ("id", "event", "action", "message", "check", "seen_scope") + REGEX_KEYS
LIST_KEYS = ("tools", "field", "needs_turn_tools", "needs_turn_field", "allow_hosts")
SEEN_SCOPES = ("url", "host")
URL_RE = re.compile(r"https?://[^\s<>\"'`)\]]+")
URL_TRAIL = ".,;:!?*_"
RULES_MAX_BYTES = 1024 * 1024
MAX_CLAIMS = 50  # claim matches examined per reply rule


def validate(rule) -> list:
    """Return problems with one rule. An invalid rule is skipped; it never takes the engine down."""
    if not isinstance(rule, dict):
        return ["rule is not an object"]
    rid = rule.get("id") if isinstance(rule.get("id"), str) and rule.get("id") else "?"
    errs = ["%s: missing %r" % (rid, k) for k in ("id", "event", "action", "message") if not rule.get(k)]
    for k in STR_KEYS:
        if rule.get(k) is not None and not isinstance(rule[k], str):
            errs.append("%s: %r must be a string" % (rid, k))
    for k in ("only_added", "only_removed"):
        if rule.get(k) is not None and not isinstance(rule[k], bool):
            errs.append("%s: %r must be true or false" % (rid, k))
    if rule.get("only_added") and rule.get("only_removed"):
        errs.append("%s: 'only_added' and 'only_removed' cannot both be true" % rid)
    for k in LIST_KEYS:
        v = rule.get(k)
        if v is not None and not (isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))):
            errs.append("%s: %r must be a string or a list of strings" % (rid, k))
    if errs:
        return errs
    if rule["event"] not in EVENTS:
        errs.append("%s: event must be one of %s" % (rid, "/".join(EVENTS)))
    if rule["action"] not in ACTIONS:
        errs.append("%s: action must be one of %s" % (rid, "/".join(ACTIONS)))
    elif rule["action"] == "ask" and rule["event"] != "tool":
        errs.append("%s: action 'ask' is for tool rules only (a reply has no permission prompt)" % rid)
    if rule.get("check") and rule["check"] not in CHECKS:
        errs.append("%s: unknown check %r" % (rid, rule["check"]))
    if rule.get("seen_scope") and rule["seen_scope"] not in SEEN_SCOPES:
        errs.append("%s: seen_scope must be one of %s" % (rid, "/".join(SEEN_SCOPES)))
    if any(not h.strip() or h.strip() == "*." for h in _as_list(rule.get("allow_hosts"))):
        errs.append("%s: 'allow_hosts' has an empty entry" % rid)
    if not rule.get("pattern") and not rule.get("check"):
        errs.append("%s: needs 'pattern' or 'check'" % rid)
    for k in REGEX_KEYS:
        if rule.get(k):
            try:
                re.compile(rule[k])
            except re.error as e:
                errs.append("%s: bad regex in %r: %s" % (rid, k, e))
    return errs


_FLAGS = re.compile(r"^\(\?([aimsux]+)\)")


def _split_flags(rx: str) -> tuple:
    m = _FLAGS.match(rx)
    return (m.group(1), rx[m.end():]) if m else ("", rx)


def join_regex(base: str, extra: str) -> str:
    """base OR extra as one regex. Each side keeps its own leading flags, scoped to that side, so
    "(?x)" in a project extension cannot change how the packaged pattern is read."""
    if not base:
        return extra
    out = []
    for rx in (base, extra):
        flags, body = _split_flags(rx)
        out.append("(?%s:%s)" % (flags, body) if flags else "(?:%s)" % body)
    return "|".join(out)


def merge_rule(base, patch: dict) -> dict:
    """Apply a project rule onto an earlier rule with the same id.

    Keys you write replace the old value, keys you leave out are kept, a key set to null is removed,
    and "<regex key>+" (for example "needs_turn+") adds an alternative to the old regex instead of replacing it.
    Raises ValueError for a patch that cannot be applied.
    """
    out = dict(base or {})
    for k, v in patch.items():
        if not isinstance(k, str):
            raise ValueError("rule keys must be strings")
        if k.endswith("+"):
            if k[:-1] not in REGEX_KEYS or not isinstance(v, str):
                raise ValueError("%r: only regex fields can be extended, with a string" % k)
            if v:
                out[k[:-1]] = join_regex(out.get(k[:-1]) or "", v)
        elif v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def read_rules_file_bytes(path: str) -> bytes:
    """Bytes of a regular file of at most RULES_MAX_BYTES. A FIFO, device or huge file is an error,
    never a hang: the project rules file is something an agent may try to plant."""
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("not a regular file")
    if st.st_size > RULES_MAX_BYTES:
        raise ValueError("larger than %d bytes" % RULES_MAX_BYTES)
    with open(path, "rb") as f:
        return f.read(RULES_MAX_BYTES + 1)


def read_rules_file(path: str):
    return json.loads(read_rules_file_bytes(path).decode("utf-8"))


def load_rules(paths, disabled=()) -> tuple:
    """Load rule files in order. A rule whose id appeared in an earlier file is merged onto it
    (see merge_rule), so a project can change one field of a core rule without copying it.

    A file may be a list of rules or {"rules": [...], "disable": ["id", ...]}.
    Returns (rules, errors). Any problem in a file or a rule is reported and skipped: the rest,
    including the earlier version of a rule, keeps working.
    """
    by_id, errors, off = {}, [], set(disabled)
    for p in paths:
        name = os.path.basename(p)
        try:
            data = read_rules_file(p)
        except (OSError, ValueError) as e:
            errors.append("%s: %s" % (name, e))
            continue
        items = data.get("rules", []) if isinstance(data, dict) else data
        if isinstance(data, dict) and data.get("disable") is not None:
            dis = data["disable"]
            if isinstance(dis, list) and all(isinstance(x, str) for x in dis):
                off.update(dis)
            else:
                errors.append("%s: 'disable' must be a list of rule ids" % name)
        if not isinstance(items, list):
            errors.append("%s: 'rules' must be a list" % name)
            continue
        for r in items:
            try:
                if isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"] in by_id:
                    r = merge_rule(by_id[r["id"]], r)
                problems = validate(r)
            except (TypeError, ValueError, AttributeError, re.error) as e:
                problems = ["%s: %s" % (r.get("id") if isinstance(r, dict) else "?", e)]
            if problems:
                errors.extend("%s: %s" % (name, x) for x in problems)
                continue
            by_id[r["id"]] = r
    return [r for rid, r in by_id.items() if rid not in off], errors


def _as_list(v) -> list:
    return [v] if isinstance(v, str) else list(v or [])


def applies(rule: dict, event: str, tool: str = "") -> bool:
    if rule["event"] != event:
        return False
    if event != "tool":
        return True
    tools = _as_list(rule.get("tools"))
    if tools and tool not in tools:
        return False
    return not (rule.get("tool_pattern") and not re.search(rule["tool_pattern"], tool))


_OLD_OF = {"new_string": "old_string", "content": "_prior"}


def _values(tool_input: dict, name: str) -> list:
    """Values of one input field. MultiEdit keeps old_string/new_string inside an "edits" list."""
    v = tool_input.get(name)
    vals = [] if v is None else [v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)]
    if name in ("old_string", "new_string") and isinstance(tool_input.get("edits"), list):
        vals.extend(str(e.get(name) or "") for e in tool_input["edits"] if isinstance(e, dict))
    return vals


def _tool_text(rule: dict, tool_input: dict, old: bool = False) -> str:
    field = rule.get("field", "*")
    if field == "*":
        return "" if old else json.dumps(tool_input, ensure_ascii=False, sort_keys=True)
    parts = []
    for name in _as_list(field):
        if old:
            name = _OLD_OF.get(name)
            if not name:
                continue
        parts.extend(_values(tool_input, name))
    return "\n".join(parts)


_SEP = re.compile(r"[;&|\n]")


def _segment(text: str, start: int, end: int) -> str:
    """The command segment around text[start:end] (between ; & | or newline): an `unless` only
    excuses its own command, so "docker push org/app; echo -n done" is not excused by echo's -n."""
    s = 0
    for m in _SEP.finditer(text, 0, start):
        s = m.end()
    m = _SEP.search(text, end)
    return text[s:(m.start() if m else len(text))]


def tool_hits(rules: list, tool: str, tool_input: dict) -> list:
    """[(rule, matched_text)] for tool rules that fire on this call.

    A rule with "only_added": true fires only when the edit adds a match: the new text (new_string,
    content) has more matches than the text it replaces (old_string, or "_prior", the current file
    content the caller may pass for Write). "only_removed": true is the mirror: it fires only when the
    replaced text has more matches than the new text, e.g. an edit that deletes a test function.
    """
    hits = []
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    for r in rules:
        if not applies(r, "tool", tool):
            continue
        text = _tool_text(r, tool_input)
        if r.get("only_removed"):
            if "content" in tool_input and "_prior" not in tool_input:
                continue  # Write of a new file: nothing was there to remove
            before = _tool_text(r, tool_input, old=True)
            m = re.search(r["pattern"], before)
            if not m or (r.get("unless") and re.search(r["unless"], _segment(before, m.start(), m.end()))):
                continue
            if len(re.findall(r["pattern"], before)) <= len(re.findall(r["pattern"], text)):
                continue
            hits.append((r, m.group(0)))
            continue
        m = re.search(r["pattern"], text)
        if not m or (r.get("unless") and re.search(r["unless"], _segment(text, m.start(), m.end()))):
            continue
        if r.get("only_added"):
            if "content" in tool_input and "_prior" not in tool_input:
                continue  # Write of a new file: there was nothing to weaken
            before = _tool_text(r, tool_input, old=True)
            if len(re.findall(r["pattern"], text)) <= len(re.findall(r["pattern"], before)):
                continue
        hits.append((r, m.group(0)))
    return hits


def _norm_url(u: str) -> str:
    return u.rstrip(URL_TRAIL).split("#", 1)[0].rstrip("/")


def _without_userinfo(u: str) -> str:
    """scheme://host[:port]/path, so "https://example.com:x@evil.io/" is judged as evil.io."""
    try:
        p = urlsplit(u)
        port = ":%d" % p.port if p.port else ""
    except ValueError:
        return ""
    return "%s://%s%s%s" % (p.scheme, p.hostname or "", port, p.path)


def _seen_urls(seen: str) -> set:
    """Every URL in the text the agent saw, plus each of its prefixes that ends at a path,
    query or fragment boundary: "https://a.dev/docs/x?y" also covers "https://a.dev/docs"."""
    out = set()
    for u in URL_RE.findall((seen or "").replace("\\/", "/")):
        u = u.rstrip(URL_TRAIL)
        out.add(_norm_url(u))
        start = u.find("//") + 2
        for i in range(start, len(u)):
            if u[i] in "/?#&":
                out.add(u[:i].rstrip("/"))
    return out


_DEFAULT_PORTS = {"http": 80, "https": 443}


def url_origin(u: str) -> str:
    """scheme://host[:port], lower case, default port dropped, user info ignored ("" if unparsable)."""
    try:
        p = urlsplit(u.rstrip(URL_TRAIL))
        port = p.port
    except ValueError:
        return ""
    if not p.hostname:
        return ""
    scheme = p.scheme.lower()
    port = ":%d" % port if port and port != _DEFAULT_PORTS.get(scheme) else ""
    return "%s://%s%s" % (scheme, p.hostname.lower().rstrip("."), port)


def url_host(u: str) -> str:
    o = url_origin(u)
    return o.split("://", 1)[1].split(":", 1)[0] if o else ""


def _host_allowed(host: str, allow) -> bool:
    """"vendor.example" matches only that host; "*.vendor.example" matches its subdomains."""
    if not host:
        return False
    for a in allow or ():
        a = a.strip().lower().rstrip(".")
        if a.startswith("*."):
            if host.endswith(a[1:]) and host != a[2:]:
                return True
        elif a and host == a:
            return True
    return False


def unseen_urls(reply: str, seen: str, unless: str = "", scope: str = "url", allow_hosts=()) -> list:
    """URLs in the reply that never appeared in anything the agent saw this session.

    scope "host": a URL also passes when its scheme + host appeared in the seen text.
    allow_hosts: hosts that always pass ("github.com", "*.vendor.example").
    """
    allow = _as_list(allow_hosts)
    known = None
    origins = None
    out = []
    for u in URL_RE.findall(reply or ""):
        u = u.rstrip(URL_TRAIL)
        if unless and re.search(unless, _without_userinfo(u)):
            continue
        if allow and _host_allowed(url_host(u), allow):
            continue
        if known is None:
            known = _seen_urls(seen)
        if _norm_url(u) in known:
            continue
        if scope == "host":
            if origins is None:
                origins = {url_origin(s) for s in URL_RE.findall((seen or "").replace("\\/", "/"))}
                origins.discard("")
            o = url_origin(u)
            if o and o in origins:
                continue
        out.append(u)
    return out


_BOUND = re.compile(r"[.!?](?=\s|$)|\n")


def _sentence(text: str, start: int, end: int) -> str:
    """The sentence around text[start:end]: an `unless` only excuses the claim it sits next to."""
    s = 0
    for m in _BOUND.finditer(text, 0, start):
        s = m.end()
    m = _BOUND.search(text, end)
    return text[s:(m.end() if m else len(text))]


_OPEN_QUOTES = "\"'`“‘«"
_CLOSE_QUOTES = "\"'`”’»"


def _quoted(text: str, start: int, end: int) -> bool:
    """A claim inside quotation marks is a mention, not a claim: 'my earlier "All tests pass" was wrong'."""
    if start == 0 or text[start - 1] not in _OPEN_QUOTES:
        return False
    if end < len(text) and text[end] in ".,!":
        end += 1
    return end < len(text) and text[end] in _CLOSE_QUOTES


_CLAUSE_END = re.compile(r"[.!?;,:\n—–()]|\s(?:so|but|then)\s")
_ASKS = re.compile(r"(?i)\s*(?:do|does|did|is|are|was|were|have|has|had|can|could|would|will|should|shall|may|might"
                   r"|why|how|what|where|which|who|whether)\b")


def _question(text: str, start: int, end: int) -> bool:
    """A claim inside a question is not a claim: "Do all tests pass?", "Hata düzeltildi mi?".
    Only the claim's own clause counts: in "All tests pass, want me to commit?" the claim stands."""
    m = _CLAUSE_END.search(text, end)
    if m and m.group(0) == "?":
        return True
    sentence = _sentence(text, start, end)
    return bool(_ASKS.match(sentence)) and sentence.rstrip().endswith("?")


# a condition right before a claim: "If the tests pass, merge it", "If I deployed it now, ..."
_LEAD_IF = re.compile(r"(?i)\b(?:if|unless|whether|so\s+that|in\s+case|as\s+long\s+as|provided|assuming|eğer|şayet)"
                      r"(?:\s+that)?\s*$")
# a time clause right before a claim: "Once the build passes, ..."; with a past verb it is a report
_LEAD_TIME = re.compile(r"(?i)\b(?:once|when|whenever|until|till|before|after|as\s+soon\s+as)\s*$")
# a hope, a hedge, a negation or someone else's words right before a claim
_LEAD = re.compile(
    r"(?i)(?:\b(?:ensuring|making\s+sure|checking|verifying|confirming|require|requires|required|expect|expects"
    r"|expecting|hope|not|nothing|none|claims?|claimed|says|said|states|stated|asserts|asserted|believes|believed"
    r"|thinks|thought|assumes|assumed|the\s+(?:goal|idea|aim|plan|hope|intent|requirement|expectation|point)\s+is)"
    r"(?:\s+that)?"
    r"|\b(?:in\s+theory|theoretically|ideally|hopefully|presumably|supposedly|in\s+principle|at\s+best"
    r"|in\s+(?:the\s+|an\s+)?(?:ideal|best)\s+(?:case|world))\s*,?"
    r"|\b(?:can(?:not|['’]t)|could\s*n[o'’]?t|won['’]t|don['’]t|didn['’]t|not)\s+(?:yet\s+)?(?:say|confirm|verify"
    r"|claim|guarantee|promise|know|think|sure)(?:\s+(?:that|whether|if))?)\s*$")
_VERBS = r"(?:confirm|verify|check|ensure|make\s+sure|double-check|state|say|claim|assert|report|mention|note)"
# an instruction or an intent: "You should verify that the build passes", "I'll make sure all tests pass"
_ASK_MODAL = re.compile(
    r"(?i)\b(?:to|will|['’]ll|should|must|shall|would|please|let['’]?s|let\s+me|need\s+to|needs\s+to|have\s+to"
    r"|has\s+to)\s+" + _VERBS + r"(?:\s+(?:that|whether|if))?\s*$")
# an imperative: "Make sure all tests pass", "Pull the branch and verify that the build passes";
# with "I" or "we" before it, it is a report: "I re-ran pytest and confirm all tests pass"
_ASK_LIST = re.compile(r"(?i)(?:\A|[,(]|\b(?:then|and|or|always|first|just)\s)\s*" + _VERBS
                       + r"(?:\s+(?:that|whether|if))?\s*$")
_FIRST_PERSON = re.compile(r"\bI\b|(?i:\bwe\b)")
_INTENT = re.compile(r"(?i)\b(?:I|we)(?:['’]ll|\s+will|\s+would|\s+can|\s+could|\s+should|\s+need\s+to|\s+want\s+to"
                     r"|\s+am\s+going\s+to|['’]m\s+going\s+to|\s+are\s+going\s+to|['’]re\s+going\s+to)\b")
# "... to make sure all tests pass, and they do": confirmed right after, so a claim
_AND_THEY_DO = re.compile(r"(?i)[^.!?\n]*?\b(?:and|which)\s+(?:they|it|all|everything|both)\s+(?:all\s+)?"
                          r"(?:do|does|did|pass|passes|passed)\b")
# a sentence opened by a condition: "If the suite is green, the tests pass and you can merge"
_IF_CLAUSE = re.compile(r"(?i)\s*(?:if|once(?!\s+(?:again|more)\b)|when|whenever|until(?!\s+now\b)|unless|as\s+long\s+as"
                        r"|as\s+soon\s+as|provided|assuming|in\s+case|eğer|şayet)\b")
_SPEECH_ACT = re.compile(r"(?i)\s*(?:(?:if|in\s+case)\s+(?:you(?:['’]re|\s+are|\s+were)?\s+(?:wondering|asking|curious"
                         r"|interested)|you\s+(?:want\s+to\s+know|missed\s+it|ask(?:ed)?(?:\s+me)?)|I['’]m\s+(?:being\s+)?honest)"
                         r"|eğer\s+merak\s+ed(?:iyorsan(?:ız)?|erseniz|ersen))\b")
_TIME_CLAUSE = re.compile(r"(?i)\s*(?:once|when|whenever|until|till|before|after|as\s+soon\s+as)\b")
# a past event is a report, not a condition: "Once I pushed the fix, CI went green"
_PAST = re.compile(r"(?i)\b(?:\w+(?<!e)ed|went|ran|built|made|did|was|were|got)\b")
_NOT_SIMPLE_PAST = re.compile(r"(?i)\b(?:have|has|been|be|is|are|am|will|would)\b|['’](?:ve|s|re|ll|m)\b")
# a condition or a definition right after the claim: "The build passes only if you set NODE_ENV",
# "Tests pass or fail per shard", "The suite passes when every required check reports success"
_ONLY_IF = re.compile(r"(?i)\s+(?:only\s+(?:if|when|after|once)|or\s+fail|when\s+(?:every|each|all|any))\b")
_CUT = re.compile(r"[\n.!?;:]")


def _past(s: str) -> bool:
    return bool(_PAST.search(s)) and not _NOT_SIMPLE_PAST.search(s)


def _conditional(text: str, start: int, end: int) -> bool:
    """"If the tests pass, merge it", "Make sure all tests pass", "Not all tests pass": not a claim.
    Only the claim's own line and sentence count ("## Verify\\nAll tests pass." is a claim), and a past
    event is a report ("Once I pushed the fix, CI went green" is a claim)."""
    w = text[max(0, start - 200):start]
    cuts = [m.end() for m in _CUT.finditer(w)]
    whole = bool(cuts) or start <= 200  # w starts where the sentence starts
    if cuts:
        w = w[cuts[-1]:]
    narrative = _past(text[start:end])
    if _LEAD.search(w) or _LEAD_IF.search(w) or (not narrative and _LEAD_TIME.search(w)):
        return True
    if not _AND_THEY_DO.match(text, end):
        if _ASK_MODAL.search(w):
            return True
        m = _ASK_LIST.search(w if whole else "\x00" + w)
        if m:
            before = (w if whole else "\x00" + w)[:m.start()]
            if not _FIRST_PERSON.search(before) or _INTENT.search(before):
                return True
    if whole and _IF_CLAUSE.match(w) and not _SPEECH_ACT.match(w):
        if not (_TIME_CLAUSE.match(w) and (narrative or _past(w))):
            return True
    return bool(_ONLY_IF.match(text, end))


def _claim(rule: dict, reply: str):
    """First match of the rule's pattern that is a claim: not quoted, not asked, not a condition,
    and its sentence not excused by `unless`."""
    for i, m in enumerate(re.finditer(rule["pattern"], reply)):
        if i >= MAX_CLAIMS:
            break
        a, b = m.start(), m.end()
        if _quoted(reply, a, b) or _question(reply, a, b) or _conditional(reply, a, b):
            continue
        if rule.get("unless") and re.search(rule["unless"], _sentence(reply, a, b)):
            continue
        return m.group(0) or m.string[a:a + 1]
    return None


def _turn_text(line: str, fields: list) -> str:
    """The part of one turn line ("Tool: <json input>") that counts as evidence. With fields, only
    those input fields: a Bash call's "description" saying "run tests" is not a test run."""
    if not fields:
        return line
    rest = line.partition(":")[2]
    try:
        data = json.loads(rest)
    except ValueError:
        return rest.strip()  # "Bash: pytest -q" as typed to `raynsis-inspector check --turn`
    if not isinstance(data, dict):
        return rest.strip()
    return "\n".join(data[f] for f in fields if isinstance(data.get(f), str))


def reply_hits(rules: list, reply: str, turn=(), seen: str = "") -> list:
    """[(rule, matched_text)] for reply rules that fire.

    turn: lines "Tool: <json input>" for tool calls made since the last human message.
    seen: text of everything the agent saw this session (for check "urls_seen").
    """
    reply = reply or ""
    hits = []
    for r in rules:
        if not applies(r, "reply"):
            continue
        if r.get("check") == "urls_seen":
            bad = unseen_urls(reply, seen, r.get("unless_url", ""), r.get("seen_scope") or "url", r.get("allow_hosts"))
            if not bad:
                continue
            excerpt = bad[0]
        else:
            excerpt = _claim(r, reply)
            if excerpt is None:
                continue
        if r.get("needs_turn"):
            only = _as_list(r.get("needs_turn_tools"))
            fields = _as_list(r.get("needs_turn_field"))
            lines = [_turn_text(t, fields) for t in turn if not only or t.split(":", 1)[0] in only]
            if re.search(r["needs_turn"], "\n".join(lines)):
                continue
        hits.append((r, excerpt))
    return hits


def _lines(hits: list) -> str:
    return "\n".join('- [%s] %s (matched: "%s")' % (r["id"], r["message"], ex[:80]) for r, ex in hits)


# Permission modes in which Claude Code shows the human the prompt an "ask" asks for. Measured 19.11.2026: in
# bypassPermissions a Write under .claude/ went through although a hook returned "ask" (a Write to an ordinary
# path was stopped). There, in dontAsk and in a mode we do not know, an "ask" rule denies instead.
ASK_MODES = ("default", "acceptEdits", "plan", "auto")
NO_PROMPT = ("This would be a permission prompt for the human, but in permission mode %r Claude Code may run the call "
             "without one, so it is denied. To make this change, the human switches to another permission mode "
             "(Shift+Tab) and asks again, or makes it by hand.")


def decide(hits: list, event: str, stop_hook_active: bool = False, mode: str = "default"):
    """Turn hits into the Claude Code hook JSON, or None when nothing fired.

    mode: the session's permission_mode from the hook payload; it decides whether an "ask" can be an ask."""
    deny = [h for h in hits if h[0]["action"] == "deny"]
    ask = [h for h in hits if h[0]["action"] == "ask"]
    warn = [h for h in hits if h[0]["action"] == "warn"]
    out = {}
    no_prompt = ""
    if ask and event == "tool" and mode not in ASK_MODES:
        deny, ask = deny + ask, []
        no_prompt = "\n" + NO_PROMPT % (mode or "unknown")
    if deny and event == "tool":
        out["hookSpecificOutput"] = {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                     "permissionDecisionReason": "RAYNSIS Inspector blocked this call:\n" + _lines(deny)
                                     + no_prompt}
    elif ask and event == "tool":
        # Claude Code shows the human a permission prompt; with nobody to answer (claude -p) the call is denied
        out["hookSpecificOutput"] = {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                     "permissionDecisionReason": "RAYNSIS Inspector asks you first:\n" + _lines(ask)}
    elif deny and event == "reply" and not stop_hook_active:
        out["decision"] = "block"
        out["reason"] = ("RAYNSIS Inspector: this reply claims something the session cannot prove. "
                         "Fix it before finishing:\n" + _lines(deny))
    elif deny:  # already re-prompted once: never loop, tell the human instead
        warn = deny + warn
    if warn:
        out["systemMessage"] = "RAYNSIS Inspector warning:\n" + _lines(warn)
    return out or None
