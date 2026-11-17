#!/usr/bin/env python3
"""Lint EARS requirements in Markdown, plain-text or drwatt manifest files.

Finds requirement lines (list items or lines that start with an ID such as
TB-001, and plain sentences that contain "shall"), or the statements of a
drwatt requirements.json manifest, classifies each into an EARS pattern, and
reports defects and warnings. Exit status: 0 = no defect, 1 = at least one
defect, 2 = usage, I/O, encoding or manifest error. Standard library only,
Python 3.11 or newer.

Patterns (Mavin et al., RE 2009; alistairmavin.com/ears):
  ubiquitous          The <system> shall <response>
  state-driven        While <precondition>, the <system> shall <response>
  event-driven        When <trigger>, the <system> shall <response>
  optional-feature    Where <feature is included>, the <system> shall <response>
  unwanted-behaviour  If <trigger>, then the <system> shall <response>
  complex             two or more keywords, in the order
                      Where, While/During, When, If ... then
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import sys

ID_RE = r"[A-Z][A-Z0-9]{0,15}(?:-[A-Z0-9]+)*-\d{1,6}"
ITEM_START = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
ID_LEAD = re.compile(
    r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:\*\*|__|`)?\[?(" + ID_RE + r")\]?(?:\*\*|__|`)?"
    r"\s*(?:[:.)–—-]\s*)?(?:\*\*|__)?\s*"
)
HEADING = re.compile(r"^ {0,3}(#{1,6})(?:\s|$)")
SCENARIO_HEADING = re.compile(r"^ {0,3}#{4,6}\s+Scenario\b", re.I)
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}(?=[^`]*$)|~{3,})")
TABLE_SEP = re.compile(r"\|?[ \t]*:?-{3,}")
MARKER = re.compile(r"<!--\s*ears-lint:\s*(off|on)\s*-->", re.I)
CODE_SPAN = re.compile(r"`[^`]*`")

# drwatt's accepted statement forms (tools/drwatt/drwatt.py, DW-002), for --drwatt.
DRWATT_FORMS = (
    re.compile(r"The (.+?) shall (.+)\."),
    re.compile(r"(?:When|While|Where) (.+?), the (.+?) shall (.+)\."),
    re.compile(r"If (.+?), then the (.+?) shall (.+)\."),
)

KEYWORDS = {"where": "where", "while": "while", "during": "while", "when": "when", "if": "if"}
RANK = {"where": 0, "while": 1, "when": 2, "if": 3}
PATTERN_OF = {
    frozenset(): "ubiquitous",
    frozenset({"while"}): "state-driven",
    frozenset({"when"}): "event-driven",
    frozenset({"where"}): "optional-feature",
    frozenset({"if"}): "unwanted-behaviour",
}
# Modals other than "shall". After a "shall", only these make the behaviour
# optional or mix modals; "will" and "can" are left out because they occur in
# described content ("warn that changes will be lost").
WEAK_MODALS = ["should", "may", "might", "could", "must", "will", "can"]
WEAK_IN_RESPONSE = ["should", "may", "might", "could", "must"]
VAGUE = [
    "fast", "quick", "quickly", "slow", "slowly", "user-friendly", "user friendly",
    "easy", "easily", "efficient", "efficiently", "robust", "flexible", "intuitive",
    "adequate", "adequately", "appropriate", "appropriately", "sufficient", "sufficiently",
    "reasonable", "reasonably", "as soon as possible", "asap", "minimize", "minimise",
    "maximize", "maximise", "optimal", "optimally", "seamless", "seamlessly",
    "approximately", "etc", "and/or", "normally", "usually", "generally", "typically",
    "if possible", "where possible", "as needed", "as required", "as appropriate",
    "high performance", "state of the art", "timely", "acceptable", "unacceptable",
]
# Often vague, but common in exact sentences too: reported as warnings.
VAGUE_WARN = [
    "about", "some", "several", "many", "few", "best", "better", "large", "small",
    "simple", "simply", "minimal", "secure", "securely", "reliable", "reliably",
    "real-time", "real time",
]
HIDDEN_TRIGGER = [
    "upon", "whenever", "each time", "every time", "in the event of", "in case of",
    "on receipt of", "on failure", "on error",
]
HIDDEN_TRIGGER_RE = re.compile(r"(?i)(?<![\w-])on\s+[a-z]+\s+failure(?![\w-])")
# A word after "while" that ends in -ing but is not a participle.
NOT_PARTICIPLE = {"string", "strings", "nothing", "anything", "something", "everything",
                  "thing", "things", "during", "morning", "evening", "ring", "king", "bring",
                  "sing", "wing", "spring", "sling", "swing", "ceiling", "setting", "settings"}
TRAILING = re.compile(r"(?i)(?<![\w-])(when|while|if|unless|during)(?![\w-])")
IRREGULAR_PP = {
    "sent", "kept", "shown", "given", "made", "done", "written", "set", "held", "built",
    "put", "read", "run", "known", "seen", "taken", "chosen", "drawn", "found", "sold",
    "told", "paid", "left", "lost", "met", "shut", "spent", "split", "thrown", "hidden",
}
NOT_PASSIVE_ED = {"red", "need", "feed", "seed", "bed", "shed", "speed", "embed", "proceed",
                  "exceed", "succeed", "indeed", "bounded", "limited", "able"}
STATE_HINT = re.compile(
    r"\b(?:is|are)\s+(?:in|not\s+in|active|enabled|disabled|on|off|open|closed|empty|full|present|absent)\b"
    r"|\b(?:has|have)\s+no\b|\bexists?\b|\bremains?\b|\bmode\b", re.I)
EVENT_HINT = re.compile(r"\b(?:arrives?|occurs?|is\s+(?:pressed|selected|received|commanded|clicked|detected)|receives?)\b", re.I)
GENERIC_SYSTEMS = {"system", "user"}
ABBREVIATIONS = {"e.g", "i.e", "etc", "vs", "cf", "approx", "fig", "no", "nr"}

# A product name used without "the": a code span, a word with an inner capital or
# digit (AgentBus, S3), or two or more capitalised words (Engine Control System).
# [a-z]* and [A-Z0-9] do not overlap, so a failed match does not backtrack.
PROPER_NAME = re.compile(r"^(?:`[^`]+`(?:\s+[\w-]+)?|[A-Z][a-z]*[A-Z0-9][\w-]*|[A-Z][\w-]*(?:\s+[A-Z][\w-]*)+)$")
QUANTIFIER = re.compile(r"^(?:A|An|Each|Every|All|Any|No|Some|One|This|That|It|They)\b")
SUBJECT_START = re.compile(r"(?i)^(?:then\s+)?the\s+\S|^(?:where|while|during|when|if)\b")


def _mask(text: str) -> str:
    """Blank out code spans and quoted strings, keeping positions aligned."""
    out = list(text)
    for pat in (r"`[^`]*`", r"\"[^\"]*\"", r"“[^”]*”", r"(?<![\w`])'[^'\n]*'(?![\w`])"):
        for m in re.finditer(pat, text):
            for i in range(m.start() + 1, m.end() - 1):
                if not out[i].isspace():
                    out[i] = "_"
    return "".join(out)


def _strip_emphasis(text: str) -> str:
    """Drop Markdown ** and __ markers outside code spans; code spans stay as written."""
    parts, last = [], 0
    for m in CODE_SPAN.finditer(text):
        parts.append(re.sub(r"(\*\*|__)", "", text[last:m.start()]))
        parts.append(m.group(0))
        last = m.end()
    parts.append(re.sub(r"(\*\*|__)", "", text[last:]))
    return "".join(parts)


def _has_word(masked: str, phrase: str) -> bool:
    return re.search(r"(?<![\w/-])" + re.escape(phrase) + r"(?![\w/-])", masked, re.I) is not None


def _has_modal(masked: str, modal: str) -> bool:
    # "May" with a capital inside a sentence is the month; "may" and "MAY" are modals.
    for m in re.finditer(r"(?<![\w/-])" + modal + r"(?![\w/-])", masked, re.I):
        if m.group(0) == "May" and m.start() > 0:
            continue
        return True
    return False


def _split_top_commas(masked: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for m in re.finditer(r",", masked):
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(masked)))
    return spans


def _sentences(masked: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for m in re.finditer(r"(?<=[.!?])\s+(?=[A-Z\"“(*_`])", masked):
        before = masked[start:m.start()].rstrip(".!?")
        last = before.rsplit(None, 1)[-1].lower() if before.split() else ""
        if last in ABBREVIATIONS:
            continue
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(masked)))
    return spans


def _main_shall(masked: str) -> re.Match | None:
    """The 'shall' that follows the system name; a 'shall' inside a clause is a mention."""
    shalls = list(re.finditer(r"\bshall\b", masked, re.I))
    for m in shalls:
        chunk = masked[: m.start()].rsplit(",", 1)[-1].strip()
        if SUBJECT_START.match(chunk) or PROPER_NAME.match(chunk) or re.fullmatch(r"(?i)it|they", chunk):
            return m
    return shalls[0] if shalls else None




def _skip_trailing(kw: str, before: str, after: str) -> bool:
    """Concessive 'even if' and participial 'while retaining ...' are not conditions."""
    if before.endswith("even") or (kw == "if" and before.endswith(" as")):
        return True
    if kw != "while":
        return False
    nxt = re.match(r"\s+(?:still\s+|also\s+)?([a-z]+)", after)
    return nxt is not None and nxt.group(1).endswith("ing") and nxt.group(1) not in NOT_PARTICIPLE


def _is_selection(kw: str, before: str) -> bool:
    return (kw in ("if", "when") and before.endswith("only")) or kw == "during"


def _selection_warning(kw: str) -> dict:
    what = f"only {kw}" if kw != "during" else "during"
    return {"code": "response-condition", "message":
            f"'{what} ...' inside the response; check whether it selects an outcome of this "
            "response (keep it) or is a condition on the whole requirement (give that case its "
            "own requirement); moving 'only if' in front as If-then inverts it"}


def _trailing_defect(kw: str) -> dict:
    lead = "While" if kw == "while" else "If-then" if kw in ("if", "unless") else "When"
    return {"code": "trailing-condition", "message":
            f"condition '{kw} ...' inside the response; give that case its own requirement with a leading "
            f"{lead} clause and keep the other obligations here (moving the words alone can drop or invert "
            "obligations)"}


def _trailing(response_m: str) -> tuple[dict | None, dict | None]:
    """Classify condition words after the response: (defect, warning)."""
    warning = None
    for m in TRAILING.finditer(response_m):
        kw = m.group(1).lower()
        before = response_m[: m.start()].rstrip().lower()
        if _skip_trailing(kw, before, response_m[m.end():]):
            continue
        if _is_selection(kw, before):
            warning = warning or _selection_warning(kw)
            continue
        return _trailing_defect(kw), None
    return None, warning


class _Req:
    """One requirement under analysis: the text as written, its mask, and the result."""

    def __init__(self, raw: str):
        self.raw = raw
        self.masked = _mask(raw)
        self.defects: list[dict] = []
        self.warnings: list[dict] = []
        self.res = {"pattern": None, "keywords": [], "system": None, "response": None,
                    "defects": self.defects, "warnings": self.warnings}

    def d(self, code: str, msg: str) -> None:
        self.defects.append({"code": code, "message": msg})

    def w(self, code: str, msg: str) -> None:
        self.warnings.append({"code": code, "message": msg})


CLAUSE_KW = re.compile(r"(?i)(where|while|during|when|if|unless|after|before|until|in case|once)\b")
CLAUSE_LEAD = re.compile(r"(?i)\s*(where|while|during|when|if|unless|after|before|until|in case|once)\b")


def _is_passive_word(word: str) -> bool:
    return (word.endswith("ed") and word not in NOT_PASSIVE_ED) or word in IRREGULAR_PP


def _check_sentences(r: _Req) -> None:
    sentences = _sentences(r.masked)
    if len(sentences) <= 1:
        return
    extra = [r.masked[s:e] for s, e in sentences[1:]]
    if any(re.search(r"\b(?:shall|should|must|may|might|could|will)\b", x, re.I) for x in extra):
        r.d("multi-sentence", f"{len(sentences)} sentences, and a later one states behaviour; EARS is one sentence per requirement: split it and give each part its own ID")
    else:
        r.w("multi-sentence", f"{len(sentences)} sentences; EARS is one sentence per requirement: move the extra text out of the requirement")


def _no_shall(r: _Req) -> None:
    for pm in re.finditer(r"(?i)\b(should|may|must|will|can|could|might)\s+(?:not\s+)?be\s+([a-z]+)(?![\w-])", r.masked):
        word = pm.group(2).lower()
        if _is_passive_word(word):
            r.d("passive", f"passive '{pm.group(1).lower()} be {word}' hides who acts; make the system the subject of an active verb")
            break
    weak = [mw for mw in WEAK_MODALS if _has_modal(r.masked, mw)]
    if weak:
        r.d("weak-modal", f"uses '{weak[0]}' and no 'shall'; an EARS requirement states its response with 'shall'")
    else:
        r.d("no-shall", "no 'shall'; write '<clauses>, the <system> shall <response>'")
    _vague(r.masked, r.masked, r.d, r.w)


def _check_response_words(r: _Req, response_m: str) -> None:
    if not response_m:
        r.d("empty-response", "nothing follows 'shall'")
    # Only a 'shall' after the system name is normative; one inside a clause is a mention.
    later = list(re.finditer(r"\bshall\b", response_m, re.I))
    if later:
        r.d("compound", f"{len(later) + 1} 'shall's after the system name; EARS puts one or many responses after one 'shall', and the factory traces one 'shall' per ID: for one obligation drop the repeated 'shall' ('shall A and not B'), for a separate case split it and give it its own ID")
    weak = next((mw for mw in WEAK_IN_RESPONSE if _has_modal(response_m, mw)), None)
    if weak:
        r.d("weak-modal", f"'{weak}' in the response leaves the behaviour optional or mixes modals; use 'shall', or drop the sentence")
    pm = re.match(r"(?i)(?:not\s+)?be\s+([a-z]+)(?![\w-])", response_m)
    if pm and _is_passive_word(pm.group(1).lower()):
        r.d("passive", f"passive 'shall be {pm.group(1).lower()}' hides who acts; make the system the subject of an active verb")
    _vague(r.masked, response_m, r.d, r.w)


def _split_missing_comma(r: _Req, prefix_m: str, prefix_r: str, span: tuple[int, int], lead: re.Match):
    """No comma between clause and subject: split before the last "the" / "then the"."""
    subj_s, subj_e = span
    subject_m = prefix_m[subj_s:subj_e].strip()
    k = None
    for m in re.finditer(r"(?i)\b(?:then\s+)?the\b", subject_m):
        if m.start() > lead.end():
            k = m.start()
    if k is None:
        r.d("no-system", "condition clause but no 'the <system name>' before 'shall'")
        return [(subj_s, subj_e)], "", ""
    r.w("missing-comma", "put a comma between the condition clause and 'the <system>'")
    off = subj_s + (len(prefix_m[subj_s:subj_e]) - len(prefix_m[subj_s:subj_e].lstrip()))
    return [(subj_s, off + k)], prefix_m[off + k:subj_e].strip(), prefix_r[off + k:subj_e].strip()


def _split_subject(r: _Req, prefix_m: str, prefix_r: str):
    """Split the text before 'shall' into clause spans and the subject ('the <system>')."""
    spans = _split_top_commas(prefix_m)
    subj_s, subj_e = spans[-1]
    clause_spans = spans[:-1]
    subject_m = prefix_m[subj_s:subj_e].strip()
    if clause_spans and re.match(r"(?i)(?:and|or)\b", subject_m) and not CLAUSE_LEAD.match(prefix_m):
        # "The loader, parser, and validator shall ...": a list of systems, not clauses.
        r.d("multiple-systems", f"subject '{prefix_r.strip()}' names several systems; EARS has exactly one system name per requirement: split it")
        r.res["system"] = prefix_r.strip()
        return [], "", ""
    lead = re.match(r"(?i)(where|while|during|when|if)\b", subject_m)
    if lead and not clause_spans:
        return _split_missing_comma(r, prefix_m, prefix_r, (subj_s, subj_e), lead)
    return clause_spans, subject_m, prefix_r[subj_s:subj_e].strip()


def _then_in_clause(prefix_m: str, prefix_r: str, clause_spans: list, subject_m: str, subject_r: str):
    """Kiro-style "WHEN x THEN the system SHALL" or "If x then the system": "then" inside the last clause."""
    if not clause_spans:
        return clause_spans, subject_m, subject_r, False
    cs, ce = clause_spans[-1]
    tm = list(re.finditer(r"(?i)\bthen\b", prefix_m[cs:ce]))
    if not tm or subject_m.lower().startswith("then"):
        return clause_spans, subject_m, subject_r, False
    t0 = cs + tm[-1].start()
    subject_m = (prefix_m[t0:ce] + " " + subject_m).strip()
    subject_r = (prefix_r[t0:ce] + " " + subject_r).strip()
    return clause_spans[:-1] + [(cs, t0)], subject_m, subject_r, True


def _keyword_clause(r: _Req, km: re.Match, chunk: str) -> list:
    kw = km.group(1).lower()
    if kw in KEYWORDS:
        return [KEYWORDS[kw], chunk[km.end():].strip()]
    r.d("non-ears-keyword", f"clause starts with '{km.group(1)}'; use While (state), When (event), If-then (unwanted) or Where (feature)")
    return ["?", chunk]


def _parse_clauses(r: _Req, prefix_m: str, prefix_r: str, clause_spans: list) -> list[list]:
    """Each comma chunk starts with a keyword or continues the clause before it."""
    clauses: list[list] = []
    for cs, ce in clause_spans:
        chunk = prefix_m[cs:ce].strip()
        if not chunk:
            r.d("empty-clause", "empty clause between commas")
            continue
        km = CLAUSE_KW.match(chunk)
        if km:
            clauses.append(_keyword_clause(r, km, chunk))
        elif clauses:
            clauses[-1][1] += ", " + chunk
        else:
            r.d("no-keyword", f"condition '{prefix_r[cs:ce].strip()}' has no EARS keyword; start it with While, When, If or Where")
            clauses.append(["?", chunk])
    return clauses


def _check_clause(r: _Req, kw: str, body: str) -> None:
    if kw != "?" and not body.strip(" _"):
        r.d("empty-clause", f"'{kw}' clause has no condition")
    if kw == "when" and STATE_HINT.search(body):
        r.w("when-is-state", "this When clause reads as a state; if the response holds for as long as it is true, use While")
    if kw == "while" and EVENT_HINT.search(body) and not STATE_HINT.search(body):
        r.w("while-is-event", "this While clause reads as an event; if it fires once, use When")


def _check_clauses(r: _Req, clauses: list[list], kws: list[str]) -> None:
    for kw, body in clauses:
        _check_clause(r, kw, body)
    ranks = [RANK[k] for k in kws]
    if ranks != sorted(ranks):
        r.d("clause-order", "clauses out of order; EARS puts preconditions (While) before the trigger (When or If-then); this linter also puts Where first (a convention, not EARS)")
    if kws.count("when") > 1 or kws.count("if") > 1:
        r.d("multiple-triggers", "more than one trigger; EARS allows zero or one trigger per requirement, so split it")


def _then_misuse(r: _Req, kws: list[str]) -> None:
    if "when" in kws:
        r.d("when-then", "'When ... THEN ... SHALL' is not canonical EARS (THEN belongs only to If-then); write 'When <trigger>, the <system> shall <response>'")
    else:
        r.d("then-without-if", "'then' without an If clause; drop it, or make the clause 'If <trigger>, then ...'")


def _check_then(r: _Req, kws: list[str], subject_m: str, then_in_clause: bool) -> None:
    starts_then = re.match(r"(?i)then\b", subject_m) is not None
    has_if = "if" in kws
    if has_if and not starts_then:
        r.d("if-without-then", "an If clause needs 'then': 'If <trigger>, then the <system> shall ...'")
    if starts_then and not has_if:
        _then_misuse(r, kws)
    if then_in_clause and has_if:
        r.w("missing-comma", "put a comma before 'then'")


def _the_system(r: _Req, sys_m: str, sys_r: str) -> None:
    r.res["system"] = re.sub(r"(?i)^the\s+", "", sys_r)
    if re.search(r"(?i)\s(?:and|or)\s+(?:the|a|an)\s", sys_m):
        r.d("multiple-systems", f"subject '{sys_r}' names several systems; EARS has exactly one system name per requirement: split it")
    elif r.res["system"].lower() in GENERIC_SYSTEMS:
        r.w("generic-system", f"'{sys_r}' does not name the system; write the real system name (the token bucket, the drwatt CLI)")


def _check_system(r: _Req, subject_m: str, subject_r: str) -> None:
    sys_m = re.sub(r"(?i)^then\s+", "", subject_m).strip()
    sys_r = re.sub(r"(?i)^then\s+", "", subject_r).strip()
    if not sys_m:
        if not any(x["code"] in ("no-system", "multiple-systems") for x in r.defects):
            r.d("no-system", "no system name before 'shall'")
    elif re.match(r"(?i)the\s+\S", sys_m):
        _the_system(r, sys_m, sys_r)
    elif PROPER_NAME.match(sys_r) and not QUANTIFIER.match(sys_r):
        r.res["system"] = sys_r
        r.w("proper-name", f"subject '{sys_r}' has no 'the'; correct for a product name (AgentBus, `vault run`), otherwise write 'the <system name>'")
    elif re.fullmatch(r"(?i)(it|they|this|that|these|those)", sys_m):
        r.d("no-system", f"pronoun '{sys_r}' as the subject; name the system, so the requirement stands alone")
    else:
        r.d("no-system", f"subject '{sys_r}' is not 'the <system name>'; name the one system that responds")


def _hidden_trigger(r: _Req, response_m: str) -> None:
    ph = next((p for p in HIDDEN_TRIGGER if _has_word(response_m, p)), None)
    if ph:
        r.d("hidden-trigger", f"'{ph}' in the response hides a trigger; move it into a When (or If-then) clause")
        return
    hm = HIDDEN_TRIGGER_RE.search(response_m)
    if hm:
        r.d("hidden-trigger", f"'{hm.group(0)}' in the response hides a trigger; move it into an If-then clause")


def _check_response_conditions(r: _Req, response_m: str) -> None:
    if re.match(r"(?i)be\s+able\s+to\b", response_m):
        r.w("capability", "'shall be able to' states a capability, not a response; state what the system does")
    trailing, selection = _trailing(response_m)
    if trailing:
        r.defects.append(trailing)
    elif selection:
        r.warnings.append(selection)
    _hidden_trigger(r, response_m)


def _pattern(kws: list[str], clauses: list[list]) -> str | None:
    if any(c[0] == "?" for c in clauses):
        return None
    key = frozenset(kws)
    if len(key) >= 2:
        return "complex-unwanted" if "if" in key else "complex"
    return PATTERN_OF.get(key, "complex")


def analyse(text: str, markdown: bool = True) -> dict:
    """Classify one requirement. Returns pattern, keywords, system, response, defects, warnings.

    With markdown=False (manifest statements) the text is analysed exactly as written.
    """
    r = _Req((_strip_emphasis(text) if markdown else text).strip().rstrip(".").strip())
    _check_sentences(r)
    main = _main_shall(r.masked)
    if main is None:
        _no_shall(r)
        return r.res
    prefix_m, response_m = r.masked[: main.start()].rstrip(), r.masked[main.end():].strip()
    prefix_r = r.raw[: main.start()].rstrip()
    r.res["response"] = r.raw[main.end():].strip()
    _check_response_words(r, response_m)
    clause_spans, subject_m, subject_r = _split_subject(r, prefix_m, prefix_r)
    clause_spans, subject_m, subject_r, then_in_clause = _then_in_clause(
        prefix_m, prefix_r, clause_spans, subject_m, subject_r)
    clauses = _parse_clauses(r, prefix_m, prefix_r, clause_spans)
    kws = [c[0] for c in clauses if c[0] != "?"]
    r.res["keywords"] = kws
    _check_clauses(r, clauses, kws)
    _check_then(r, kws, subject_m, then_in_clause)
    _check_system(r, subject_m, subject_r)
    _check_response_conditions(r, response_m)
    r.res["pattern"] = _pattern(kws, clauses)
    return r.res


def _matching(text: str, words: list[str]) -> list[str]:
    return [v for v in words if _has_word(text, v)]


def _quoted(words: list[str]) -> str:
    return ", ".join(f"'{v}'" for v in words)


def _vague(masked: str, response_m: str, d, w) -> None:
    """Vague words: a defect in a response with no number, a warning otherwise."""
    in_response = _matching(response_m, VAGUE)
    elsewhere = [v for v in _matching(masked, VAGUE) if v not in in_response]
    if in_response and not re.search(r"\d", response_m):
        d("untestable", "cannot be checked pass/fail: " + _quoted(in_response)
          + "; replace each with a measurable value or bound")
    elif in_response or elsewhere:
        w("maybe-vague", "check that these words state a bound: " + _quoted(in_response + elsewhere))
    vw = _matching(masked, VAGUE_WARN)
    if vw:
        w("maybe-vague", "check that these words state a bound: " + _quoted(vw))


def drwatt_form(statement: str) -> dict | None:
    """drwatt validate's statement check (DW-002): None when drwatt accepts the statement."""
    if any(form.fullmatch(statement) for form in DRWATT_FORMS):
        return None
    return {"code": "drwatt-form", "message": "drwatt validate rejects this form: it accepts 'The X shall Y.', "
            "'When|While|Where X, the Y shall Z.' and 'If X, then the Y shall Z.' on one line, case as shown, "
            "with a final period"}


def _cells(line: str) -> list[str]:
    """Split a table row on '|' outside code spans and escapes."""
    body = line.strip()
    body = body[1:] if body.startswith("|") else body
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    masked = _mask(body)
    cells, start = [], 0
    for i, ch in enumerate(masked):
        if ch == "|" and (i == 0 or masked[i - 1] != "\\"):
            cells.append(body[start:i].strip())
            start = i + 1
    cells.append(body[start:].strip())
    return cells


def _is_id_lead(line: str, idm: re.Match) -> bool:
    """An ID that is not wrapped and has no delimiter must be followed by a capital (RL-004 The ...).

    That keeps 'SHA-256 digests shall ...' and 'UTF-8 input shall ...' as plain sentences.
    """
    wrapped = idm.start(1) > 0 and line[idm.start(1) - 1] in "*_`["
    after = line[idm.end(1):]
    if wrapped or re.match(r"[\]*_`]*\s*[:.)–—-]", after):
        return True
    return re.match(r"\s+[a-z]", after) is None




ROW_ID = re.compile(r"\**`?(" + ID_RE + r")`?\**")
KEYWORD_LINE = re.compile(r"\s*(?:When|While|If|Where|During|WHEN|WHILE|IF|WHERE|DURING)\b")


def _row_id(cells: list[str]) -> str | None:
    for c in cells:
        cm = ROW_ID.fullmatch(c)
        if cm:
            return cm.group(1)
    return None


def _row_text(cells: list[str], rid: str | None) -> str | None:
    """The first cell that states a requirement; with an ID, a weak modal counts too."""
    for c in cells:
        mc = _mask(c)
        if re.search(r"\bshall\b", mc, re.I) or (rid and re.search(r"\b(?:should|must)\b", mc, re.I)):
            return c
    return None


def _piece_starts(pieces: list[str]) -> list[int]:
    starts, pos = [], 0
    for p in pieces:
        starts.append(pos)
        pos += len(_strip_emphasis(p)) + 1
    return starts


class _Extractor:
    """Line-by-line Markdown reader that collects candidate requirements."""

    def __init__(self):
        self.items: list[dict] = []
        self.fence: tuple[str, int] | None = None
        self.scenario_level = 0
        self.off = False
        self.heading: str | None = None
        self.block: dict | None = None
        self.handlers = (self._in_fence, self._fence_open, self._marker, self._is_off, self._heading,
                         self._in_scenario, self._break, self._table, self._id_line, self._item)

    def flush(self) -> None:
        block, self.block = self.block, None
        if block is None:
            return
        if block["id"]:
            text = " ".join(s.strip() for s in block["parts"]).strip()
            self.items.append({"line": block["line"], "id": block["id"], "text": text, "heading": self.heading})
        else:
            self._plain_block(block)

    def _plain_block(self, block: dict) -> None:
        """A block without an ID: each sentence with 'shall' is one requirement."""
        pieces = [p.strip() for p in block["parts"]]
        # _strip_emphasis changes offsets; map sentences on the stripped text.
        stripped = _strip_emphasis(" ".join(pieces))
        masked = _mask(stripped)
        starts = _piece_starts(pieces)
        for s, e in _sentences(masked):
            if re.search(r"\bshall\b", masked[s:e], re.I):
                lead = s + len(stripped[s:e]) - len(stripped[s:e].lstrip())
                idx = bisect.bisect_right(starts, lead) - 1
                self.items.append({"line": block["line"] + idx, "id": None, "text": stripped[s:e].strip(),
                                   "heading": self.heading})

    def feed(self, n: int, line: str) -> None:
        for handler in self.handlers:
            if handler(n, line):
                return
        self._plain_line(n, line)

    def _in_fence(self, n: int, line: str) -> bool:
        if self.fence is None:
            return False
        if re.match(r"^ {0,3}(" + re.escape(self.fence[0]) + "{" + str(self.fence[1]) + r",})\s*$", line):
            self.fence = None
        return True

    def _fence_open(self, n: int, line: str) -> bool:
        fm = FENCE_OPEN.match(line)
        if not fm:
            return False
        self.flush()
        self.fence = (fm.group(1)[0], len(fm.group(1)))
        return True

    def _marker(self, n: int, line: str) -> bool:
        markers = list(MARKER.finditer(CODE_SPAN.sub(lambda m: "_" * len(m.group(0)), line)))
        if not markers:
            return False
        self.flush()
        self.off = markers[-1].group(1).lower() == "off"
        return True

    def _is_off(self, n: int, line: str) -> bool:
        return self.off

    def _heading(self, n: int, line: str) -> bool:
        hm = HEADING.match(line)
        if not hm:
            return False
        self.flush()
        level = len(hm.group(1))
        if self.scenario_level and level > self.scenario_level:
            return True
        self.scenario_level = level if SCENARIO_HEADING.match(line) else 0
        self.heading = line.strip().lstrip("#").strip()
        return True

    def _in_scenario(self, n: int, line: str) -> bool:
        return bool(self.scenario_level)

    def _break(self, n: int, line: str) -> bool:
        if line.strip() and not line.lstrip().startswith(">"):
            return False
        self.flush()
        return True

    def _table(self, n: int, line: str) -> bool:
        if not line.lstrip().startswith("|"):
            return False
        self.flush()
        if TABLE_SEP.match(line.lstrip()):
            return True
        cells = _cells(line)
        rid = _row_id(cells)
        text = _row_text(cells, rid)
        if text is not None:
            self.items.append({"line": n, "id": rid, "text": text, "heading": self.heading})
        return True

    def _id_line(self, n: int, line: str) -> bool:
        idm = ID_LEAD.match(line)
        if not idm or not _is_id_lead(line, idm):
            return False
        if ITEM_START.match(line) is None and line[: idm.start(1)].strip(" *_`[") != "":
            return False
        self.flush()
        self.block = {"line": n, "id": idm.group(1), "parts": [line[idm.end():]]}
        return True

    def _item(self, n: int, line: str) -> bool:
        if ITEM_START.match(line) is None:
            return False
        self.flush()
        self.block = {"line": n, "id": None, "parts": [ITEM_START.sub("", line, count=1)]}
        return True

    def _plain_line(self, n: int, line: str) -> None:
        # A plain line that opens with an EARS keyword starts a new requirement
        # (Kiro writes "WHEN ...", next line "THE SYSTEM SHALL ...", with no blank line).
        block = self.block
        if block is not None and block["id"] is None and KEYWORD_LINE.match(line) \
                and not block["parts"][-1].rstrip().endswith(","):
            self.flush()
        if self.block is None:
            self.block = {"line": n, "id": None, "parts": [line]}
        else:
            self.block["parts"].append(line)


def extract(lines: list[str]) -> list[dict]:
    """Return candidate requirements: {line, id, text, heading}."""
    ex = _Extractor()
    for n, line in enumerate(lines, 1):
        ex.feed(n, line)
    ex.flush()
    return ex.items


def _finish(r: dict, it: dict, path: str, seen: dict, require_ids: bool) -> dict:
    r.update({"file": path, "line": it["line"], "id": it["id"], "text": it["text"], "heading": it.get("heading")})
    if it["id"]:
        if it["id"] in seen:
            r["defects"].append({"code": "duplicate-id", "message": f"{it['id']} also used at {seen[it['id']]}"})
        else:
            seen[it["id"]] = f"{path}:{it['line']}"
    elif require_ids:
        r["defects"].append({"code": "no-id", "message": "requirement has no ID (for example ABC-001); every formal artifact traces to an ID"})
    return r




def _add_drwatt_form(r: dict, statement: str, drwatt: bool) -> None:
    form = drwatt_form(statement) if drwatt else None
    if form:
        r["defects"].append(form)


def lint_text(text: str, path: str = "<stdin>", require_ids: bool = False, seen: dict | None = None,
              drwatt: bool = False) -> list[dict]:
    seen = {} if seen is None else seen
    reqs = []
    for it in extract(text.splitlines()):
        r = analyse(it["text"])
        _add_drwatt_form(r, _strip_emphasis(it["text"]).strip(), drwatt)
        reqs.append(_finish(r, it, path, seen, require_ids))
    return reqs


def _unique_object(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key {k!r}")
        out[k] = v
    return out




def _manifest_records(text: str, path: str) -> list:
    try:
        doc = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: invalid JSON: {e}") from None
    records = doc.get("requirements") if isinstance(doc, dict) else doc
    if not isinstance(records, list) or not records:
        raise ValueError(f"{path}: expected a nonempty requirements array")
    return records


def _check_record(rec, n: int, path: str) -> None:
    if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) or not isinstance(rec.get("statement"), str):
        raise ValueError(f"{path}: record {n} needs string id and statement fields")


def lint_manifest(text: str, path: str = "requirements.json", seen: dict | None = None,
                  drwatt: bool = False) -> list[dict]:
    """Lint the statements of a drwatt manifest, exactly as written. Raises ValueError on a bad manifest."""
    seen = {} if seen is None else seen
    reqs = []
    for n, rec in enumerate(_manifest_records(text, path), 1):
        _check_record(rec, n, path)
        r = analyse(rec["statement"], markdown=False)
        _add_drwatt_form(r, rec["statement"], drwatt)
        reqs.append(_finish(r, {"line": n, "id": rec["id"], "text": rec["statement"]}, path, seen, False))
    return reqs


def _read(f: str) -> str:
    if f == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(f, "rb") as fh:
            data = fh.read()
    return data.decode("utf-8").removeprefix("﻿")




def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Lint EARS requirements in Markdown, text or drwatt manifest files.")
    ap.add_argument("files", nargs="*", help="files to read; '-' or none reads stdin; *.json is read as a drwatt manifest")
    ap.add_argument("--json", action="store_true", help="print one JSON document")
    ap.add_argument("--manifest", action="store_true", help="read every input as a drwatt requirements.json manifest")
    ap.add_argument("--drwatt", action="store_true", help="also report statements that drwatt validate rejects")
    ap.add_argument("--require-ids", action="store_true", help="a requirement without an ID, or no requirement at all, is a defect")
    ap.add_argument("--strict", action="store_true", help="warnings also make the exit status 1")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only defects and warnings")
    return ap


def _lint_one(f: str, name: str, a: argparse.Namespace, seen: dict) -> list[dict]:
    text = _read(f)
    if a.manifest or f.endswith(".json"):
        return lint_manifest(text, name, seen, a.drwatt)
    return lint_text(text, name, a.require_ids, seen, a.drwatt)


def _lint_files(a: argparse.Namespace) -> list[dict] | None:
    """All requirements of all inputs, or None after an input error."""
    reqs: list[dict] = []
    seen: dict[str, str] = {}
    for f in a.files or ["-"]:
        name = "<stdin>" if f == "-" else f
        try:
            reqs += _lint_one(f, name, a, seen)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            print(f"ears_lint: {name}: {e}", file=sys.stderr)
            return None
    return reqs


def summarize(reqs: list[dict]) -> dict:
    return {"requirements": len(reqs), "with_defects": sum(1 for r in reqs if r["defects"]),
            "defects": sum(len(r["defects"]) for r in reqs), "warnings": sum(len(r["warnings"]) for r in reqs)}


def _print_one(r: dict, quiet: bool) -> None:
    if not quiet or r["defects"] or r["warnings"]:
        print(f"{r['file']}:{r['line']}: {r['id'] or '-'}: {r['pattern'] or 'unclassified'}")
    for x in r["defects"]:
        print(f"  defect {x['code']}: {x['message']}")
    for x in r["warnings"]:
        print(f"  warning {x['code']}: {x['message']}")


def _exit_status(reqs: list[dict], summary: dict, a: argparse.Namespace) -> int:
    if not reqs:
        print("ears_lint: no requirements found", file=sys.stderr)
        if a.require_ids:
            return 1
    return 1 if summary["defects"] or (a.strict and summary["warnings"]) else 0


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    reqs = _lint_files(a)
    if reqs is None:
        return 2
    summary = summarize(reqs)
    if a.json:
        print(json.dumps({"summary": summary, "requirements": reqs}, indent=2, ensure_ascii=False))
    else:
        for r in reqs:
            _print_one(r, a.quiet)
        print(f"{summary['requirements']} requirements, {summary['with_defects']} with defects "
              f"({summary['defects']} defects, {summary['warnings']} warnings)")
    return _exit_status(reqs, summary, a)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(1)
