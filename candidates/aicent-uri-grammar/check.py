#!/usr/bin/env python3
"""Recompute each case's grammar decision from the URI string, compare with the
declared expectation. The grammar is the ABNF of draft-li-rttp-iqa-addressing-02
sec. 4.1 plus the exclusions of sec. 4.2, transcribed from the pinned text, with
one disclosed tightening (leading hyphen, author decision 2026-11-09). Standard
library only. Exit 0 when every case agrees, 1 otherwise."""
import json, os, sys

SEGMENT_SET = set("abcdefghijklmnopqrstuvwxyz0123456789-")  # %x61-7A / DIGIT / "-"


def grammar(uri):
    """Returns "accept", "ambiguous", or ("reject", reason)."""
    if uri != uri.strip():
        return ("reject", "whitespace")
    if uri.startswith("rttps://"):
        # "There is no 'rttps' scheme and no fallback."
        return ("reject", "scheme")
    if not uri.startswith("rttp://"):
        if uri.lower().startswith("rttp://"):
            # "The canonical form is lowercase US-ASCII": uppercase is invalid
            # input, not a formatting difference; a parser MUST NOT normalise it.
            return ("reject", "uppercase")
        return ("reject", "scheme")
    rest = uri[len("rttp://"):]
    if "%" in rest:
        # "a canonical URI contains no percent-encoded octets; a parser MAY
        # reject such input rather than normalising it" - both licensed.
        return "ambiguous"
    for ch, why in (("@", "userinfo"), (":", "port"), ("?", "query"), ("#", "fragment")):
        if ch in rest:
            return ("reject", why)
    if "/" in rest:
        authority, action = rest.split("/", 1)
        if "/" in action or action == "":
            # the action is a single path segment "/" 1*( ... )
            return ("reject", "path")
        if any(c.isupper() for c in action):
            return ("reject", "uppercase")
        if any(c not in SEGMENT_SET for c in action):
            return ("reject", "charset")
    else:
        authority = rest
    segments = authority.split(".")
    if len(segments) != 3 or any(s == "" for s in segments):
        # "The authority is exactly three dot-separated segments"
        return ("reject", "segments")
    for s in segments:
        if any(c.isupper() for c in s):
            return ("reject", "uppercase")
        if any(c not in SEGMENT_SET for c in s):
            return ("reject", "charset")
        if s.startswith("-"):
            # tightening: the ABNF literal admits a leading hyphen; the author
            # decision of 2026-11-09 (-03) rejects it. Disclosed in vectors.json.
            return ("reject", "leading_hyphen")
    return "accept"


def evaluate(case, fn=grammar):
    got = fn(case["uri"])
    expect = case["expect"]
    if expect == "ambiguous":
        if got == "ambiguous":
            return "ambiguous"
        return "reject" if isinstance(got, tuple) else "accept"
    if expect == "reject":
        if isinstance(got, tuple):
            return "reject" if got[1] == case.get("reject_reason") else "reject:" + got[1]
        return got
    return got


def r_grammar(case):
    return evaluate(case)


def main(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")):
    doc = json.load(open(path, encoding="utf-8"))
    bad = 0
    for c in doc["cases"]:
        got = r_grammar(c)
        flag = "BAD" if got != c["expect"] else "ok "
        bad += got != c["expect"]
        extra = c.get("reject_reason", "")
        print(f"{flag} {c['id']:7} expect={c['expect']:9} {extra:14} {c['name'][:52]}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
