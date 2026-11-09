#!/usr/bin/env python3
"""Weaken or distort each grammar rule in a plausible way and show that some case
catches it. Exit 0 when every mutant is killed."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check

G = check.grammar
SEG = check.SEGMENT_SET


def g_lower(uri):
    return G(uri.strip().lower())


def g_any_scheme(uri):
    u = uri.strip()
    for p in ("rttp://", "rttps://", "rttp://".upper(), "rttps://".upper()):
        if u.lower().startswith(p):
            u = "rttp://" + u[len(p):]
            break
    return G(u)


def g_exclusions_allowed(uri):
    u = uri.strip()
    prefix = "rttp://"
    if not u.lower().startswith(prefix):
        return G(u)
    body = u[len(prefix):]
    for ch, sub in (("@", "-at-"), ("?", "-q-"), ("#", "-h-"), (":", "-p-")):
        body = body.replace(ch, sub)
    return G(prefix + body)


def g_segments_flexible(uri):
    u = uri.strip()
    if u.lower().startswith("rttp://"):
        rest = u[len("rttp://"):]
        auth = rest.split("/", 1)[0]
        segs = [s for s in auth.split(".") if s]
        if len(segs) >= 1 and all(
                all(c in SEG for c in s) and not s.startswith("-") for s in segs):
            return "accept"
    return G(uri)


def g_empty_segments(uri):
    got = G(uri)
    if isinstance(got, tuple) and got[1] == "segments":
        u = uri.strip()
        rest = u[len("rttp://"):] if u.lower().startswith("rttp://") else u
        auth = rest.split("/", 1)[0]
        if ".." in auth:
            return "accept"
    return got


def g_charset_wide(uri):
    got = G(uri)
    if isinstance(got, tuple) and got[1] == "charset":
        return "accept"
    return got


def g_path_flexible(uri):
    got = G(uri)
    if isinstance(got, tuple) and got[1] == "path":
        return "accept"
    return got


def g_no_tightening(uri):
    got = G(uri)
    if isinstance(got, tuple) and got[1] == "leading_hyphen":
        return "accept"
    return got


def g_whitespace_stripped(uri):
    got = G(uri)
    if isinstance(got, tuple) and got[1] == "whitespace":
        return G(uri.strip())
    return got


def g_percent_reject(uri):
    got = G(uri)
    return "reject_percent" if got == "ambiguous" else got


def g_percent_normalise(uri):
    got = G(uri)
    return "accept" if got == "ambiguous" else got


def g_accept_all(uri):
    return "accept"


def g_reject_all(uri):
    return ("reject", "whitespace")


M = {
 "grammar: uppercase normalised away": g_lower,
 "grammar: any scheme accepted": g_any_scheme,
 "grammar: userinfo/port/query/fragment allowed": g_exclusions_allowed,
 "grammar: segment count flexible": g_segments_flexible,
 "grammar: empty segments allowed": g_empty_segments,
 "grammar: charset widened": g_charset_wide,
 "grammar: path flexible": g_path_flexible,
 "grammar: leading-hyphen tightening dropped": g_no_tightening,
 "grammar: whitespace stripped silently": g_whitespace_stripped,
 "grammar: percent-encoding always rejected": g_percent_reject,
 "grammar: percent-encoding silently normalised": g_percent_normalise,
 "grammar: always accept": g_accept_all,
 "grammar: always reject": g_reject_all,
}


def main():
    cases = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))["cases"]
    killed = 0
    for name, fn in M.items():
        hits = [c["id"] for c in cases if check.evaluate(c, fn) != c["expect"]]
        killed += bool(hits)
        print(("killed " if hits else "ALIVE  ") + f"{name:45} by {','.join(hits) or '-'}")
    print(f"{killed}/{len(M)} mutants killed")
    return 0 if killed == len(M) else 1

if __name__ == "__main__":
    sys.exit(main())
