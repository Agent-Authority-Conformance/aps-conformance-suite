# Provenance

## Rule under test

- Scope: agreed on cosai-oasis/ws4-secure-design-agentic-systems#149, in the
  exchange between imran-siddique (comment of 2026-09-09T04:01:23Z), aeoess
  (2026-09-09T04:50:37Z and 2026-09-09T20:38:10Z and 2026-09-09T23:07:45Z),
  Levaj2000 (2026-09-09T21:13:45Z) and darklordVirtual
  (2026-09-09T22:27:13Z). Status: open RFC, unapproved. Comment URLs:
  - https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149#issuecomment-5595582544
  - https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149#issuecomment-5595992996
  - https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149#issuecomment-5608392565
  - https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149#issuecomment-5608834772
  - https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149#issuecomment-5609594123
  - https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149#issuecomment-5609968253
- Verdict vocabulary: the candidate rule on cosai-oasis/ws4-secure-design-agentic-systems#189,
  stated by aeoess (2026-09-11T17:57:28Z) and refined through 2026-09-19T21:06:14Z
  by darklordVirtual, Levaj2000 and imran-siddique. Also open, also unapproved.
  Reused directly from `interop/cosai-ws4-189-evidence-sufficiency/` in this
  suite, which already implements it: `pass | fail | not_established`, with
  malformed input, an unsupported verification path, parser failure and an
  internal error excluded from the vocabulary rather than folded into
  `not_established`.
- Observation-coverage scope+claim binding: added to the #189 candidate in
  this suite's PR #98 (`Agent-Authority-Conformance/aps-conformance-suite#98`),
  after chernistry raised per-claim binding on #189 from an independent
  implementation (2026-09-17T06:42:01Z) and imran-siddique asked for it in the
  rule text (2026-09-19T04:26:57Z). Applied here identically: observation
  coverage must be bound to both the evaluated scope and the evaluated claim
  instance (`context.claim_ref`), and a mismatch on either leaves the verdict
  `not_established`, never `pass` and never `fail`.

## REMORA prior art

Repository `darklordVirtual/REMORA-research`, tag/ref `decision-to-effect-v1`,
commit `b0e0cbee`. Per the agreement on #149 between darklordVirtual
(2026-09-09T22:27:13Z, "treat V-02 and V-13 as prior art and re-express the
scenarios ... rather than making the corpus depend on the REMORA fixtures or
adapter") and aeoess (2026-09-09T23:07:45Z, "I'll express V-02 and V-13 as new
cases in the Apache corpus and keep a pinned REMORA reference for
provenance"), none of REMORA's code or fixture files are copied here. Each
vector below is re-expressed as an independent fixture in this corpus's own
evidence shape.

| REMORA vector | scenario | re-expressed as |
|---|---|---|
| V-02 (exact-call mutation) | arguments mutated after authorization | `CAND-COSAI-149-D2E-EXACT-01` (dispatched anyway, fail), `CAND-COSAI-149-D2E-EXACT-02` (refused citing the mismatch, pass) |
| V-13 (effect mismatch) | tool self-report disagrees with independent verification | `CAND-COSAI-149-D2E-EFFECT-01` (fail) |
| V-14 (`EFFECT_INDETERMINATE` runtime outcome) | runtime reports an indeterminate effect | `CAND-COSAI-149-D2E-EFFECT-03` (not_established, with the runtime outcome carried strictly as evidence) |

`non_bypassability` has no REMORA prior art. aeoess on #149
(2026-09-09T20:38:10Z): "No REMORA vector currently expresses this, because
its effectful adapter methods all require the handle returned by
`authorize`." Both non_bypassability cases (`CAND-COSAI-149-D2E-BYPASS-01`,
`CAND-COSAI-149-D2E-BYPASS-02`) are new, lab-authored, with no source vector.

`CAND-COSAI-149-D2E-EFFECT-02` (read-back unavailable) is also new,
lab-authored. It isolates the `not_established`/`read_back` path that
Levaj2000 and aeoess agreed belongs in the shape on 2026-09-09, but it is not
one of the three REMORA vectors named on the issue.

The four positive-control cases (`CAND-COSAI-149-D2E-POS-01-*`) are
lab-authored, exercising the same authorized-and-agreeing scenario against
each of the three properties.

## Suite pin

Authored against a worktree of `Agent-Authority-Conformance/aps-conformance-suite`
branched from `origin/main` at commit `d058112` (merge of PR #119).
