# zhaoxinghua09-cell — 52 negative-control cases for delegated authority

Candidate test material. Not a reviewed fixture, not counted in any corpus total, and not to be
described as admitted to, accepted by, validated by or certified by the lab.

- **Submitter:** `zhaoxinghua09-cell` (Xinghua Zhao). GitHub issue where this was first raised: #255.
- **Target:** `draft-pidlisnyi-aps-04`, §4.2 — delegated authority: narrowing, revocation and
  propagation, authorization before dispatch, session-level admission — with the §4.1 action-ref
  projection used where a case has to name the action. The clause ids this set is aimed at are
  `REQ-4.2-2` and `REQ-4.2-3` (both listed as NOT EXERCISED in `docs/ID-COVERAGE.md` at
  `b0bf645c`), plus `REQ-4.2-1` and the §4.1 ref checks a dispatch has to pass first. The mapping
  from draft clauses to these families is **my reading of the text**, not something the draft
  states in a table; no one else has confirmed the mapping.

## What it is

Four families, 52 cases, every case a refusal with a fixed expected verdict. The point of the set
is that a verifier which accepts everything passes none of them; a verifier which refuses
everything also fails, because each family carries at least one case that must be allowed.

| family | cases | what a case asks |
|---|---|---|
| `narrowing` | 11 | does a child grant stay inside the parent's seven facets; missing facet vs unrecognised facet vs widened facet are three different outcomes |
| `cascade-revocation` | 10 | does revoking an ancestor invalidate what depends on it, and is evidence of a revocation kept distinct from the cause of one |
| `pre-dispatch-authorization` | 12 | is authorization checked before the action is taken, and when several facets fail at once, which is the primary code and which are recorded beside it |
| `session-gate` | 19 | does a session path hold at five layers — structure, chain signature, a signed and issuer-bound and leaf-bound policy envelope, revocation/expiry, two ceilings (root grant and this hop's granted authority) — before dispatch |

Terms here (`facet`, `envelope`, `L1`–`L5`, and the reason codes) are this submitter's vocabulary
and do not become corpus vocabulary.

## Source

- Repository `zhaoxinghua09-cell/lgd-passport`, commit `203cb9eee5d0d85dbe24426f3b0ca2416987d15c`,
  also reachable as tag `v2.0.0`
- Path in that commit: `zc/v2_candidates/`
- **Durable identity is the commit plus the tree, not the archive bytes.** Archives fetched for the
  same commit can differ: a fetch made minutes after the commit landed came back 252,231 bytes /
  `c21a0241…`, while three consecutive fetches later gave 252,252 bytes / `23cc4e75…`, byte-identical
  to each other, with the same 91 files and the same tree. Quote the archive hash as "as fetched on
  <date>", never as identity.
- `zc/` identity, computable from the API without any archive:
  - tree sha `f507df2b25d9647e27e5fe5cfaae74e051d1a92c` (91 blobs, 96 entries)
  - content digest `sha256 6450db3c98f66ff6d2358db4db6940095862dad923331d3b6153274cc84204c9` over one
    line per entry, `<mode> <type> <blob sha> zc/<path>`, sorted, newline-terminated
- Check performed 2026-11-28: the archive fetched by that commit came back 252,252 bytes /
  `23cc4e75759189569ec2df49a17f1c2be983227e58db019254de6ab8bf42ab91`, and the nine `runners/*`
  files here are byte-identical (sha256) to `zc/v2_candidates/` inside it.
- The four `vectors/*.json` files are not in the repository; they were exported by
  `v2_candidates/` at that commit from fixed constants, and every `expect` in them is the value
  both implementations at that commit produce.
- Fetch by **commit or tag**, never by branch: the branch archive is served through a CDN that can
  return a stale archive after a push.
- License: Apache-2.0 (LICENSE at the repository root of the pinned commit)
- No credentials, live keys or personal data. The Ed25519 keys in `cascade-revocation` are derived
  deterministically from a public seed string and are test-only.

## Files

```
vectors/narrowing.json                11 cases, {profile, cases}
vectors/cascade-revocation.json       10 cases, each with its signed chain and revocations
vectors/pre-dispatch-authorization.json  12 cases, policy + call + state
vectors/session-gate.json             19 cases, chain + envelope + policy + call + ceilings
runners/                              the two implementations and the parity checker, copied
                                      byte-for-byte from the pinned commit
summary.json                          family sizes and expected-value sets
CHECKSUMS.sha256                       every file above
```

## How to reproduce

1. Fetch the tarball by the commit above and check the sha256.
2. `python zc/run_all.py` → expect `VERDICT MATCH` (106/106 on each of two implementations).
3. `python zc/v2_candidates/parity_check.py` → expect `VERDICT: PASS` over the 52 cases, comparing
   verdict, reason code and layer name per case.
4. Negative control on the negative controls: set any `expect` in a vector file to `__TAMPERED__`
   and rerun step 3 → expect a mismatch naming that case id, not a pass.

`parity_check.py` in `runners/` is the same file as path in step 3; the vectors here are exported
from the same commit, so the counts must agree (11 / 10 / 12 / 19).

## Verification split

Per claim, one entry. Only the labels `Mode A` / `Mode B` and `author-produced` / `independent` are
used; no other wording stands in for them.

| layer / claim | runner | mode | authorship | implementation |
|---|---|---|---|---|
| structure — facet presence and unknown-facet classification, 11 cases | `narrowing_check.py` | Mode A | author-produced | lgd-passport v2 (Python) |
| structure — same 11 cases recomputed | `narrowing_check.mjs` | Mode B | author-produced | lgd-passport v2 (Node) |
| chain — revocation cascade with per-hop signatures, 10 cases | `cascade_revoke.py` | Mode A | author-produced | lgd-passport v2 (Python) |
| chain — same 10 cases with signatures verified in `node:crypto`, 10 cases | `cascade_revoke.mjs` | Mode B | author-produced | lgd-passport v2 (Node) |
| pre-dispatch — ordered facet check and first-failure code, 12 cases | `mcp_predispatch.py` | Mode A | author-produced | lgd-passport v2 (Python) |
| pre-dispatch — same 12 cases recomputed | `mcp_predispatch.mjs` | Mode B | author-produced | lgd-passport v2 (Node) |
| session — five-layer gate with envelope binding and two ceilings, 19 cases | `session_gate.py` | Mode A | author-produced | lgd-passport v2 (Python) |
| session — same 19 cases recomputed | `session_gate.mjs` | Mode B | author-produced | lgd-passport v2 (Node) |

Every entry above is `author-produced`: the same person wrote the vectors and both implementations.
Mode B here means a second implementation recomputes the verdict; it does not mean an independent
party did anything.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## What this does not prove

- Agreement with APS, any APS profile or any other protocol. None is established, in either
  direction; the overlap in vocabulary with `draft-pidlisnyi-aps-04` §4.1/§4.2 is asserted by the
  submitter and has not been checked by anyone else.
- Coverage. 52 is the size of this set; there is no denominator for "all delegated-authority cases"
  and none is implied.
- Correctness of the rule sets. Two implementations agreeing shows the rule set is implementable
  twice and unambiguous enough to be recomputed, nothing more.
- Time, freshness or trusted timestamping. Deliberately out of scope; the two `time` fields are
  fixed constants for reproducibility, not a clock claim.
- Independence. Nothing here carries an independent record, and the submitter will not describe any
  later reproduction as admitted, accepted, validated or certified, or edit a contradicting one.
