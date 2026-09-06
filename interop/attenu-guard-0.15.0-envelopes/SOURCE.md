# attenu-guard 0.15.0: observer-envelope vectors at revision envelope_vectors_v1.2, three author-produced runners and two independent ones

Artifact: `attenu_guard/vectors/envelopes/envelope_vectors_v1.json`, revision
`envelope_vectors_v1.2`, 19 cases, Ed25519 observer envelopes over committed ledger entries of
the same nine-entry ledger the bundle file uses. Announced by rafaelasor on a2aproject/A2A#1575
on 2026-09-06 (comment 5557848990) as shipped in attenu-guard 0.15.0 on PyPI and attenu-guard
0.9.0 on npm, sha256
`a8be5ff764a86122ca09e94340416b7169531bf5d0cc76a0b1fc87f8272eb16e`, 197346 bytes. This is the
successor to `interop/attenu-guard-0.13.0-envelopes/`, which covers revision
`envelope_vectors_v1.1` and its 18 cases: same scope, same shape, same three runners, plus two
runs of externally authored checkers that the 0.13.0 record did not have.

The single new row, `reject_duplicate_subject_defective_second`, was proposed by Xuebin Ma
(@XuebinMa) in comment 5556849470 on the same thread, four hours before the release, after he
scored revision v1.1 at 18 of 18 with his own Rust verifier. Rows 1 to 18 did not move.

## Byte identity of the vector file across its published locations

| location | identity |
|---|---|
| PyPI wheel attenu_guard-0.15.0-py3-none-any.whl, sha256 f838b06fb6f0a4d7521f70f4753ec934399e27221f0c9522571da002d2716736, 356925 bytes, path `attenu_guard/vectors/envelopes/envelope_vectors_v1.json` | file sha256 a8be5ff764a86122ca09e94340416b7169531bf5d0cc76a0b1fc87f8272eb16e, git blob fb9f8bcb |
| attenu-io/attenu-guard commit 8a8d598e2036d6815b50df01b776a13777c1d72b (tag v0.15.0), `src/attenu_guard/vectors/envelopes/` | blob fb9f8bcb, file sha256 a8be5ff7 |
| attenu-io/attenu-guard commit 8a8d598e2036d6815b50df01b776a13777c1d72b, `tests/vectors/envelopes/` | blob fb9f8bcb, file sha256 a8be5ff7 |
| attenu-io/attenu-guard-ts commit ae055c92ce2f23e476c42b1a742c3babfa543bb2 (tag v0.9.0), `test/fixtures/vectors/envelopes/` | blob fb9f8bcb, file sha256 a8be5ff7 |

One object, four locations, 197346 bytes, and the sha256 the announcement names. Both commits
were resolved to their release tags rather than taken on trust: `v0.15.0` dereferences to
8a8d598e and `v0.9.0` to ae055c92, the two pins safal207 published in his correction comment
5559148305.

The npm package `attenu-guard` 0.9.0 (tarball sha256
a849ed7b4c5cedeb50423332354af5bc3db44b35cdeb585bf7ebd8c20cc8d7f1, 246172 bytes, registry
`unpackedSize` 1299337 over 128 files) ships no vector file. This is recorded as a checked
absence rather than as a restatement of the announcement: the tarball was downloaded and listed,
it holds 128 entries, three of them JSON, and all three are `package.json`
(`package/package.json`, `package/dist/cjs/package.json`, `package/dist/esm/package.json`). A
listing filtered for any path containing `vector`, `envelope` or `fixture` returns nothing. The
TypeScript side carries the vectors in its repository only, as it did at 0.8.0 and at 0.6.0.

### Rows 1 to 18 against revision v1.1

The v1.1 file was fetched again from its own pinned sources for this comparison and nothing was
carried from the 0.13.0 record: tag `v0.13.0` of attenu-io/attenu-guard dereferences to commit
8042a0ce33a9f8a7bf54a1917d5e8a0ac0344084 and tag `v0.8.0` of attenu-io/attenu-guard-ts to
51eebfc957c47aeba3738e5f1f67e8d3d55da50f, and all three paths there return sha256
6a57d75ebec881d39d5a1805793a20f9a6d7bff021b70782dcb57c43b276df64, 185227 bytes, git blob
112d5eca, which is what the 0.13.0 record pins.

Rows 1 to 18 are byte-identical as a JSON-array prefix, not merely semantically equal. The
longest common byte prefix of the two whole files is 183428 bytes, and the divergence there is
the comma and brace that open case 19: v1.1 closes the array and v1.2 continues it. Each of the
18 case elements was located by exact span and compared as raw text: 18 of 18 byte-identical,
and the whole `cases[1..18]` region hashes to
4ca75030fd2b3597dfbb6719938a37f641a0678c16ac6699fb7f05a21d9ad383 in both files. Outside the
array the only changed top-level field is `revision`; `version` stays `envelope_vectors_v1`,
which is the compatibility contract, and `description` is unchanged.

## Direction 1: the author's runners (Mode A), Python and TypeScript

Python, from PyPI:

    python3 -m venv pkg && pkg/bin/pip install attenu-guard==0.15.0
    pkg/bin/python  (attenu_guard.evidence.verify_bundle(bundle, signer, witness_keys=...)
                     over vectors.load_envelope_vectors(), signer wrapped as
                     attenu_guard.wire.HS256TestSigner(secret, kid), and envelope_bytes
                     supplied from the case's raw_hex where it carries one)

The installed package's own copy of the file was checked before scoring: the path
`attenu_guard/vectors/envelopes/envelope_vectors_v1.json` inside the venv is 197346 bytes at
sha256 a8be5ff7, the same object as the table above.

Result (results-package-verify-envelopes.txt, verbatim): 19/19. Every verdict as declared, every
required {reason, seq, node} present at its declared position, and `expect_states` matched entry
by entry for all nine entries of every case.

TypeScript, the npm package, scored over the byte-identical copy of the same file:

    npm init -y && npm install attenu-guard@0.9.0
    node run.js <envelope_vectors_v1.json>   (verifyBundle(bundle, signer, {witnessKeys, envelopeBytes}))

Result (results-ts-verify-envelopes.txt, verbatim): 19/19, and the same failure set on every case
as the Python runner, position for position.

The two shape notes the 0.13.0 record made about the comparison still hold and are still printed
in the results files themselves: `report["envelopes"]["states"]` is keyed by integer while
`expect_states` is keyed by string, so the report's keys are stringified before comparison, and
`report["failure_details"]` entries carry `call_id` and `detail` beside `{reason, seq, node}`, so
each is projected to the triple before the presence check. One further note belongs to this
revision's runner rather than to the vectors: `reject_rehashed_chain_unanchored` carries a null
`signer`, so the harness passes `signer=None` for that row instead of constructing an
`HS256TestSigner`.

## Direction 2: clean-room verifier written from the README (Mode B)

`cleanroom/verify_envelope_v1.py` is the file the 0.13.0 record merged, copied here unchanged.
Both copies hash to sha256 96d87f407af120e6c5560bf9f59c569e875b2871213a418a3c0511071ad57d3e.
It was written 2026-09-04 by aeoess from `tests/vectors/README.md` at attenu-io/attenu-guard
v0.13.0 and from the vector file's own description field, with no attenu_guard code read or
imported. Dependencies unchanged: rfc8785 0.1.4, cryptography 50.0.1, hashlib, hmac.

    python3 -m venv cr && cr/bin/pip install -r cleanroom/requirements.txt
    cr/bin/python cleanroom/verify_envelope_v1.py <path to envelope_vectors_v1.json>

Result (results-cleanroom-verify-envelopes.txt, verbatim): 19 ok, 0 mismatches, exit 0.

**Row 19 passes under the unchanged script, and that is the finding.** No `_1_2` variant of the
verifier was written and none was needed. The rule row 19 discriminates, that an entry is claimed
as soon as `subject.seq` finds it and before the rest of the envelope is judged, was already
implemented when the file was written on 2026-09-04: `verify_envelopes` adds the located entry to
`claimed` and only then calls `_judge_envelope`, and the docstring names the rule under
"claim first" as one of the envelope rules taken from the README. Row 19 is therefore a
discriminator of semantics this lab had already written down, not a new requirement it had to
meet. Two days separate the writing from the row.

### R-CLAIM-MUTATION: the mutation that makes the claim false

A green result on row 19 is a claim about what the clean-room enforces, so it gets one mutation
built to break it. In a scratch copy only, never in `cleanroom/`, the order was reversed so that a
defective envelope is judged and rejected before its subject is claimed. The whole change:

    +        # judge the envelope FIRST and let a defective one bail out
    +        # before its subject is ever claimed.
    +        bad = _judge_envelope(env, subject, found, recomputed, trusted, raw_hex, fail, at_seq, at_node)
    +        if bad:
    +            continue
             if key in claimed:
                 fail('envelope_duplicate_subject', at_seq, at_node)
                 ...
             claimed.add(key)
    -        bad = _judge_envelope(env, subject, found, recomputed, trusted, raw_hex, fail, at_seq, at_node)
    -        if not bad and found is not None:
    +        if found is not None:
                 states[str(found['seq'])] = 'witness-signed'

No expectation was altered to produce the result. The mutated copy over the same 19 cases:

    FAIL reject_duplicate_subject_defective_second expect=reject got=reject states=DIFFER
      required=[{"node": "vectors:n1", "reason": "envelope_duplicate_subject", "seq": 1}]
      reported=[{"reason": "envelope_bad_signature", "seq": 1, "node": "vectors:n1"}]
      MISSING=[{"node": "vectors:n1", "reason": "envelope_duplicate_subject", "seq": 1}]
      extra=[{"reason": "envelope_bad_signature", "seq": 1, "node": "vectors:n1"}]
      witness-signed=1(matched)

    18 ok, 1 mismatches, 19 cases
    exit 1

Side by side on that row:

    UNCHANGED failures : [{"reason": "envelope_duplicate_subject", "seq": 1, "node": "vectors:n1"}]
    UNCHANGED states[1]: process-asserted
    MUTATED   failures : [{"reason": "envelope_bad_signature", "seq": 1, "node": "vectors:n1"}]
    MUTATED   states[1]: witness-signed

    required by the row : [{"node": "vectors:n1", "reason": "envelope_duplicate_subject", "seq": 1}]
    required state seq 1: process-asserted

The bundle still rejects either way, so acceptance does not separate the two implementations. What
separates them is the state: the mutated verifier reports `envelope_bad_signature` instead of the
required `envelope_duplicate_subject`, never reaches the duplicate rule, and leaves seq 1 reading
`witness-signed` on the strength of the first envelope alone, while two witnesses contradicted each
other over that entry. That is the state lie the row exists to catch, and the row catches it. The
other 18 rows are unmoved by the mutation, which is the point of the row: on rows where both
envelopes are sound, both orderings reach the same answer.

## Direction 3: independent runs, the lab executing two published external verifiers

Neither checker below was written by this lab, and neither was written by the author of the
vectors. Under the label rule in CONTRIBUTING, independence follows the implementation that
supplies the substantive recomputation, so both runs are Mode B, independent.

safal207's Python verifier (results-independent-safal207-verify-envelopes.txt, verbatim):
`verify_envelope_vectors.py` at git blob 194a68e4c89653e7c819f1ed12156f758bfd7de9, sha256
e814afb84f7e9ecaff4183a3a685f249ca6065309e293e4a224ec9afbba64a8d, in safal207/ContractGraph-QA at
commit 3747cd2518ecee4051246c08ef24114f5fea432e, path
`proofs/attenu-envelope-v1.2-independent/`. The blob digest was confirmed before the file was
run. It imports no attenu_guard code; the one further file it loads,
`proofs/attenu-guard-v0.12.1-independent/independent_bundle_verifier.py`, is Python standard
library only, so the run went ahead. Fresh venv, cryptography 46.0.4 and nothing else, which is
the single dependency its own workflow installs; Python 3.14.6 here against 3.12.13 there.

Two runs, because the pinned blob and the pinned wrapper answer different questions. Invoked
directly, the blob reports agree 19, disagree 0, accept 5, reject 14, and exits 1 with
`overall: DISAGREE`. All three of its complaints are about the pinned subject and none about a
verdict: the blob carries the v1.1 digest, the v1.1 revision string and an 18-name case list, and
computes `overall` as `agree == len(CASE_NAMES)`. Run through `run_pinned_proof.py`, which is
pinned in the same directory and which rebinds those constants without touching an envelope rule
or an ordering, the same 19 verdicts read `overall: AGREE` at exit 0. The generated report is
byte-identical to the `report.json` he committed, sha256
4328c5a38e647b601b73fa5ff4a8b8f9f5375296318ba1a5d440372c9edbbd6b over 9272 bytes, which is the
digest his comment announces.

XuebinMa's Rust verifier (results-independent-xuebinma-verify-envelopes.txt, verbatim):
crate `guard-verify` in XuebinMa/agent-guard at pin e7eaba2c14a87cc7d0fb672f7a997e303df18d8c,
run with the command his comment publishes and with no change to his code. cargo 1.95.0, rustc
1.95.0, dev profile. Over his own vendored fixture, which is the v1.1 file at sha256 6a57d75e:
18 of 18 conformant, exit 0, with both permitted extras landing where the other runners put them.
Over the released v1.2 bytes placed at that same fixture path: 19 of 19 conformant, exit 0. His
vendored file was restored afterwards and his tree left as cloned, `git status --short` empty at
e7eaba2c.

That pin is dated 2026-09-06T04:00:05Z and rafaelasor's release comment is 07:51:08Z, so the
verifier predates the publication of the row it scores. It neither refuses the unfamiliar
revision string nor mismatches on the new case. The claim-first ordering was already implemented
there too, which is why no post-row-19 pin of his was needed to close anything.

### The two authors' own runs, recorded as they reported them

XuebinMa, comment 5556849470, 2026-09-06T04:19:06Z, over revision v1.1 at pin e7eaba2c: 18 of 18,
five accepting and thirteen rejecting. Mode B, author-produced, because he wrote the checker that
supplies the recomputation. His stated boundary, wording preserved, punctuation normalized:
"Independent reproduction of the released envelope corpus at that pinned boundary. Not verifier
completeness, not runtime correctness, not certification. A full score says only that no one has
yet attacked a path this corpus does not cover, which is the whole reason for the section above."
One em dash was replaced with a comma to satisfy this repository's scan policy; nothing else in
the passage was changed, and it is not offered as verbatim.

safal207, comments 5559145070 and 5559148305, 2026-09-06T12:15:31Z and 12:16:06Z, over revision
v1.2 at blob 194a68e4: 19 of 19 agree. Mode B, author-produced, same reason. His stated boundary,
carried verbatim and needing no normalization: "Bounded claim only: independent agreement with
this frozen 19-case interoperability corpus. No claim of global capture completeness, intended
witness coverage, witness freshness/non-equivocation, deployment non-bypassability, integrity of a
stripped top-level `envelopes` array, specification completeness, A2A adoption, certification, or
endorsement." The second comment corrects two source-pin lines that his mail client masked; the
corrected pins are the ones this record uses.

## Where the runners differ, recorded and not adjudicated

They do not differ, within what each run publishes. On all 19 cases the five runners agree on the
verdict, on every required `{reason, seq, node}` at its declared position, and on the state of
every entry.

Four of the five publish their full observed failure list, and in those four the permitted extras
are the same objects in the same places: `reject_non_canonical` reports `envelope_bad_signature`
beside the required `envelope_non_canonical`, which the README names as permitted for a verifier
that recomputes the signing preimage, and `reject_rehashed_chain_anchored` reports the mismatch at
seq 2 beside the required one at seq 1, which the README names as an extra on a covered hop. The
fifth, safal207's verifier, publishes four booleans per case, `verdict`, `minimal_failures`,
`failure_position_rule` and `entry_states`, and no observed failure list, so its extras cannot be
compared from its report and are not claimed here to match. All four booleans are true on all 19
of its rows.

Row 19 permits `envelope_bad_signature` at seq 1 as an extra beside the required
`envelope_duplicate_subject`. None of the four runners that show their list takes it: each stops
at the duplicate rule and reports the required failure alone. Reporting the extra would be
conformant; reporting it instead of the required failure would not be, which is exactly what the
mutation above did.

safal207's report reaches the same conclusion from the other side, by scoring the row's three
parts separately rather than by listing extras: the full row requires
`envelope_duplicate_subject` at seq 1 with seq 1 at `process-asserted`; the first envelope alone
carries no failure and leaves seq 1 `witness-signed`; the defective second envelope alone
requires `envelope_bad_signature` at seq 1 with seq 1 at `process-asserted`. Those three
observations are the same discrimination the mutation above demonstrates by breaking it.

The two readings the clean-room had to choose at 0.13.0, an unknown `v` or `typ` stopping the
remaining checks and a malformed `witness_keys` row raising rather than folding into a finding,
are still unseparated by any vector in this file. Row 19 does not touch either.

## Verification split

- Author's runner over the author's vectors, Python (direction 1); runner: aeoess via PyPI
  attenu-guard 0.15.0; Mode A; author-produced; implementation: attenu-guard 0.15.0. Author-produced
  because the implementation supplying the recomputation is the vectors' own author's.
- Author's runner over the author's vectors, TypeScript (direction 1); runner: aeoess via the
  published npm package; Mode A; author-produced; implementation: attenu-guard 0.9.0 on npm. Same
  relationship.
- Clean-room README-derived verifier over the author's vectors (direction 2); runner: aeoess;
  Mode B; author-produced; implementation: cleanroom/verify_envelope_v1.py, authored by the
  runner.
- safal207's verifier over the author's vectors, executed by the lab (direction 3); runner:
  aeoess; Mode B; independent; implementation: verify_envelope_vectors.py at blob 194a68e4,
  authored by safal207.
- XuebinMa's verifier over the author's vectors, executed by the lab (direction 3); runner:
  aeoess; Mode B; independent; implementation: guard-verify at pin e7eaba2c, authored by
  XuebinMa.
- safal207's own run of his own verifier, comment 5559145070; runner: safal207; Mode B;
  author-produced; implementation: his own verifier.
- XuebinMa's own run of his own verifier, comment 5556849470; runner: XuebinMa; Mode B;
  author-produced; implementation: his own verifier.
- The Python-package and TypeScript-package layers have no independent record and stay in
  docs/OPEN-RUNS.md. The semantic-verdict and entry-state layer does have one, twice over, and is
  not listed.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## What this record does not show

No live A2A traffic was exercised, and no message crossed a network on behalf of any agent here.
Nothing in this record is a claim about witness coverage or freshness: an absent envelope still
does not reveal whether coverage was promised, and nothing here says a witness was available,
independent, or non-equivocating. It is not a conformance verdict on attenu-guard: five runners
agreeing on one 19-case file is agreement on that file, and it says nothing about behaviour
outside these cases. The byte work is a byte diff and nothing more. It says nothing about the
limit the author's own announcement keeps visible, that envelopes sit outside the anchor so a
stripped array reads as never having existed, which the vectors README carries under "Known
limits of envelope v1" and which the author states is a v2 question. It is not an adoption,
endorsement, certification or partnership claim by or about any project named in it, and nothing
here is posted anywhere.

The two independent runs close the semantic and state layer only. An alternate checker
recomputing the verdicts does not establish that attenu-guard's Python package or its npm package
behaved as recorded; only a run that observes those implementations can close those, and neither
of these does.

## Not done here

The bundle-level record at `interop/attenu-guard-0.11.0-bundles/` was not re-run against 0.15.0.
The token vectors were not re-run. The new family is not added to the suite's own `npm test`,
which continues to gate the repository's fixtures rather than these interop runs. No file in
`interop/attenu-guard-0.13.0-envelopes/` was modified except the dated append at the end of its
SOURCE.md, which that record's own policy permits because it publishes no digest set.
