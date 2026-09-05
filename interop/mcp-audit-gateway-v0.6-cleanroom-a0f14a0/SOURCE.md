# mcp-audit-gateway v0.6.0 at a0f14a0: clean-room recompute of the canonical bytes, digests and checkpoint chain, two runs over one script

Artifact: `test/vectors/canonicalization.json` (sha256
`34f8261aacb666c4bff9e48a2fe7cbda6647a3fb295d371a1a7e8bd5e3826a32`) and
`test/vectors/checkpoint.json` (sha256
`1eadd73cef1910c91e911eb57a496bc8e4c373c9c33820233c8b654714877d70`) from
elang2/mcp-audit-gateway at `a0f14a0418c2abe6135436f037f6b171735d1e73`, the tag behind the
family proposed in PR #63 (`mcp-audit-gateway-v0.6/`). This directory holds the lab's clean-room
verifier and the runs made with it; it is the recomputation record CONTRIBUTING requires for
that family's byte, digest and chain layers. The family's own runners and README live in #63.

## The verifier

`recompute.py` (sha256 `67e3c68c4ce1286d2c63c51f19c895527bbed55d3298a84db32e6a185696f8fc` at
8b5b0f39, the branch commit pinned in issue #68; the bytes are unchanged here), Python 3 standard library only, no install, no network.
Written by the lab on 2026-09-03 from the two vector files' own header text and the README at
`a0f14a0`: the tuple-array canonical form, the SHA-256 over canonical bytes, `record_hash` over
`full_record_json`, and the `previousHash` chain rule. No verifier from mcp-audit-gateway was
read or imported, and no existing verifier of any other project was used. The script prints the
sha256 of both inputs and the Python version first, so a run states what bytes it saw.

    python3 recompute.py canonicalization.json checkpoint.json

It performs 112 checks. Two are UNSPECIFIED because the header text does not state the value
(the genesis seed for `checkpoint_chain :: record[0] previousHash`; the complete chain result
under `truncation_detection`, whose records the file does not enumerate). One is NOT CHECKED:
`count_mismatch` is documented in `failure_codes` and is not exercised by any vector in these
two files, so it is out of this verifier's scope.

## Run 1: the lab (Mode B, author-produced)

Runner aeoess, 2026-09-03, at 8b5b0f39. Result (results.json, verbatim
statuses): 112 checks, 109 PASS, 2 UNSPECIFIED, 1 NOT CHECKED, exit 0. Author-produced: the
runner wrote the implementation whose output supplies the recomputation.

## Run 2: Silentpartnercoding (Mode B, independent)

Asked on issue #68 on 2026-09-03, posted there on 2026-09-05 (comment 5549228266), verbatim from
his report:

    Environment: Darwin 25.5.0 arm64
    Python: 3.14.6
    Verifier pin: Agent-Authority-Conformance/aps-conformance-suite@8b5b0f398dc813a2c4192a437270299d544b16f8
    Vector pin: elang2/mcp-audit-gateway@a0f14a0418c2abe6135436f037f6b171735d1e73
    recompute.py SHA-256: 67e3c68c4ce1286d2c63c51f19c895527bbed55d3298a84db32e6a185696f8fc
    canonicalization.json SHA-256: 34f8261aacb666c4bff9e48a2fe7cbda6647a3fb295d371a1a7e8bd5e3826a32
    checkpoint.json SHA-256: 1eadd73cef1910c91e911eb57a496bc8e4c373c9c33820233c8b654714877d70
    Command: python3 recompute.py canonicalization.json checkpoint.json
    Exit code: 0
    Result: 112 checks, 109 PASS, 2 UNSPECIFIED, 1 NOT CHECKED

His full stdout is preserved in `results-silentpartnercoding-2026-09-05.txt`, copied from the
comment. Compared in chat against run 1: all 112 check names present, every status identical,
the three hashes he printed equal the bytes at the pins. Independent under CONTRIBUTING: he
authored neither the vectors nor the implementation whose output supplies the recomputation.
He ran the lab's script; he did not write a second one, so this is an independent run of one
implementation, not agreement between two implementations.

## Where the runs differ, recorded and not adjudicated

They do not differ. 112 of 112 statuses agree, including the two UNSPECIFIED and the one NOT
CHECKED, which are properties of the header text and of the verifier's scope rather than of
either run.

## Verification split

- Canonical bytes and SHA-256 over canonical bytes, all canonicalization cases; runner: aeoess;
  Mode B; author-produced; implementation: recompute.py, authored by the runner.
- Same layer; runner: Silentpartnercoding; Mode B; independent; implementation: recompute.py
  (lab-authored, runner-independent), pinned at 8b5b0f39.
- `record_hash` over `full_record_json` and the `previousHash` chain, checkpoint and
  party-attribution chains; runner: aeoess; Mode B; author-produced; implementation:
  recompute.py, authored by the runner.
- Same layer; runner: Silentpartnercoding; Mode B; independent; implementation: recompute.py
  (lab-authored, runner-independent), pinned at 8b5b0f39.
- `count_mismatch` and the two UNSPECIFIED values: no record; not derivable from these two
  files.

These records are attributed per layer. Merge of this family is not an end-to-end verification
or a family-level verdict.

## What this record does not establish

It does not verify mcp-audit-gateway beyond these two files at this tag. It says nothing about
the family's `chain_continuity_violation` class or about `count_mismatch`, which no vector here
exercises. It is not an adoption or endorsement claim by or about either project. The run by
Silentpartnercoding is a run of the lab's reading of the header rules; a second reading of the
same rules by another author would be a different record and is not claimed here.
