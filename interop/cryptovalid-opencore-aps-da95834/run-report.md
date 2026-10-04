# Run report: cryptovalid-opencore 0.17.0 against canonical-bytes, actionref-canonical and accountability-record at `da95834`, Mode B, labelled per layer

| field | value |
|---|---|
| who ran it | Roberto Locatelli (`robertolocatelli81-dev`). The commands were executed by an AI agent (Noûs) operating under his revocable mandate; he reviewed the record and is accountable for it. |
| date | 2026-10-04 (UTC) |
| run mode | B, alternate recomputation |
| implementation name | cryptovalid-opencore clean-room checkers: `cryptovalid_acta.jcs` (RFC 8785), `cryptovalid_aps.action_ref_native_01` (the draft-pidlisnyi-aps-01 section 4.1 form; its option `reject_duplicate_scopes=True` applies the duplicate-scope rule of draft-03 section 4.1 on request) and `cryptovalid_aps.verify_accountability_record`. Written from RFC 8785, the drafts and the three family READMEs; no code from agent-passport-system. |
| implementation repo and commit or version | https://github.com/robertolocatelli81-dev/cryptovalid-opencore, tag `v0.17.0` = commit `db7cabfce614163fbca0d9e8f40ae0f5031074df`. Installed as the wheel `cryptovalid-opencore==0.17.0` (sha256 `741c9c7b20b55f9a90d67b649b08551d0dd2d56076c007914e22b084ec72f4f8`) from the index https://robertolocatelli81-dev.github.io/pypi/. The wheel declares no dependencies (`Requires:` is empty); `cryptography==50.0.1` was installed separately. |
| corpus reference | `da95834aacbb5b5550872fc85f51d067652c9e7f`, the merge commit of #147 and the head of `main` on 2026-10-04. The four fixture files were checked against `fixtures/manifest.json` before any vector was read (table below, 4 of 4 match). |
| per-vector result | 36 of 36 match: canonical-bytes 18 of 18, actionref-canonical 6 of 6, accountability-record 12 of 12. List below; recorded and observed values side by side in `RESULTS.md`; raw values in `results_da95834.json`. |
| verbatim command and output | `python run_aps_da95834.py <suite checkout at da95834> results_da95834.json`; output below, uncut, and in `run_output.txt`. |
| environment | Python 3.11.2, cryptography 50.0.1, Debian GNU/Linux 12 (bookworm), Linux 6.6, x86_64 |
| author-produced or independent | **Labelled per layer, table below.** The runner authored neither the vectors, nor the claim inputs being checked, nor the implementation under test (agent-passport-system), but did author cryptovalid-opencore, the alternate implementation that supplies the recomputation. Under CONTRIBUTING.md, independence follows the implementation that supplies the substantive recomputation: every layer whose verdict is constructed or interpreted by cryptovalid-opencore's own code is **author-produced** (authorship relationship: the runner wrote the checker). One layer, the Ed25519 signature check, is decided by an independently authored primitive (`cryptography` 50.0.1) over a signing input that cryptovalid-opencore builds; it is listed as a candidate for `independent` and left to the lab to settle at review. The harness `run_aps_da95834.py` transports the fixture inputs, calls the three functions above and compares their output with the recorded values; it decides no verdict of its own except the two-mode rule for the duplicate-scope negatives, which is author-produced. |
| suspected defective vectors | none. One ordering note, not a defect: `negative-type-relabel` is refused by the schema layer (the `record_type` const) before its signature is checked, while the family table names the signature layer; the verdict matches. |

## What this run checks and what it does not

- `canonical-bytes` (jcs-v1, jcs-v2): the canonical bytes of each `input` under RFC 8785, compared byte for byte with `canonical_bytes_hex`, and their SHA-256 with `canonical_sha256`.
- `actionref-canonical`: `action_ref` and `canonical_scope_order` of the four draft-01 vectors, in both modes of the function. The two duplicate-scope negatives are labelled implementation-specific at this commit: they are accepted under the draft-01 reading (draft-01 defines no duplicate-scope rule) and rejected as `duplicate_scope_required` with `reject_duplicate_scopes=True`; a vector matches when both behaviours are observed.
- `accountability-record`: each record verified under the fixture's `keypair` public key; the verdict is compared with `expected_verification`, and for the negatives the rejection layer with `rejection_kind`. `detached-payload` verifies with `payload_verified=false`.
- Not checked: every other family of the corpus, the Go and TypeScript runners of this repository, and the draft-03 `aps-action-ref-v2` form, which these families do not carry.

Expected values (`canonical_bytes_hex`, `canonical_sha256`, `action_ref`, `canonical_scope_order`, `expected_verification`, `rejection_kind`) are read only for the comparison.

## Labels per layer

One entry per distinct claim, in the form CONTRIBUTING.md asks of a verification split: layer / claim; runner; mode; label; implementation. Where cryptovalid-opencore's own code constructs or interprets the claimed result, the layer is author-produced; the authorship relationship in every such case is that the runner wrote cryptovalid-opencore. The one candidate for `independent` is marked as such and not claimed: the lab decides at review.

| layer / claim | runner | mode | label | implementation that supplies the recomputation |
|---|---|---|---|---|
| canonical-bytes: the RFC 8785 bytes of each `input` (18 vectors) | Roberto Locatelli, `robertolocatelli81-dev` | Mode B | author-produced | `cryptovalid_acta.jcs`, a JCS serializer written by the runner; no third-party JCS library |
| canonical-bytes: SHA-256 over those bytes (18 vectors) | same | Mode B | author-produced (derived) | `hashlib.sha256` (Python standard library) over bytes produced by the layer above; it confirms nothing the layer above does not already decide, so no separate label is claimed |
| actionref-canonical: `action_ref` and `canonical_scope_order` of the four draft-01 vectors | same | Mode B | author-produced | `cryptovalid_aps.action_ref_native_01`, written by the runner: member and timestamp grammar, NFC (`unicodedata`, standard library), code-point sort, JCS as above, SHA-256 (`hashlib`) over the preimage the function builds |
| actionref-canonical: the two duplicate-scope negatives, accepted under draft-01 and rejected with `reject_duplicate_scopes=True` | same | Mode B | author-produced | the option is the runner's own rule, and the two-mode comparison is decided by the harness `run_aps_da95834.py` |
| accountability-record: schema layer (member set, `record_type` const, decision and `sig_alg` values) | same | Mode B | author-produced | `cryptovalid_aps._schema`, written by the runner |
| accountability-record: Ed25519 signature over JCS(record without `sig`) under the fixture's `keypair`, 12 vectors, including `negative-wrong-key` and the wrong-key control | same | Mode B | **candidate independent, for the lab to settle** | the verdict is decided by `cryptography` 50.0.1 (`Ed25519PublicKey.verify`), an implementation the runner did not write; the signing input is built by `cryptovalid_acta.jcs`, the runner's code, so a positive verdict also shows that preimage equals the bytes the SDK signed. If the lab reads the preimage construction as part of the recomputation, the layer is author-produced |
| accountability-record: `action_digest.sha256` = SHA-256(JCS(`action`)) for the inline-payload records | same | Mode B | author-produced | `hashlib.sha256` over `cryptovalid_acta.jcs(action)`, the runner's JCS |
| accountability-record: `action_ref` recomputed from the inline `action` (producer-side second-precision normalisation) | same | Mode B | author-produced | `cryptovalid_aps.action_ref_native_01(..., normalize=True)`, written by the runner |
| accountability-record: the verdict and its first failing layer (`schema`, `signature`, `digest_mismatch`, `action_ref`), compared with `expected_verification` and `rejection_kind` | same | Mode B | author-produced | the order of layers and the composition of the verdict are `cryptovalid_aps.verify_accountability_record`, written by the runner |

These records are attributed per layer. This directory is a record of runs, not an end-to-end verification or a family-level verdict.

## Fixture bytes against `fixtures/manifest.json`

| file | sha256 | manifest |
|---|---|---|
| `fixtures/canonical-bytes/canonical-bytes-jcs-v1.json` | `914803e87ce165f59958835519b30274623f2afab9a8ef5059bd2902ff0c9a8a` | match |
| `fixtures/canonical-bytes/canonical-bytes-jcs-v2.json` | `9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593` | match |
| `fixtures/actionref-canonical/actionref-canonical-fixture-v1.json` | `8dae334a5177e79ce2caef325c8c59e3be68c99aa89886cdf548d7edbb9f454d` | match |
| `fixtures/accountability-record/accountability-record-fixture-v1.json` | `536a952ebade9c8bfc7e0437d943e5157361cd8bcde83c1983cc8d7d4c865d14` | match |

## Per-vector result

| family | vector | result | note |
|---|---|---|---|
| canonical-bytes/jcs-v1 | `float-tenth` | match |  |
| canonical-bytes/jcs-v1 | `float-1e21-boundary` | match |  |
| canonical-bytes/jcs-v1 | `negative-zero` | match |  |
| canonical-bytes/jcs-v1 | `integer-above-2pow53` | match |  |
| canonical-bytes/jcs-v1 | `small-exponent-vs-decimal` | match |  |
| canonical-bytes/jcs-v1 | `astral-key-ordering` | match |  |
| canonical-bytes/jcs-v1 | `nfd-key-used-as-given` | match |  |
| canonical-bytes/jcs-v1 | `nested-object-and-array` | match |  |
| canonical-bytes/jcs-v2 | `float-tenth` | match |  |
| canonical-bytes/jcs-v2 | `float-1e21-boundary` | match |  |
| canonical-bytes/jcs-v2 | `negative-zero` | match |  |
| canonical-bytes/jcs-v2 | `integer-above-2pow53` | match |  |
| canonical-bytes/jcs-v2 | `small-exponent-vs-decimal` | match |  |
| canonical-bytes/jcs-v2 | `astral-key-ordering` | match |  |
| canonical-bytes/jcs-v2 | `nfd-key-used-as-given` | match |  |
| canonical-bytes/jcs-v2 | `nested-object-and-array` | match |  |
| canonical-bytes/jcs-v2 | `integer-2pow60-inside-int64` | match |  |
| canonical-bytes/jcs-v2 | `integer-2pow68-above-int64` | match |  |
| actionref-canonical | `plain-single-scope-ascii` | match | identical in both modes |
| actionref-canonical | `unsorted-multi-scope-ascii` | match | identical in both modes |
| actionref-canonical | `nfd-scope-normalizes-to-nfc` | match | identical in both modes |
| actionref-canonical | `astral-scope-orders-after-bmp-high` | match | identical in both modes |
| actionref-canonical | `negative-duplicate-scope-raw` | match | draft-01 reading accepts (no duplicate rule in -01); the implementation-specific option rejects, as the family now labels it |
| actionref-canonical | `negative-duplicate-scope-nfc-collision` | match | draft-01 reading accepts (no duplicate rule in -01); the implementation-specific option rejects, as the family now labels it |
| accountability-record | `allow-executed-settled` | match |  |
| accountability-record | `deny-no-settlement` | match |  |
| accountability-record | `halt` | match |  |
| accountability-record | `detached-payload` | match |  |
| accountability-record | `negative-tampered-payload` | match |  |
| accountability-record | `negative-wrong-key` | match |  |
| accountability-record | `negative-schema-decision` | match |  |
| accountability-record | `negative-type-relabel` | match | rejected at layer 'schema', the vector names 'signature' |
| accountability-record | `positive-deny-executed` | match |  |
| accountability-record | `positive-collision-same-second-a` | match |  |
| accountability-record | `positive-collision-same-second-b` | match |  |
| accountability-record | `negative-sig-alg-lowercase` | match |  |

## Positive controls

The runner must be able to fail. Each control replaces one step with a wrong one and counts the matches that survive.

| family | control | matches |
|---|---|---|
| canonical-bytes | json.dumps(sort_keys) instead of JCS (code-point key order, Python numbers) | 12/18 |
| actionref-canonical | scopeRequired sorted by UTF-16 code units | 3/6 |
| actionref-canonical | no NFC normalisation | 3/6 |
| accountability-record | first signature byte flipped on every record | 5/12 |
| accountability-record | sig removed | 5/12 |
| accountability-record | inline action.type altered (digest must break) | 6/12 |
| accountability-record | verified under the fixture's wrong_keypair public key | 4/12 |

## Byte identity across runs

Four runs on 2026-10-04: two in the first environment, then two more, each on a fresh clone of this repository at `da95834` with a fresh virtual environment, the last one following the Re-run section below as written. All four wrote a byte-identical `results_da95834.json` (sha256 `55e138981f5ebc7ed8000d1a4412a2537a1b1352ebe56119550384038be9b5f1`) and a byte-identical output (sha256 `49e4080ed509f7505429d70f2658dcb258a5e68de50a813cfdcf69ca917cf83a`). The results file carries the Python and cryptography versions, so byte identity holds for the environment above.

## Verbatim command and output

```
$ python run_aps_da95834.py <suite checkout at da95834> results_da95834.json
{
 "canonical-bytes/canonical-bytes-jcs-v1.json": {
  "sha256": "914803e87ce165f59958835519b30274623f2afab9a8ef5059bd2902ff0c9a8a",
  "manifest": "914803e87ce165f59958835519b30274623f2afab9a8ef5059bd2902ff0c9a8a",
  "match": true
 },
 "canonical-bytes/canonical-bytes-jcs-v2.json": {
  "sha256": "9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593",
  "manifest": "9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593",
  "match": true
 },
 "actionref-canonical/actionref-canonical-fixture-v1.json": {
  "sha256": "8dae334a5177e79ce2caef325c8c59e3be68c99aa89886cdf548d7edbb9f454d",
  "manifest": "8dae334a5177e79ce2caef325c8c59e3be68c99aa89886cdf548d7edbb9f454d",
  "match": true
 },
 "accountability-record/accountability-record-fixture-v1.json": {
  "sha256": "536a952ebade9c8bfc7e0437d943e5157361cd8bcde83c1983cc8d7d4c865d14",
  "manifest": "536a952ebade9c8bfc7e0437d943e5157361cd8bcde83c1983cc8d7d4c865d14",
  "match": true
 }
}
SUMMARY {"canonical-bytes": "18/18", "actionref-canonical": "6/6", "accountability-record": "12/12", "accountability_rejection_layer_as_named": "4/5"}
CONTROLS
  {"family": "canonical-bytes", "control": "json.dumps(sort_keys) instead of JCS (code-point key order, Python numbers)", "match": "12/18", "expected": "fewer than 18"}
  {"family": "actionref-canonical", "control": "scopeRequired sorted by UTF-16 code units", "match": "3/6", "expected": "fewer than 6"}
  {"family": "actionref-canonical", "control": "no NFC normalisation", "match": "3/6", "expected": "fewer than 6"}
  {"family": "accountability-record", "control": "first signature byte flipped on every record", "match": "5/12", "expected": "fewer than 12"}
  {"family": "accountability-record", "control": "sig removed", "match": "5/12", "expected": "fewer than 12"}
  {"family": "accountability-record", "control": "inline action.type altered (digest must break)", "match": "6/12", "expected": "fewer than 12"}
  {"family": "accountability-record", "control": "verified under the fixture's wrong_keypair public key", "match": "4/12", "expected": "fewer than 12"}
match    canonical-bytes/jcs-v1       float-tenth                              
match    canonical-bytes/jcs-v1       float-1e21-boundary                      
match    canonical-bytes/jcs-v1       negative-zero                            
match    canonical-bytes/jcs-v1       integer-above-2pow53                     
match    canonical-bytes/jcs-v1       small-exponent-vs-decimal                
match    canonical-bytes/jcs-v1       astral-key-ordering                      
match    canonical-bytes/jcs-v1       nfd-key-used-as-given                    
match    canonical-bytes/jcs-v1       nested-object-and-array                  
match    canonical-bytes/jcs-v2       float-tenth                              
match    canonical-bytes/jcs-v2       float-1e21-boundary                      
match    canonical-bytes/jcs-v2       negative-zero                            
match    canonical-bytes/jcs-v2       integer-above-2pow53                     
match    canonical-bytes/jcs-v2       small-exponent-vs-decimal                
match    canonical-bytes/jcs-v2       astral-key-ordering                      
match    canonical-bytes/jcs-v2       nfd-key-used-as-given                    
match    canonical-bytes/jcs-v2       nested-object-and-array                  
match    canonical-bytes/jcs-v2       integer-2pow60-inside-int64              
match    canonical-bytes/jcs-v2       integer-2pow68-above-int64               
match    actionref-canonical          plain-single-scope-ascii                 identical in both modes
match    actionref-canonical          unsorted-multi-scope-ascii               identical in both modes
match    actionref-canonical          nfd-scope-normalizes-to-nfc              identical in both modes
match    actionref-canonical          astral-scope-orders-after-bmp-high       identical in both modes
match    actionref-canonical          negative-duplicate-scope-raw             draft-01 reading accepts (no duplicate rule in -01); the implementation-specific option rejects, as the family now labels it
match    actionref-canonical          negative-duplicate-scope-nfc-collision   draft-01 reading accepts (no duplicate rule in -01); the implementation-specific option rejects, as the family now labels it
match    accountability-record        allow-executed-settled                   
match    accountability-record        deny-no-settlement                       
match    accountability-record        halt                                     
match    accountability-record        detached-payload                         
match    accountability-record        negative-tampered-payload                
match    accountability-record        negative-wrong-key                       
match    accountability-record        negative-schema-decision                 
match    accountability-record        negative-type-relabel                    rejected at layer 'schema', the vector names 'signature'
match    accountability-record        positive-deny-executed                   
match    accountability-record        positive-collision-same-second-a         
match    accountability-record        positive-collision-same-second-b         
match    accountability-record        negative-sig-alg-lowercase               
```

## Re-run

```
git clone https://github.com/Agent-Authority-Conformance/aps-conformance-suite.git
cd aps-conformance-suite
git checkout da95834aacbb5b5550872fc85f51d067652c9e7f
python3 -m venv v
v/bin/pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ "cryptovalid-opencore==0.17.0"
v/bin/pip install cryptography==50.0.1
v/bin/python interop/cryptovalid-opencore-aps-da95834/run_aps_da95834.py . results.json
sha256sum results.json
```

`sha256sum -c SHA256SUMS.txt` in this directory checks every file here except the checksum file itself. sha256 of `run_aps_da95834.py`: `ba2ea7620a71d43f099386c0a517d8232bec1f255cb908a93ed0bdb0fb1db392`.

## What this record means

It records a run, not a verdict. It is not a conformance verdict on agent-passport-system or on cryptovalid-opencore, and not an endorsement of either.
