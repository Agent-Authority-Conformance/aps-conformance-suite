# aps-conformance-suite @ `da95834aacbb5b5550872fc85f51d067652c9e7f` — per-vector results, checker cryptovalid-opencore 0.17.0

Run: 2026-10-04 (two runs, byte-identical `results_da95834.json`, sha256 `55e138981f5ebc7ed8000d1a4412a2537a1b1352ebe56119550384038be9b5f1`).
Checker: cryptovalid-opencore 0.17.0 (tag `v0.17.0` = commit `db7cabfce614163fbca0d9e8f40ae0f5031074df`), functions
`cryptovalid_acta.jcs`, `cryptovalid_aps.action_ref_native_01`, `cryptovalid_aps.verify_accountability_record`.
Environment: Python 3.11.2, cryptography 50.0.1 (installed separately: the 0.17.0 wheel declares no dependency), Debian 12, Linux 6.6 x86_64.
Fixture bytes checked against `fixtures/manifest.json` before any vector was read:
- `fixtures/canonical-bytes/canonical-bytes-jcs-v1.json`: sha256 `914803e87ce165f59958835519b30274623f2afab9a8ef5059bd2902ff0c9a8a` = manifest (match)
- `fixtures/canonical-bytes/canonical-bytes-jcs-v2.json`: sha256 `9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593` = manifest (match)
- `fixtures/actionref-canonical/actionref-canonical-fixture-v1.json`: sha256 `8dae334a5177e79ce2caef325c8c59e3be68c99aa89886cdf548d7edbb9f454d` = manifest (match)
- `fixtures/accountability-record/accountability-record-fixture-v1.json`: sha256 `536a952ebade9c8bfc7e0437d943e5157361cd8bcde83c1983cc8d7d4c865d14` = manifest (match)

Tally: **36 of 36** — canonical-bytes 18/18, actionref-canonical 6/6, accountability-record 12/12 (rejection layer as named by the vector: 4/5).

| family | vector | recorded (read for the comparison only) | observed (cryptovalid-opencore 0.17.0) | result | note |
|---|---|---|---|---|---|
| canonical-bytes/jcs-v1 | `float-tenth` | bytes 7b2276616c756522…, sha256 097a678e9d133973… | bytes 7b2276616c756522…, sha256 097a678e9d133973… | **match** |  |
| canonical-bytes/jcs-v1 | `float-1e21-boundary` | bytes 7b2276616c756522…, sha256 776bf0d292f3767f… | bytes 7b2276616c756522…, sha256 776bf0d292f3767f… | **match** |  |
| canonical-bytes/jcs-v1 | `negative-zero` | bytes 7b2276616c756522…, sha256 23d7b286bd429460… | bytes 7b2276616c756522…, sha256 23d7b286bd429460… | **match** |  |
| canonical-bytes/jcs-v1 | `integer-above-2pow53` | bytes 7b2276616c756522…, sha256 ab21889a153140e1… | bytes 7b2276616c756522…, sha256 ab21889a153140e1… | **match** |  |
| canonical-bytes/jcs-v1 | `small-exponent-vs-decimal` | bytes 7b22646563223a30…, sha256 4ecf258561293513… | bytes 7b22646563223a30…, sha256 4ecf258561293513… | **match** |  |
| canonical-bytes/jcs-v1 | `astral-key-ordering` | bytes 7b22f09d8c86223a…, sha256 0ed25e94bd02f7ca… | bytes 7b22f09d8c86223a…, sha256 0ed25e94bd02f7ca… | **match** |  |
| canonical-bytes/jcs-v1 | `nfd-key-used-as-given` | bytes 7b2263616665cc81…, sha256 05ba6cbd8fd6ef6e… | bytes 7b2263616665cc81…, sha256 05ba6cbd8fd6ef6e… | **match** |  |
| canonical-bytes/jcs-v1 | `nested-object-and-array` | bytes 7b22617272223a5b…, sha256 be6fc370ca7efc25… | bytes 7b22617272223a5b…, sha256 be6fc370ca7efc25… | **match** |  |
| canonical-bytes/jcs-v2 | `float-tenth` | bytes 7b2276616c756522…, sha256 097a678e9d133973… | bytes 7b2276616c756522…, sha256 097a678e9d133973… | **match** |  |
| canonical-bytes/jcs-v2 | `float-1e21-boundary` | bytes 7b2276616c756522…, sha256 776bf0d292f3767f… | bytes 7b2276616c756522…, sha256 776bf0d292f3767f… | **match** |  |
| canonical-bytes/jcs-v2 | `negative-zero` | bytes 7b2276616c756522…, sha256 23d7b286bd429460… | bytes 7b2276616c756522…, sha256 23d7b286bd429460… | **match** |  |
| canonical-bytes/jcs-v2 | `integer-above-2pow53` | bytes 7b2276616c756522…, sha256 ab21889a153140e1… | bytes 7b2276616c756522…, sha256 ab21889a153140e1… | **match** |  |
| canonical-bytes/jcs-v2 | `small-exponent-vs-decimal` | bytes 7b22646563223a30…, sha256 4ecf258561293513… | bytes 7b22646563223a30…, sha256 4ecf258561293513… | **match** |  |
| canonical-bytes/jcs-v2 | `astral-key-ordering` | bytes 7b22f09d8c86223a…, sha256 0ed25e94bd02f7ca… | bytes 7b22f09d8c86223a…, sha256 0ed25e94bd02f7ca… | **match** |  |
| canonical-bytes/jcs-v2 | `nfd-key-used-as-given` | bytes 7b2263616665cc81…, sha256 05ba6cbd8fd6ef6e… | bytes 7b2263616665cc81…, sha256 05ba6cbd8fd6ef6e… | **match** |  |
| canonical-bytes/jcs-v2 | `nested-object-and-array` | bytes 7b22617272223a5b…, sha256 be6fc370ca7efc25… | bytes 7b22617272223a5b…, sha256 be6fc370ca7efc25… | **match** |  |
| canonical-bytes/jcs-v2 | `integer-2pow60-inside-int64` | bytes 7b2276616c756522…, sha256 001814306319dfed… | bytes 7b2276616c756522…, sha256 001814306319dfed… | **match** |  |
| canonical-bytes/jcs-v2 | `integer-2pow68-above-int64` | bytes 7b2276616c756522…, sha256 57c82398dfd8be4a… | bytes 7b2276616c756522…, sha256 57c82398dfd8be4a… | **match** |  |
| actionref-canonical | `plain-single-scope-ascii` | action_ref c3828feae9320905… | draft-01: c3828feae9320905…; with reject_duplicate_scopes: c3828feae9320905… | **match** | identical in both modes |
| actionref-canonical | `unsorted-multi-scope-ascii` | action_ref 9f49b6ea908b45f4… | draft-01: 9f49b6ea908b45f4…; with reject_duplicate_scopes: 9f49b6ea908b45f4… | **match** | identical in both modes |
| actionref-canonical | `nfd-scope-normalizes-to-nfc` | action_ref 8f89060853f7e50f… | draft-01: 8f89060853f7e50f…; with reject_duplicate_scopes: 8f89060853f7e50f… | **match** | identical in both modes |
| actionref-canonical | `astral-scope-orders-after-bmp-high` | action_ref 2adf3d32f65a24aa… | draft-01: 2adf3d32f65a24aa…; with reject_duplicate_scopes: 2adf3d32f65a24aa… | **match** | identical in both modes |
| actionref-canonical | `negative-duplicate-scope-raw` | expected_verification false, rejection_kind duplicate_scope_required (labelled implementation-specific) | draft-01: accepted (4a3ccb54936fefc0…); with reject_duplicate_scopes: rejected (duplicate scope after NFC (rule of -03 §4.1, applied on request)) | **match** | draft-01 reading accepts (no duplicate rule in -01); the implementation-specific option rejects, as the family now labels it |
| actionref-canonical | `negative-duplicate-scope-nfc-collision` | expected_verification false, rejection_kind duplicate_scope_required (labelled implementation-specific) | draft-01: accepted (1e60c15732a1b3bc…); with reject_duplicate_scopes: rejected (duplicate scope after NFC (rule of -03 §4.1, applied on request)) | **match** | draft-01 reading accepts (no duplicate rule in -01); the implementation-specific option rejects, as the family now labels it |
| accountability-record | `allow-executed-settled` | verifies | verifies | **match** |  |
| accountability-record | `deny-no-settlement` | verifies | verifies | **match** |  |
| accountability-record | `halt` | verifies | verifies | **match** |  |
| accountability-record | `detached-payload` | verifies, payload unverified | verifies, payload_verified=false | **match** |  |
| accountability-record | `negative-tampered-payload` | fails (digest_mismatch) | fails (layer digest_mismatch) | **match** |  |
| accountability-record | `negative-wrong-key` | fails (signature) | fails (layer signature) | **match** |  |
| accountability-record | `negative-schema-decision` | fails (schema) | fails (layer schema) | **match** |  |
| accountability-record | `negative-type-relabel` | fails (signature) | fails (layer schema) | **match** | rejected at layer 'schema', the vector names 'signature' |
| accountability-record | `positive-deny-executed` | verifies | verifies | **match** |  |
| accountability-record | `positive-collision-same-second-a` | verifies | verifies | **match** |  |
| accountability-record | `positive-collision-same-second-b` | verifies | verifies | **match** |  |
| accountability-record | `negative-sig-alg-lowercase` | fails (schema) | fails (layer schema) | **match** |  |

## Positive controls

| family | control (the runner must be able to fail) | matches | 
|---|---|---|
| canonical-bytes | json.dumps(sort_keys) instead of JCS (code-point key order, Python numbers) | 12/18 |
| actionref-canonical | scopeRequired sorted by UTF-16 code units | 3/6 |
| actionref-canonical | no NFC normalisation | 3/6 |
| accountability-record | first signature byte flipped on every record | 5/12 |
| accountability-record | sig removed | 5/12 |
| accountability-record | inline action.type altered (digest must break) | 6/12 |
| accountability-record | verified under the fixture's wrong_keypair public key | 4/12 |

Command: `python run_aps_da95834.py <suite clone at da95834> results_da95834.json` (verbatim output: `run_output.txt`).
