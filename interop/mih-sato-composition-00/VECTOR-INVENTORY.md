# Vector inventory

The 27 cases carried in corpus/examples/composition/cross-slot-conformance-v1/bundle.json.
Variant labels are the pack's own. Expected values are the pack's pinned expectations.

| case id | variant | expected terminal | expected primary check | observed |
|---|---|---|---|---|
| `COMP-POSITIVE-01` | positive | pass | `composition.complete` | reproduced |
| `COMP-BIND-01` | negative | fail | `subject.action_bytes` | reproduced |
| `COMP-BIND-01.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-BIND-02` | negative | indeterminate | `join.digest_context` | reproduced |
| `COMP-BIND-02.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-BIND-03` | negative | fail | `join.digest_representation` | reproduced |
| `COMP-BIND-03.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-BIND-04` | negative | fail | `join.protected_cross_reference` | reproduced |
| `COMP-BIND-04.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-BIND-05` | negative | fail | `join.additional_binding_context` | reproduced |
| `COMP-BIND-05.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-BIND-06` | negative | unsupported | `policy.binding_semantics` | reproduced |
| `COMP-BIND-06.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-BASIS-01` | negative | indeterminate | `join.field_basis` | reproduced |
| `COMP-BASIS-01.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-BASIS-02` | negative | indeterminate | `join.field_mapping` | reproduced |
| `COMP-BASIS-02.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-RESULT-01` | negative | fail | `report.result_separation` | reproduced |
| `COMP-RESULT-01.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-RESULT-02` | negative | fail | `report.result_preservation` | reproduced |
| `COMP-RESULT-02.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-JOIN-01` | negative | fail | `join.exact_action` | reproduced |
| `COMP-JOIN-01.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-JOIN-02` | negative | fail | `report.not_evaluated_preservation` | reproduced |
| `COMP-JOIN-02.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |
| `COMP-UNKNOWN-01` | negative | unsupported | `policy.required_profile` | reproduced |
| `COMP-UNKNOWN-01.condition_removed` | condition_removed | pass | `composition.complete` | reproduced |

Counts: 1 positive, 13 negative, 13 condition-removed, 27 total.

## Corpus files and digests

SHA-256 over file bytes, as copied byte-exact from the pack at commit
30916c802dcb60251f6af5e0999912a6306117c3.

| file | bytes | sha256 |
|---|---|---|
| `docs/COMPOSITION-CONFORMANCE-MECHANISM.md` | 6389 | `30ec7d527107ec85900b1cd3e283dfa33c768b8f41a656c227e0ec3953d5d314` |
| `examples/composition/caid-aec-aeb-capsule-v1/CHECKSUMS.sha256` | 342 | `223eb51de5dfef189a49cae03e51380f721e2be585b312623c65c704a11e39c3` |
| `examples/composition/caid-aec-aeb-capsule-v1/README.md` | 2861 | `9ec726c2cbefc17248d17fad02bf57ff7c8091a905b0c78a4488f00e898cb304` |
| `examples/composition/caid-aec-aeb-capsule-v1/bundle.json` | 40296 | `f7a2ca926ee46a5b4d8c77cb26602e08e0dbd1fc6a204a3e37ac6c9273809cad` |
| `examples/composition/caid-aec-aeb-capsule-v1/external-report.template.json` | 524 | `5c9c44458d807f62435d80af14033d54814e2e9f7dd8aff9f0197daa6722aa6b` |
| `examples/composition/caid-aec-aeb-capsule-v1/manifest.json` | 2915 | `f1e6f179bcbc31f36bd4b852cecd94bcb81f96b11d9aaa1efb30fcedb92a0efb` |
| `examples/composition/caid-aec-aeb-capsule-v1/report.emilia-js.json` | 87816 | `f1006e878439eeebed7b84e3720779d3e7b51412b6f09269ad721ffeb0a1c48e` |
| `examples/composition/caid-aec-aeb-capsule-v1/run.mjs` | 38624 | `b032af6ef6a1f9f8f129d3d08883d63e492cb41001a3648da3a589f28a3df327` |
| `examples/composition/caid-aec-aeb-capsule-v1/run.mts` | 36318 | `ca120a51518c61c0bbdc3c30dfde5f4bd86cc6278ff090bead6a1be97b50cfc5` |
| `examples/composition/caid-aec-aeb-capsule-v1/run.test.mjs` | 2284 | `54f16654fc5c1d8506e9c63eb1e8e3f5ac6807afaa054fbe7a44e361ef85d58a` |
| `examples/composition/caid-aec-aeb-capsule-v1/run.test.mts` | 2146 | `c0df422bda98a2ff1e03d7b8065a04d0a5e8da4201b854b00afc3cb0c69a75b3` |
| `examples/composition/cross-slot-conformance-v1/CHECKSUMS.sha256` | 342 | `4077aade454335321d00c2a103c666c410205143c75faae935c6888d19688f0b` |
| `examples/composition/cross-slot-conformance-v1/README.md` | 1541 | `0cbec7e5658cd9d17e38b3ea726f56bfad4aea3d441e6e51b3e672e586fa9e84` |
| `examples/composition/cross-slot-conformance-v1/bundle.json` | 370699 | `55cbf2bbd5667a2b8008660f02ca1500018b9ad45a3e194c8e0098309291eb16` |
| `examples/composition/cross-slot-conformance-v1/external-report.template.json` | 546 | `1bf51804efc876201cc5cb14ffb721dcbfd764298fe1ee52f41573d6885f5aa8` |
| `examples/composition/cross-slot-conformance-v1/manifest.json` | 1358 | `49cc0fddefba9ce39e1d3f1238b2d0283472da7066f5408e263ce0aba8a78e10` |
| `examples/composition/cross-slot-conformance-v1/report.emilia-js.json` | 155821 | `96cca9df3d3c91f383e4be797d3745783eed5bca60def15f7086b696a2093ec9` |
| `examples/composition/cross-slot-conformance-v1/run.mjs` | 37084 | `cbfe9242f60cca06d7aab18f341ab6cd3eea4a7b505134fcdf90122a06856df0` |
| `examples/composition/cross-slot-conformance-v1/run.mts` | 37477 | `9d0d3d2feddb88af8058d116daf9d628ca5727ddf2cfb30596c48749af2116eb` |
| `examples/composition/cross-slot-conformance-v1/run.test.mjs` | 5054 | `667390c2896450b151c0b966c32fd84da6a80172a6422d82ff7faf45cc585cf0` |
| `examples/composition/cross-slot-conformance-v1/run.test.mts` | 4801 | `69264344201c096ec7c3a0fa55619154065a70b7b6dc945b532309fb93101e21` |
