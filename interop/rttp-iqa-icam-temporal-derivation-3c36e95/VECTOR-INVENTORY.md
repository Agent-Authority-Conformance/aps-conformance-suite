# Vector inventory

Source: `vendor/vectors.json` (sha256 `8fa9e4aef50e79a02d03196c0873b8f6cd3e70f382aacda2796d1bff168185e7`, digest-gated against `vendor/CHECKSUMS.sha256` — 6/6 verified before anything ran).

Header facts as declared by the candidate: name `icam-temporal-derivation`, revision `0.2.0-prepublication`, normative target `draft-li-rttp-iqa-addressing-02 sections 6.1, 6.3, 7.2; experimental Informational draft, not an IETF standard`; scope: separate verifier-time derivation (lease reliance) from the wire-frame expiry gate, with negative controls challenging an untrusted advisory flag that is not a field of RTTP/IQA; note: expected values are author-produced, not independent implementation results.

## Composition — 24 cases

- 20 `DERIVE` (reliance layer, section 6.1): TD-B01, TD-B02, TD-B03, TD-B04, TD-B05, TD-B06, TD-B07, TD-B08, TD-N01, TD-N02, TD-N03, TD-N04, TD-N05, TD-N06, TD-X01, TD-X02, TD-X03, TD-X04, TD-X05, TD-X06
- 4 `WIRE_TIME_GATE` (wire_time_gate_only layer, section 7.2 step 2 only): TD-W01, TD-W02, TD-W03, TD-W04

Case status as declared: 16 `normative`, 4 `convention_specific`, 3 `local_precondition`, 1 `interpretive`.

## Case anatomy

Every DERIVE case carries an explicit `verifier_now_unix_s` and `lease_expiry_unix_s`, a declared `boundary_convention` (`fresh_at_instant` or `expired_at_instant`), and the advisory `supplied_boundary_classification` input. Notable groups:

- TD-B01–TD-B06: the two boundary conventions across strictly-before / equality / strictly-after.
- TD-N01–TD-N06: negative controls whose supplied classification contradicts the times — any oracle that trusts the advisory flag is punished (the flag is not an RTTP/IQA field).
- TD-X01, TD-X02: classification absent (`null`) — time alone decides.
- TD-X03: no declared convention at equality → `boundary_undetermined` (SHOULD declaration, interpretive only).
- TD-X04, TD-X05: null time inputs → `insufficient_input` (ICAM-local precondition, not a protocol refusal reason).
- TD-X06: `invalid_convention` — outside the two proposed conventions.
- TD-B07, TD-B08: a nondefault 300-second stated lease — punishes any hard-coded 120-second window.
- TD-W01–TD-W04: the wire gate answers section 7.2 step (2) strictly — earlier rejects, equality passes the isolated gate; NOT HMAC or full frame validity.

## Expectation vocabulary

`fresh`, `expired`, `boundary_undetermined`, `insufficient_input`, `invalid_convention` (reliance layer); `time_gate_pass`, `time_gate_reject` (wire gate).
