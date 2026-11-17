# Changes after phase 1

`out/phase1.json` and `out/phase1-sensitivity.json` were not edited after the phase-1 zip was written (`logs/phase1.zip`, SHA-256 in `logs/phase1-zip.sha256`). Every change is in `out/final.json`, produced by `reader/phase2.py`, which loads `reader/checker.py` unchanged.

## Change 1. Two choice points fixed by the candidate's stated axis definitions

- **What changed.** Choice point A1 (`C1_item3_axis`) is fixed to reading B, and choice point A2 (`C5_freshness_axis`) to reading A. The other two choice points (A3, `C2_future_iat_null_skew`; A4, `C3_jti_replay`) are still evaluated both ways.
- **Why.** `CANDIDATE.md`, read in phase 2, states the axis map: "`proof_signature`: the proof is a well-formed DPoP JWT and its signature verifies with the key in its own `jwk` header (RFC 9449 section 4.3, items 2 to 7)" and "`request_binding`: ... (items 8 to 11 and section 11.1)". Item 3 is inside items 2 to 7, so a missing required claim is charged to `proof_signature` (A1 reading B); items 10, 11 and 11.1 are charged to `request_binding` (A2 reading A).
- **RFC sentence it rests on.** None decides it. RFC 9449 4.3 item 3, "All required claims per Section 4.2 are contained in the JWT.", is the condition the candidate places in `proof_signature`. The placement is the candidate's representation, not RFC text.
- **Verdicts that change.** B26 (PK-26) ambiguous -> nonconformant; B28 (PK-28) ambiguous -> nonconformant. No other verdict changes.
- **Fault.** Neither the checker nor the harness computed a wrong value. The axis map is stated in `CANDIDATE.md`, which was sealed during phase 1; the blind copy's `text_status` and `readings` do not state it, so phase 1 evaluated both placements and reported the two cases `ambiguous`.

## Not changed

- B27 (PK-18) stays `ambiguous`. Nothing read in phase 2 changes the reading of RFC 9449 11.1; `CANDIDATE.md` itself says "Section 11.1 says a server can do this and does not require it." See `findings/F01-pk18-jti-replay-requirement.md`.
- B17 (PK-17) stays `ambiguous`, as expected by the candidate.
- No fact (signature, thumbprint, `ath`, time difference, URI comparison, scope) changed.

## Notes added after review

These change no command of the run, no checker output (`phase1.json`, `phase1-sensitivity.json`, `final.json`), and no verdict.

- `logs/transcript.log`: the command that packaged this directory, which the log had recorded after the run ended, was removed. It held local working paths.
- `run-report.md`, Commands: the block now uses a four-backtick fence. The `CANDIDATE.md` text it quotes contains three-backtick fences, which ended the block early.
- `README.md`, Re-running: the commands now name the fetch script by its path in `inputs/`, write to `rerun/`, and compare with `out/`.
- `PROVENANCE.md`, Independence: the authorship sentence of `README.md` was added.
- RFC 9449 has a verified erratum to section 4.2, EID 7646: "authentication server" should read "authorization server" in the sentence that makes `nonce` required. The checker cites that sentence as published (`9449-4.2-nonce-req`). No verdict depends on which server provided the nonce.
