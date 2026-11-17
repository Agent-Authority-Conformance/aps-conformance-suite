# F02. The axis-to-item map is stated in CANDIDATE.md but not in vectors.json

To: Tymofii Pidlisnyi, author of `aeoess-presenter-key-possession`
Status: draft, not filed.

**Cases.** PK-26 (blind B26) and PK-28 (blind B28).

**Representation.** `vectors.json` states `text_status` ("The scope check and the axis names are this candidate's representation, not RFC 9449 text") and `readings` ("Each axis is read on its own, whatever the other axes say"). It does not say which RFC 9449 4.3 items each axis reports. `CANDIDATE.md` does: `proof_signature` covers items 2 to 7, `request_binding` items 8 to 11 and 11.1.

**Observed.** Reading only `vectors.json` beside RFC 9449, this run could not decide two cases, because RFC 9449 does not assign item 3 (required claims) or items 10 and 11 to any reporting axis:
- PK-26 (missing `ath`, reported `proof_signature: true`, reject at `key_binding`) is conformant if a missing claim is charged only to `key_binding`, nonconformant if item 3 is also charged to `proof_signature`.
- PK-28 (server nonce, none in the proof, reported `proof_signature: false`, `request_binding: true`) is conformant if the nonce checks are charged to `proof_signature`, nonconformant if to `request_binding`.
With the map from `CANDIDATE.md` applied, both match the expected `nonconformant` (`out/final.json`).

**Suggested change.** Add the axis-to-item map, as written in `CANDIDATE.md`, to `vectors.json` (for example in `readings`), so that the expected results of PK-26 to PK-28 follow from the file that carries them.
