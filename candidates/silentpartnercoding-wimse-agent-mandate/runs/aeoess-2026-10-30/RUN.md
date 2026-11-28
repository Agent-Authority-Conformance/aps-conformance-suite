# aeoess runs, 2026-10-30

Source `52653c2d1f3622baa4d3c3c5ddebd9f5b12557ca`, cases 00 to 03. macOS, Python 3.14.6, `cryptography` 43.0.0 from the source's `requirements.txt`.

```
git clone https://github.com/Silentpartnercoding/wimse-agent-mandate-vectors wamv
git -C wamv checkout 52653c2d1f3622baa4d3c3c5ddebd9f5b12557ca
python3 -m venv venv && venv/bin/pip install -r wamv/requirements.txt
(cd wamv && ../venv/bin/python check.py)              # check-py-output.txt, exit 0
venv/bin/python -I outer_witness.py wamv               # outer-witness-output.txt, exit 0
```

`outer_witness.py` imports nothing from the source repository. It uses `cryptography` for Ed25519 verification and `hashlib` for SHA-256, plus standard parsing and base64url encoding. It checks:

- 15 signatures across the four cases, each against the key the draft names (anchor key by `kid` from `trust-anchors.json`, the sub-mandate by its header `jwk`)
- `sub.parent.dig` and the presented `root.authority[].dig` as base64url SHA-256 of the compact JWS bytes
- the standalone profile-file digest, `profile/profil.json` against `profile/profil.digest`
- that each `.jws` file is byte-identical to a token in `presentation.json`
- root `cnf.jkt` against an RFC 7638 thumbprint of the sub-mandate header key, which the harness builds itself

It does not read the per-case profile reference in `inputs.json`, and it decides no authority result.
