import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))
import aep_verify_v2 as V
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
corpus = Path(sys.argv[1]); cdir = Path(sys.argv[2])
man = json.loads((corpus / "manifest.json").read_text())
keys = {k: Ed25519PublicKey.from_public_bytes(bytes.fromhex((corpus / r).read_text().strip())) for k, r in man["verifying_keys"]["by_keyid"].items()}
meta = json.loads((cdir / "cases.json").read_text())
keys[meta["extra_key_id"]] = Ed25519PublicKey.from_public_bytes(bytes.fromhex((cdir / "extra-verify-key.hex").read_text().strip()))
ok = 0
for c in meta["cases"]:
    rec = json.loads((cdir / c["path"]).read_text())
    got, why = V.authenticity(rec, keys) if c["layer"] == "authenticity" else V.semantic(rec)
    hit = got == c["expected"]; ok += hit
    print(("PASS" if hit else "FAIL"), c["path"], c["layer"], "expected", c["expected"], "got", got, why)
print(f"{ok}/{len(meta['cases'])}")
