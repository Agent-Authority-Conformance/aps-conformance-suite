"""Recompute the row id known answer of Appendix B.1 from the draft's own bytes."""
import hashlib
import re
import sys

import cbor_strict as C

txt = open(sys.argv[1], encoding="utf-8").read()


def hex_after(start, end):
    i = txt.index(start)
    j = txt.index(end, i)
    return bytes.fromhex("".join(re.findall(r"^\s{3}([0-9a-f]+)\s*$", txt[i:j], re.M)))


payload = hex_after("Its payload is these", "The row id input of Section 5")
prefix = hex_after("then the byte-string head 58ec", "The row id is the SHA-256")
expected = re.search(r"The row id is the SHA-256 of those 382 bytes:\s+([0-9a-f]{64})", txt).group(1)
ok, pl = C.is_deterministic(payload)
arr = ["CEG-row/2", "scores", "evidence:.suite:.kind:.cell:.prefix", "subject-1", str(pl.get("author")), payload]
enc = C.encode(arr)
rid = hashlib.sha256(enc).hexdigest()
print(f"payload: {len(payload)} bytes, deterministic: {ok}")
print(f"row id input: {len(enc)} bytes; starts with the draft's prefix: {enc.startswith(prefix)}; "
      f"then {enc[len(prefix):len(prefix) + 2].hex()}")
print(f"row id: {rid}")
print(f"draft:  {expected}")
print("match" if rid == expected else "MISMATCH")
sys.exit(0 if rid == expected else 1)
