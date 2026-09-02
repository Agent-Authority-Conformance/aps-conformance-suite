// Mode B recomputation of the insight.oracle-safety-check:v2 EIP-712 layer with ethers,
// an implementation independent of the family's vendored code and of the suite's own SDK.
// Usage: node eip712-recompute.mjs <path-to-oracle-safety-check-v1-dir>
import { recoverAddress, TypedDataEncoder } from 'ethers';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
const D = (process.argv[2] || '.').replace(/\/?$/, '/');
let n = 0, digestMatch = 0, signerMatch = 0; const rows = [];
for (const f of readdirSync(D).filter(x => x.endsWith('.json') && x !== 'index.json').sort()) {
  const raw = readFileSync(D + f); const v = JSON.parse(raw.toString('utf8'));
  const sha = createHash('sha256').update(raw).digest('hex');
  const o = v.envelope?.oracle; if (!o) { rows.push([f, sha, 'no oracle block']); continue; } n++;
  const { domain, types, primaryType } = o.eip712; const msg = {};
  for (const fld of types[primaryType]) { let val = o.data[fld.name]; if (fld.type.startsWith('uint')) val = BigInt(val); msg[fld.name] = val; }
  const digest = TypedDataEncoder.hash(domain, types, msg);
  const dOk = digest.toLowerCase() === String(o.uid).toLowerCase(); digestMatch += dOk;
  let signer = 'ERR'; try { signer = recoverAddress(o.uid, o.signature); } catch {}
  const sOk = signer.toLowerCase() === String(o.attester).toLowerCase(); signerMatch += sOk;
  rows.push([f, sha, v.expected, dOk ? 'digest match' : `digest DIVERGE observed=${digest}`, sOk ? 'signer match' : `signer DIVERGE observed=${signer}`]);
}
for (const r of rows) console.log(r.join(' | '));
console.log(`digest match ${digestMatch}/${n}; signer match ${signerMatch}/${n}`);
