// Lab-side guard for fixtures/cross-stack/tool-manifest-digest. Checks that the
// vector files are the exact bytes admitted at this pin before the producer's
// native verifiers run. It protects this pin. It does not change or fix the
// producer's verifiers, which do not check the key_encoding count or bind the
// unsigned toolDigests map to the signed payload (lab PR #156 review).
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

const root = process.argv[2];
if (!root) { console.error('usage: node check-tool-manifest-digest-pins.mjs <family dir>'); process.exit(2); }
const pins = {
  'v0/tool-manifest-digest-v0-vectors.json': '2f4632b03305471b3262109dce7db2cf71d029fe6d9ec85fe54e9bf5c82bb9df',
  'v1/tool-manifest-digest-v1-vectors.json': '488496079155830caf83593be0cafcb21367f72cd70ea363c2400f40eda72647',
};
let bad = 0;
for (const [name, expected] of Object.entries(pins)) {
  const actual = createHash('sha256').update(readFileSync(resolve(root, name))).digest('hex');
  if (actual === expected) console.log(`  ok    pinned bytes: ${name}`);
  else { console.log(`  FAIL  pinned bytes: ${name} is ${actual}, expected ${expected}`); bad++; }
}
process.exit(bad ? 1 : 0);
