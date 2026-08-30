// APS-side implementation witness: agent-passport-system canonicalizeJCS over the three
// HJS vectors pinned at hjs-spec/hjs-05 bb6be62. Fetches the fixture at the pinned commit
// and refuses to run if its bytes do not hash to the pinned value.
// Run: npm install agent-passport-system@4.5.1 (any scratch dir), then
//      node run-aps-witness.mjs > results-aps-4.5.1.json
import { createHash } from 'node:crypto';
import * as sdk from 'agent-passport-system';
const PIN = 'bb6be62fd28911c02ff31f61db8c023757ef2243';
const URL = `https://raw.githubusercontent.com/hjs-spec/hjs-05/${PIN}/fixtures/canonical-bytes/hjs-behavior-record-jcs-v1.json`;
const FIXTURE_SHA256 = '4f593700c1b25698906483171109c02f38b7e389454f49e2b7f4e0db80cda3f7';
const raw = Buffer.from(await (await fetch(URL)).arrayBuffer());
const got = createHash('sha256').update(raw).digest('hex');
if (got !== FIXTURE_SHA256) { console.error(`fixture sha256 ${got} != pinned ${FIXTURE_SHA256}`); process.exit(2); }
const fx = JSON.parse(raw.toString('utf8'));
const out = { witness: 'agent-passport-system canonicalizeJCS', node: process.version, fixture_sha256: got, cases: [] };
let all = true;
for (const v of fx.vectors) {
  const bytes = Buffer.from(sdk.canonicalizeJCS(v.input), 'utf8');
  const hex = bytes.toString('hex'), sha = createHash('sha256').update(bytes).digest('hex');
  const bytes_match = hex === v.canonical_bytes_hex, digest_match = sha === v.canonical_sha256;
  all = all && bytes_match && digest_match;
  out.cases.push({ name: v.name, observed_bytes_hex: hex, observed_sha256: sha, expected_bytes_hex: v.canonical_bytes_hex, expected_sha256: v.canonical_sha256, bytes_match, digest_match, length: bytes.length });
}
out.all_match = all;
console.log(JSON.stringify(out, null, 2));
process.exit(all ? 0 : 1);
