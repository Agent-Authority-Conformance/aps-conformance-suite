// Lab driver, layer 1 (native JS authenticity/binding) and layer 4 (native JS chain).
// Calls only the pinned wasmagent-js public verify surface. No lab semantics here.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  verifyAEPRecordDetailed,
  verifyAEPChain,
} from "../wasmagent-js/packages/aep/src/verify.ts";

const CORPUS = "../wasmagent-protocol/conformance/aep";
const hexKey = (p: string) =>
  Uint8Array.from(
    readFileSync(join(CORPUS, p), "utf8").trim().match(/.{2}/g)!.map((b) => parseInt(b, 16)),
  );

const KEYS: Record<string, Uint8Array> = {
  "conformance-seed-key-01": hexKey("dsse/js-verify-key.hex"),
  "ci-sample-key": hexKey("dsse/rust-fixture-verify-key.hex"),
};

const out: any[] = [];

// --- single-record layers ---
for (const dir of ["valid", "invalid-semantic", "dsse", "historical"]) {
  for (const f of readdirSync(join(CORPUS, dir)).filter((f) => f.endsWith(".json")).sort()) {
    const rec = JSON.parse(readFileSync(join(CORPUS, dir, f), "utf8"));
    const keyid = rec?.dsse_envelope?.signatures?.[0]?.keyid;
    const key = KEYS[keyid] ?? KEYS["conformance-seed-key-01"];
    let r: any, err: string | null = null;
    try { r = await verifyAEPRecordDetailed(rec, key); }
    catch (e: any) { err = String(e?.message ?? e); }
    out.push({ layer: "JS-NATIVE-RECORD", fixture: `${dir}/${f}`, keyid: keyid ?? null,
               valid: r?.valid ?? null, authenticity: r?.authenticity ?? null,
               binding: r?.binding ?? null, threw: err });
  }
}

// --- chain layer ---
for (const f of readdirSync(join(CORPUS, "chain")).filter((f) => f.endsWith(".json") || f.endsWith(".jsonl")).sort()) {
  const raw = readFileSync(join(CORPUS, "chain", f), "utf8").trim();
  let records: any[];
  try {
    records = f.endsWith(".jsonl")
      ? raw.split("\n").filter(Boolean).map((l) => JSON.parse(l))
      : (() => { const p = JSON.parse(raw); return Array.isArray(p) ? p : (p.records ?? [p]); })();
  } catch (e: any) {
    out.push({ layer: "JS-NATIVE-CHAIN", fixture: `chain/${f}`, parseError: String(e?.message ?? e) });
    continue;
  }
  let c: any, err: string | null = null;
  try { c = verifyAEPChain(records); } catch (e: any) { err = String(e?.message ?? e); }
  out.push({ layer: "JS-NATIVE-CHAIN", fixture: `chain/${f}`, n: records.length,
             valid: c?.valid ?? null, status: c?.status ?? null, brokenAt: c?.brokenAt ?? null, threw: err });
}

console.log(JSON.stringify(out, null, 1));
