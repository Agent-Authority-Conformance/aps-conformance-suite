#!/usr/bin/env node
/**
 * Cross-stack conformance runner for mcp-audit-gateway-v0.6 family.
 *
 * Verifies that canonicalization.json's vectors recompute to their published
 * `canonical` bytes and `sha256_canonical` digests, using only Node's stdlib.
 *
 * Adapted from:
 *   https://github.com/elang2/mcp-audit-gateway (Apache-2.0),
 *   test/vectors/verify.mjs at tag v0.6.0 (commit a0f14a0418c2abe6135436f037f6b171735d1e73).
 *
 * Stdlib-only: node:crypto, node:fs, node:path, node:url. No dependency on
 * mcp-audit-gateway at runtime; the canonicalization logic is inlined here.
 *
 * The canonicalizeValue implementation below is duplicated verbatim in the
 * sibling concern's checkpoint/run.mjs. Any patch to either must land in
 * both, or the two concerns will silently diverge on the same input.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(__dirname, "canonicalization.json"), "utf-8"),
);

const results = {
  fixture: "canonicalization/canonicalization.json",
  source: "elang2/mcp-audit-gateway v0.6.0 (commit a0f14a0418c2abe6135436f037f6b171735d1e73)",
  recomputer: "canonicalization/run.mjs, stdlib-only Node (node:crypto + node:fs)",
  ran_at: new Date().toISOString(),
  node_version: process.version,
  platform: process.platform,
  passed: 0,
  failed: 0,
  checks: [],
};

function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

function canonicalizeValue(value) {
  if (value === null || value === undefined) return null;
  switch (typeof value) {
    case "string":
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 0xD800 && code <= 0xDBFF) {
          const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
          if (next < 0xDC00 || next > 0xDFFF)
            throw new Error(`unpaired surrogate at index ${i}`);
          i++;
        } else if (code >= 0xDC00 && code <= 0xDFFF) {
          throw new Error(`unpaired surrogate at index ${i}`);
        }
      }
      return value;
    case "boolean":
      return value;
    case "number":
      if (!Number.isSafeInteger(value)) throw new Error(`unsafe number ${value}`);
      return value;
    case "object": {
      if (Array.isArray(value)) return ["L", value.map(canonicalizeValue)];
      const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
      return ["M", keys.map((k) => [k, canonicalizeValue(value[k])])];
    }
    default:
      throw new Error(`unsupported type ${typeof value}`);
  }
}

function canonicalizeFromRecord(record, fieldOrder) {
  const ordered = fieldOrder.map((key) => [key, record[key] ?? null]);
  let insertAt = 11;
  if (record.decisionContextDigest != null) {
    ordered.splice(10, 0, ["decisionContextDigest", record.decisionContextDigest]);
    insertAt = 12;
  }
  if (record.extensionsDigest != null) {
    ordered.splice(insertAt, 0, ["extensionsDigest", record.extensionsDigest]);
    insertAt++;
  }
  if (record.aiInvocation != null) {
    ordered.splice(insertAt, 0, ["aiInvocation", canonicalizeValue(record.aiInvocation)]);
    insertAt++;
  }
  if (record.parties != null) {
    ordered.splice(insertAt, 0, ["parties", record.parties]);
  }
  return JSON.stringify(ordered);
}

function record(name, ok, detail) {
  if (ok) {
    console.log(`  PASS: ${name}`);
    results.passed++;
    results.checks.push({ name, status: "PASS" });
  } else {
    console.log(`  FAIL: ${name}`);
    if (detail) console.log(`        ${detail}`);
    results.failed++;
    results.checks.push({ name, status: "FAIL", detail: detail ?? null });
  }
}

console.log(`Format version: ${vectors.format_version}`);
console.log(`Encoding: ${vectors.encoding}`);
console.log(`Hash: ${vectors.hash_algorithm} (${vectors.hash_output})`);

// --- Canonicalization vectors ---
console.log("\n=== Canonicalization Vectors ===\n");
for (const v of vectors.canonicalization) {
  const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
  const hash = sha256Hex(canonical);
  const canonMatch = canonical === v.canonical;
  const hashMatch = hash === v.sha256_canonical;
  record(
    `canonicalization/${v.name}`,
    canonMatch && hashMatch,
    !canonMatch
      ? `canonical expected: ${v.canonical}\n        canonical got:      ${canonical}`
      : !hashMatch
        ? `hash expected: ${v.sha256_canonical}\n        hash got:      ${hash}`
        : null,
  );
}

// --- Chain vectors ---
console.log("\n=== Chain Vectors ===\n");
for (let i = 0; i < vectors.chain.records.length; i++) {
  const entry = vectors.chain.records[i];
  const rec = entry.record;
  const canonical = canonicalizeFromRecord(rec, vectors.field_order);
  const canonHash = sha256Hex(canonical);
  record(
    `chain[${i}]/canonical (${rec.toolName})`,
    canonical === entry.canonical && canonHash === entry.sha256_canonical,
    canonical !== entry.canonical
      ? `canonical mismatch`
      : canonHash !== entry.sha256_canonical
        ? `canonical hash mismatch`
        : null,
  );
  const refHash = sha256Hex(entry.full_record_json);
  record(
    `chain[${i}]/record_hash (${rec.toolName})`,
    refHash === entry.record_hash,
    `expected: ${entry.record_hash}\n        got:      ${refHash}`,
  );
  const nativeJson = JSON.stringify(rec);
  const nativeHash = sha256Hex(nativeJson);
  record(
    `chain[${i}]/native_stringify_match (${rec.toolName})`,
    nativeHash === entry.record_hash,
    nativeHash !== entry.record_hash ? `native stringify diverges from reference` : null,
  );
  let linkageOk;
  if (i === 0) {
    linkageOk = rec.previousHash === vectors.chain.genesis_seed;
  } else {
    const prev = vectors.chain.records[i - 1];
    linkageOk =
      rec.previousHash === prev.record_hash &&
      entry.previous_record_hash === prev.record_hash;
  }
  record(`chain[${i}]/linkage (${rec.toolName})`, linkageOk, null);
}

// --- Dual-hash demonstration ---
console.log("\n=== Dual-Hash Demonstration ===\n");
const demo = vectors.dual_hash_demo;
const canonA = canonicalizeFromRecord(demo.record_a.record, vectors.field_order);
const canonB = canonicalizeFromRecord(demo.record_b.record, vectors.field_order);
const hashA = sha256Hex(canonA);
const hashB = sha256Hex(canonB);
record(
  "dual_hash/canonical_hashes_match (attestation excluded)",
  hashA === hashB && hashA === demo.record_a.sha256_canonical,
  null,
);
const chainA = sha256Hex(demo.record_a.full_record_json);
const chainB = sha256Hex(demo.record_b.full_record_json);
record(
  "dual_hash/chain_hashes_differ (attestation included)",
  chainA !== chainB && chainA === demo.record_a.record_hash && chainB === demo.record_b.record_hash,
  null,
);
record(
  "dual_hash/assertions.canonical_hashes_match",
  demo.assertions.canonical_hashes_match === true,
  null,
);
record(
  "dual_hash/assertions.chain_hashes_differ",
  demo.assertions.chain_hashes_differ === true,
  null,
);

// --- Party Attribution vectors ---
if (vectors.party_attribution) {
  console.log("\n=== Party Attribution Vectors ===\n");
  for (const v of vectors.party_attribution.vectors) {
    const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
    const hash = sha256Hex(canonical);
    record(
      `party_attribution/${v.name}`,
      canonical === v.canonical && hash === v.sha256_canonical,
      canonical !== v.canonical
        ? `canonical expected: ${v.canonical}\n        canonical got:      ${canonical}`
        : hash !== v.sha256_canonical
          ? `hash expected: ${v.sha256_canonical}\n        hash got:      ${hash}`
          : null,
    );
  }
}

// --- Chain with Parties ---
if (vectors.party_attribution?.chain_with_parties) {
  console.log("\n=== Chain with Parties ===\n");
  const cwp = vectors.party_attribution.chain_with_parties;
  for (let i = 0; i < cwp.records.length; i++) {
    const entry = cwp.records[i];
    const rec = entry.record;
    const canonical = canonicalizeFromRecord(rec, vectors.field_order);
    const canonHash = sha256Hex(canonical);
    record(
      `chain_with_parties[${i}]/canonical (${rec.toolName})`,
      canonical === entry.canonical && canonHash === entry.sha256_canonical,
      null,
    );
    const refHash = sha256Hex(entry.full_record_json);
    record(
      `chain_with_parties[${i}]/record_hash (${rec.toolName})`,
      refHash === entry.record_hash,
      `expected: ${entry.record_hash}\n        got:      ${refHash}`,
    );
    let linkageOk;
    if (i === 0) {
      linkageOk = rec.previousHash === cwp.genesis_seed;
    } else {
      const prev = cwp.records[i - 1];
      linkageOk =
        rec.previousHash === prev.record_hash &&
        entry.previous_record_hash === prev.record_hash;
    }
    record(`chain_with_parties[${i}]/linkage (${rec.toolName})`, linkageOk, null);
  }
}

// --- Scope Order Significance ---
if (vectors.party_attribution) {
  const paVecs = vectors.party_attribution.vectors;
  const origVec = paVecs.find((v) => v.name === "scope_order_original");
  const sortVec = paVecs.find((v) => v.name === "scope_order_sorted");
  if (origVec && sortVec) {
    console.log("\n=== Scope Order Significance ===\n");
    const hOrig = sha256Hex(canonicalizeFromRecord(origVec.record, vectors.field_order));
    const hSort = sha256Hex(canonicalizeFromRecord(sortVec.record, vectors.field_order));
    record("scope_order/different_order_different_hash", hOrig !== hSort, null);
  }
}

// --- aiInvocation signing vectors ---
if (vectors.ai_invocation_signing) {
  console.log("\n=== aiInvocation Signing ===\n");
  for (const v of vectors.ai_invocation_signing.vectors) {
    const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
    record(`ai_invocation_signing/${v.name}/canonical`, canonical === v.canonical, null);
    record(`ai_invocation_signing/${v.name}/digest`, sha256Hex(canonical) === v.sha256_canonical, null);
  }
  const mn = vectors.ai_invocation_signing.mutation_negative;
  const hOrig = sha256Hex(canonicalizeFromRecord(mn.original.record, vectors.field_order));
  const hMut = sha256Hex(canonicalizeFromRecord(mn.mutated.record, vectors.field_order));
  record(
    "ai_invocation_signing/mutation_pair_digests_reproduce",
    hOrig === mn.original.sha256_canonical && hMut === mn.mutated.sha256_canonical,
    null,
  );
  record("ai_invocation_signing/mutation_changes_digest", hOrig !== hMut, null);
}

// --- extensionsDigest base-suite vectors ---
if (vectors.extensions_digest_base) {
  console.log("\n=== extensionsDigest (base suite) ===\n");
  for (const v of vectors.extensions_digest_base.vectors) {
    const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
    record(`extensions_digest_base/${v.name}/canonical`, canonical === v.canonical, null);
    record(`extensions_digest_base/${v.name}/digest`, sha256Hex(canonical) === v.sha256_canonical, null);
  }
}

console.log(`\n=== Results: ${results.passed} passed, ${results.failed} failed ===`);

writeFileSync(
  join(__dirname, "results.json"),
  JSON.stringify(results, null, 2) + "\n",
);
console.log(`\nWrote ${join(__dirname, "results.json")}`);

process.exit(results.failed > 0 ? 1 : 0);
