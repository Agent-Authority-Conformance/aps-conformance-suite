#!/usr/bin/env node
/**
 * Cross-stack conformance runner for mcp-audit-gateway-v0.6 family.
 *
 * Verifies that checkpoint.json's vectors recompute to their published
 * `canonical` bytes and `sha256_canonical` digests, verifies hash-chain
 * linkage across the checkpoint chain and rotation boundary, and confirms
 * the truncation-detection, sequence-regression, and chain_break semantics
 * documented in the vector file.
 *
 * Adapted from:
 *   https://github.com/elang2/mcp-audit-gateway (Apache-2.0),
 *   test/vectors/verify-checkpoint.mjs at tag v0.6.0 (commit a0f14a0418c2abe6135436f037f6b171735d1e73).
 *
 * Stdlib-only: node:crypto, node:fs, node:path, node:url. No dependency on
 * mcp-audit-gateway at runtime; the canonicalization logic is inlined here.
 *
 * The canonicalizeValue implementation below is duplicated verbatim in the
 * sibling concern's canonicalization/run.mjs. Any patch to either must land
 * in both, or the two concerns will silently diverge on the same input.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(__dirname, "checkpoint.json"), "utf-8"),
);

const results = {
  fixture: "checkpoint/checkpoint.json",
  source: "elang2/mcp-audit-gateway v0.6.0 (commit a0f14a0418c2abe6135436f037f6b171735d1e73)",
  recomputer: "checkpoint/run.mjs, stdlib-only Node (node:crypto + node:fs)",
  ran_at: new Date().toISOString(),
  node_version: process.version,
  platform: process.platform,
  passed: 0,
  failed: 0,
  checks: [],
};

function sha256(input) {
  return createHash("sha256").update(input).digest("hex");
}

function hashRecord(rec) {
  return sha256(JSON.stringify(rec));
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
      if (!Number.isSafeInteger(value))
        throw new Error(`unsafe number ${value}`);
      return value;
    case "object":
      if (Array.isArray(value)) return ["L", value.map(canonicalizeValue)];
      const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
      return ["M", keys.map((k) => [k, canonicalizeValue(value[k])])];
    default:
      throw new Error(`unsupported type ${typeof value}`);
  }
}

function canonicalizeCheckpoint(rec) {
  const ordered = [
    ["id", rec.id],
    ["type", "checkpoint"],
    ["timestamp", rec.timestamp],
    ["sequence", rec.sequence],
    ["recordCount", rec.recordCount],
    ["previousHash", rec.previousHash],
  ];
  if (rec.parties != null) ordered.push(["parties", rec.parties]);
  return JSON.stringify(ordered);
}

function canonicalizeRecord(rec) {
  const ordered = [
    ["id", rec.id],
    ["timestamp", rec.timestamp],
    ["method", rec.method],
    ["toolName", rec.toolName ?? null],
    ["namespace", rec.namespace ?? null],
    ["upstream", rec.upstream ?? null],
    ["principal", rec.principal ?? null],
    ["durationMs", rec.durationMs],
    ["success", rec.success],
    ["errorCode", rec.errorCode ?? null],
    ["previousHash", rec.previousHash ?? null],
  ];
  let insertAt = 11;
  if (rec.decisionContextDigest != null) {
    ordered.splice(10, 0, ["decisionContextDigest", rec.decisionContextDigest]);
    insertAt = 12;
  }
  if (rec.extensionsDigest != null) {
    ordered.splice(insertAt, 0, ["extensionsDigest", rec.extensionsDigest]);
    insertAt++;
  }
  if (rec.aiInvocation != null) {
    ordered.splice(insertAt, 0, ["aiInvocation", canonicalizeValue(rec.aiInvocation)]);
    insertAt++;
  }
  if (rec.parties != null) {
    ordered.splice(insertAt, 0, ["parties", rec.parties]);
  }
  return JSON.stringify(ordered);
}

function computeExtensionsDigest(extensions) {
  const canonicalized = canonicalizeValue(extensions);
  const canonical = JSON.stringify(canonicalized);
  return { canonical, digest: sha256(canonical) };
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

// --- Checkpoint Canonicalization ---
console.log("\n=== Checkpoint Canonicalization ===");
for (const vec of vectors.checkpoint_canonicalization) {
  const canonical = canonicalizeCheckpoint(vec.record);
  record(
    `checkpoint_canonicalization/${vec.name}/canonical`,
    canonical === vec.canonical,
    `expected: ${vec.canonical}\n        got:      ${canonical}`,
  );
  const hash = sha256(canonical);
  record(
    `checkpoint_canonicalization/${vec.name}/sha256`,
    hash === vec.sha256_canonical,
    `expected: ${vec.sha256_canonical}\n        got:      ${hash}`,
  );
}

// --- Checkpoint Chain ---
console.log("\n=== Checkpoint Chain ===");
const chainRecords = vectors.checkpoint_chain.records;
for (let i = 0; i < chainRecords.length; i++) {
  const entry = chainRecords[i];
  const computedHash = hashRecord(entry.record);
  record(
    `checkpoint_chain/record[${i}]/hash`,
    computedHash === entry.record_hash,
    `expected: ${entry.record_hash}\n        got:      ${computedHash}`,
  );
  if (i > 0) {
    record(
      `checkpoint_chain/record[${i}]/previousHash_links_to_record[${i - 1}]`,
      entry.record.previousHash === chainRecords[i - 1].record_hash,
      `expected: ${chainRecords[i - 1].record_hash}\n        got:      ${entry.record.previousHash}`,
    );
  }
}

// --- Truncation Detection ---
console.log("\n=== Truncation Detection ===");
const truncVec = vectors.truncation_detection;
const extCkpt = truncVec.external_checkpoint;
const fullChain = chainRecords.map((e) => e.record);
let foundInFull = false;
for (const rec of fullChain) {
  if (
    rec.type === "checkpoint" &&
    rec.previousHash === extCkpt.previousHash &&
    rec.sequence === extCkpt.sequence &&
    rec.recordCount === extCkpt.recordCount
  ) {
    foundInFull = true;
  }
}
record("truncation_detection/full_chain_contains_externalized_checkpoint", foundInFull, null);
const truncatedChain = truncVec.truncated_chain.records_delivered;
let foundInTruncated = false;
let hasDescendant = false;
for (const rec of truncatedChain) {
  if (rec.type === "checkpoint") {
    if (
      rec.previousHash === extCkpt.previousHash &&
      rec.sequence === extCkpt.sequence &&
      rec.recordCount === extCkpt.recordCount
    ) {
      foundInTruncated = true;
    }
    if (rec.sequence > extCkpt.sequence) hasDescendant = true;
  }
}
record(
  "truncation_detection/truncated_chain_missing_checkpoint (head_missing detected)",
  !foundInTruncated && !hasDescendant,
  null,
);

// --- canonicalizeValue ---
console.log("\n=== canonicalizeValue ===");
const cvVectors = vectors.canonicalize_value.vectors;
for (const vec of cvVectors) {
  if (vec.expected_error) {
    if (vec.construct) {
      let threw = false;
      try {
        canonicalizeValue(String.fromCharCode(0xD800));
      } catch {
        threw = true;
      }
      record(`canonicalize_value/${vec.name}/throws_on_invalid_input`, threw, null);
    } else {
      let threw = false;
      try {
        canonicalizeValue(vec.input);
      } catch {
        threw = true;
      }
      record(`canonicalize_value/${vec.name}/throws_on_invalid_input`, threw, null);
    }
    continue;
  }
  if (vec.input_a && vec.input_b && vec.canonical_form) {
    const ra = computeExtensionsDigest(vec.input_a);
    const rb = computeExtensionsDigest(vec.input_b);
    record(
      `canonicalize_value/${vec.name}/canonical_form`,
      ra.canonical === vec.canonical_form,
      `expected: ${vec.canonical_form}\n        got:      ${ra.canonical}`,
    );
    record(
      `canonicalize_value/${vec.name}/digest`,
      ra.digest === vec.digest,
      `expected: ${vec.digest}\n        got:      ${ra.digest}`,
    );
    record(
      `canonicalize_value/${vec.name}/both_inputs_same_digest`,
      ra.digest === rb.digest,
      null,
    );
  } else if (vec.input_a && vec.input_b && vec.canonical_a) {
    const ra = computeExtensionsDigest(vec.input_a);
    const rb = computeExtensionsDigest(vec.input_b);
    record(`canonicalize_value/${vec.name}/canonical_a`, ra.canonical === vec.canonical_a, null);
    record(`canonicalize_value/${vec.name}/digest_a`, ra.digest === vec.digest_a, null);
    record(`canonicalize_value/${vec.name}/canonical_b`, rb.canonical === vec.canonical_b, null);
    record(`canonicalize_value/${vec.name}/digest_b`, rb.digest === vec.digest_b, null);
    record(`canonicalize_value/${vec.name}/digests_differ`, ra.digest !== rb.digest, null);
  } else if (vec.input) {
    const r = computeExtensionsDigest(vec.input);
    record(
      `canonicalize_value/${vec.name}/canonical_form`,
      r.canonical === vec.canonical_form,
      `expected: ${vec.canonical_form}\n        got:      ${r.canonical}`,
    );
    record(
      `canonicalize_value/${vec.name}/digest`,
      r.digest === vec.digest,
      `expected: ${vec.digest}\n        got:      ${r.digest}`,
    );
  }
}

// --- Extensions Digest ---
console.log("\n=== Extensions Digest ===");
const extVectors = vectors.extensions_digest.vectors;
for (const vec of extVectors) {
  const { canonical, digest } = computeExtensionsDigest(vec.extensions);
  record(
    `extensions_digest/${vec.name}/canonical_form`,
    canonical === vec.canonical_form,
    `expected: ${vec.canonical_form}\n        got:      ${canonical}`,
  );
  record(
    `extensions_digest/${vec.name}/digest`,
    digest === vec.digest,
    `expected: ${vec.digest}\n        got:      ${digest}`,
  );
}

const withExt = vectors.extensions_digest.record_canonicalization.with_extensions_digest;
const withExtCanonical = canonicalizeRecord(withExt.record);
record(
  "extensions_digest/record_with_extensionsDigest/canonical",
  withExtCanonical === withExt.canonical,
  `expected: ${withExt.canonical}\n        got:      ${withExtCanonical}`,
);
record(
  "extensions_digest/record_with_extensionsDigest/sha256",
  sha256(withExtCanonical) === withExt.sha256_canonical,
  `expected: ${withExt.sha256_canonical}\n        got:      ${sha256(withExtCanonical)}`,
);

const withoutExt = vectors.extensions_digest.record_canonicalization.without_extensions_digest;
const withoutExtCanonical = canonicalizeRecord(withoutExt.record);
record(
  "extensions_digest/record_without_extensionsDigest/canonical (backward_compat)",
  withoutExtCanonical === withoutExt.canonical,
  `expected: ${withoutExt.canonical}\n        got:      ${withoutExtCanonical}`,
);
record(
  "extensions_digest/record_without_extensionsDigest/sha256",
  sha256(withoutExtCanonical) === withoutExt.sha256_canonical,
  `expected: ${withoutExt.sha256_canonical}\n        got:      ${sha256(withoutExtCanonical)}`,
);

// --- Rotation Boundary ---
console.log("\n=== Rotation Boundary ===");
const rotation = vectors.rotation_boundary;
for (let i = 0; i < rotation.file_1_records.length; i++) {
  const entry = rotation.file_1_records[i];
  const h = hashRecord(entry.record);
  record(
    `rotation_boundary/file1/record[${i}]/hash`,
    h === entry.record_hash,
    `expected: ${entry.record_hash}\n        got:      ${h}`,
  );
}
const file1LastHash = rotation.file_1_records[rotation.file_1_records.length - 1].record_hash;
const file2First = rotation.file_2_records[0];
record(
  "rotation_boundary/file2_first_chains_to_file1_last_hash",
  file2First.record.previousHash === file1LastHash,
  `expected: ${file1LastHash}\n        got:      ${file2First.record.previousHash}`,
);
const file2Hash = hashRecord(file2First.record);
record(
  "rotation_boundary/file2/record[0]/hash",
  file2Hash === file2First.record_hash,
  `expected: ${file2First.record_hash}\n        got:      ${file2Hash}`,
);

// --- Sequence Regression ---
console.log("\n=== Sequence Regression ===");
const seqReg = vectors.sequence_regression;
const checkpoints = seqReg.chain.filter((e) => e.record.type === "checkpoint");
let regressionDetected = false;
for (let i = 1; i < checkpoints.length; i++) {
  if (checkpoints[i].record.sequence <= checkpoints[i - 1].record.sequence) {
    regressionDetected = true;
  }
}
record("sequence_regression/detected_in_chain", regressionDetected, null);
record(
  "sequence_regression/failure_code_is_sequence_regression",
  seqReg.detection_result.failureCode === "sequence_regression",
  null,
);

// --- Chain Break ---
console.log("\n=== Chain Break ===");
const chainBreak = vectors.chain_break;
for (let i = 0; i < chainBreak.records.length; i++) {
  const entry = chainBreak.records[i];
  const h = hashRecord(entry.record);
  record(
    `chain_break/record[${i}]/hash`,
    h === entry.record_hash,
    `expected: ${entry.record_hash}\n        got:      ${h}`,
  );
}
record(
  "chain_break/successor_chains_from_break_record_hash",
  chainBreak.records[1].record.previousHash === chainBreak.records[0].record_hash,
  null,
);

// --- Summary ---
console.log(`\n=== Results: ${results.passed} passed, ${results.failed} failed (${results.passed + results.failed} total) ===`);

writeFileSync(
  join(__dirname, "results.json"),
  JSON.stringify(results, null, 2) + "\n",
);
console.log(`\nWrote ${join(__dirname, "results.json")}`);

process.exit(results.failed > 0 ? 1 : 0);
