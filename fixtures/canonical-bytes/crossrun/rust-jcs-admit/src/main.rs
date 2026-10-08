// Copyright 2026 Sankalp Gilda. Apache-2.0 license. See LICENSE.
//
// Rust runner for the RFC 8785 canonical-byte cross-run, second Rust
// canonicalizer.
//
// Reports where this canonicalizer's bytes and SHA-256 agree with the pinned
// fixture. It is not a verdict on the implementation, and it is not APS
// conformance; it is a byte diff on ten cases.
//
// Canonicalizer under test: jcs_admit::admit from the published jcs-admit
// crate, pinned at exactly 0.1.1 in Cargo.toml. jcs-admit decides on raw bytes
// before any decode, so this runner hands it each vector's `input` exactly as
// the fixture file spells it (`1e+21`, `295147905179352825856`), not a
// re-serialization through serde_json, which would rewrite those tokens before
// the canonicalizer saw them.
//
// Every expected value is read from the fixture at run time. Nothing about the
// ten cases is transcribed into this file.
//
// Usage:
//   cargo run --quiet -- [fixture-path]
// Default fixture: ../../canonical-bytes-jcs-v2.json

use serde_json::json;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

type RawObject = HashMap<String, Box<RawValue>>;

/// The dependency version AS LOCKED, read from the lockfile that produced this
/// binary, so the reported version cannot drift from the one that built.
fn locked_version(crate_name: &str) -> String {
    let lock = include_str!("../Cargo.lock");
    let mut in_block = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_block = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            in_block = rest.trim_matches('"') == crate_name;
            continue;
        }
        if in_block {
            if let Some(rest) = line.strip_prefix("version = ") {
                return rest.trim_matches('"').to_string();
            }
        }
    }
    "unknown".to_string()
}

/// Zero-based offset of the first differing byte; the length of the shorter
/// sequence when one is a prefix of the other; None when the bytes are equal.
fn first_divergent_byte_offset(a: &[u8], b: &[u8]) -> Option<usize> {
    let shared = a.len().min(b.len());
    for i in 0..shared {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() == b.len() {
        None
    } else {
        Some(shared)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn fail(msg: String) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

/// A string member of a vector, decoded from its raw JSON.
fn string_member(vector: &RawObject, key: &str, name: &str) -> String {
    let raw = vector
        .get(key)
        .unwrap_or_else(|| fail(format!("vector {} has no {}", name, key)));
    serde_json::from_str::<String>(raw.get())
        .unwrap_or_else(|e| fail(format!("vector {} member {}: {}", name, key, e)))
}

fn main() {
    let fixture_path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../canonical-bytes-jcs-v2.json"));
    let fixture_path = std::fs::canonicalize(&fixture_path)
        .unwrap_or_else(|e| fail(format!("resolve fixture path {}: {}", fixture_path.display(), e)));
    let fixture_bytes =
        std::fs::read(&fixture_path).unwrap_or_else(|e| fail(format!("read fixture: {}", e)));
    let fixture_text = std::str::from_utf8(&fixture_bytes)
        .unwrap_or_else(|e| fail(format!("fixture is not UTF-8: {}", e)));
    let top: RawObject = serde_json::from_str(fixture_text)
        .unwrap_or_else(|e| fail(format!("parse fixture: {}", e)));
    let vectors_raw = top
        .get("vectors")
        .unwrap_or_else(|| fail("fixture has no vectors array".to_string()));
    let vectors: Vec<RawObject> = serde_json::from_str(vectors_raw.get())
        .unwrap_or_else(|e| fail(format!("fixture vectors: {}", e)));

    let mut cases = Vec::with_capacity(vectors.len());
    let (mut byte_matches, mut sha_matches) = (0usize, 0usize);

    for v in &vectors {
        let name = string_member(v, "name", "(unnamed)");
        let input = v
            .get("input")
            .unwrap_or_else(|| fail(format!("vector {} has no input", name)));
        let canonical = jcs_admit::admit(input.get().as_bytes())
            .unwrap_or_else(|e| fail(format!("canonicalize {}: {}", name, e)));
        let actual = canonical.as_slice();
        let expected = hex::decode(string_member(v, "canonical_bytes_hex", &name))
            .unwrap_or_else(|e| fail(format!("decode expected hex for {}: {}", name, e)));
        let actual_sha = sha256_hex(actual);
        let byte_match = actual == expected.as_slice();
        let sha_match = actual_sha == string_member(v, "canonical_sha256", &name);
        if byte_match {
            byte_matches += 1;
        }
        if sha_match {
            sha_matches += 1;
        }
        let offset = if byte_match {
            None
        } else {
            first_divergent_byte_offset(actual, &expected)
        };
        cases.push(json!({
            "name": name,
            "byte_match": byte_match,
            "sha256_match": sha_match,
            "actual_bytes_hex": hex::encode(actual),
            "actual_sha256": actual_sha,
            "first_divergent_byte_offset": offset,
        }));
    }

    let total = cases.len();
    let report = json!({
        "runner": "rust",
        "implementation": "jcs_admit::admit",
        "implementation_kind": "rfc8785",
        "implementation_version": locked_version("jcs-admit"),
        "runtime_version": env!("CROSSRUN_RUSTC_VERSION"),
        "fixture": fixture_path.display().to_string(),
        "fixture_sha256": sha256_hex(&fixture_bytes),
        "cases": cases,
        "summary": {
            "total": total,
            "byte_match": byte_matches,
            "sha256_match": sha_matches,
        }
    });
    let out = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|e| fail(format!("serialize report: {}", e)));
    println!("{}", out);
}
