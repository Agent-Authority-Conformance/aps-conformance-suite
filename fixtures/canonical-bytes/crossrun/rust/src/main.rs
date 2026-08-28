// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Rust runner for the RFC 8785 canonical-byte cross-run.
//
// Reports where this canonicalizer's bytes and SHA-256 agree with the pinned
// fixture. It is not a verdict on the implementation, and it is not APS
// conformance; it is a byte diff on ten cases.
//
// Canonicalizer under test: agent_passport::jcs::canonicalize from the
// published agent-passport-system crate, pinned at exactly 0.1.0 in Cargo.toml.
//
// Every expected value is read from the fixture at run time. Nothing about the
// ten cases is transcribed into this file.
//
// Usage:
//   cargo run --quiet -- [fixture-path]
// Default fixture: ../../canonical-bytes-jcs-v2.json

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The dependency version AS LOCKED, read from the lockfile that produced this
/// binary rather than typed here, so the reported version cannot drift from the
/// one that built. Cargo exposes the version of the crate being compiled, not of
/// its dependencies, so the lockfile is the available source of truth.
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

/// Zero-based offset of the first differing byte. When one sequence is an exact
/// prefix of the other there is no differing byte, so the answer is the length
/// of the shorter one: the offset a reader would look at to see where the two
/// stopped agreeing. None when the bytes are equal.
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

fn main() {
    let fixture_path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../canonical-bytes-jcs-v2.json"));
    let fixture_path = std::fs::canonicalize(&fixture_path).unwrap_or_else(|e| {
        eprintln!("resolve fixture path {}: {}", fixture_path.display(), e);
        std::process::exit(1);
    });
    let fixture_bytes = std::fs::read(&fixture_path).unwrap_or_else(|e| {
        eprintln!("read fixture: {}", e);
        std::process::exit(1);
    });
    let fixture: Value = serde_json::from_slice(&fixture_bytes).unwrap_or_else(|e| {
        eprintln!("parse fixture: {}", e);
        std::process::exit(1);
    });

    let vectors = fixture["vectors"].as_array().unwrap_or_else(|| {
        eprintln!("fixture has no vectors array");
        std::process::exit(1);
    });

    let mut cases = Vec::with_capacity(vectors.len());
    let (mut byte_matches, mut sha_matches) = (0usize, 0usize);

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("").to_string();
        let canonical = agent_passport::jcs::canonicalize(&v["input"]).unwrap_or_else(|e| {
            eprintln!("canonicalize {}: {:?}", name, e);
            std::process::exit(1);
        });
        let actual = canonical.as_bytes();
        let expected = hex::decode(v["canonical_bytes_hex"].as_str().unwrap_or(""))
            .unwrap_or_else(|e| {
                eprintln!("decode expected hex for {}: {}", name, e);
                std::process::exit(1);
            });
        let actual_sha = sha256_hex(actual);
        let byte_match = actual == expected.as_slice();
        let sha_match = actual_sha == v["canonical_sha256"].as_str().unwrap_or("");
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
        "implementation": "agent_passport::jcs::canonicalize",
        "implementation_kind": "first_party",
        "implementation_version": locked_version("agent-passport-system"),
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
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
