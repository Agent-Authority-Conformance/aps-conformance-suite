// Lab driver, RUST-NATIVE-DSSE. Untracked lab artifact, not upstream test content.
// Calls only the public `verify_record_dsse` surface and records the collapsed result.
use aep_core::{verify_record_dsse, AepRecord};
use std::{fs, path::PathBuf};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../wasmagent-protocol/conformance/aep")
}

fn key(name: &str) -> ed25519_dalek::VerifyingKey {
    let hex_str = fs::read_to_string(corpus().join(name)).unwrap();
    let raw = hex::decode(hex_str.trim()).unwrap();
    let arr: [u8; 32] = raw.as_slice().try_into().unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&arr).unwrap()
}

#[test]
fn lab_rust_native_dsse() {
    let js_key = key("dsse/js-verify-key.hex");
    let rust_key = key("dsse/rust-fixture-verify-key.hex");

    let mut rows: Vec<String> = Vec::new();
    let mut paths: Vec<_> = fs::read_dir(corpus().join("dsse"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();

    for p in paths {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let text = fs::read_to_string(&p).unwrap();
        let parsed: Result<AepRecord, _> = serde_json::from_str(&text);
        let (keyid, outcome) = match parsed {
            Err(e) => (String::from("-"), format!("DESERIALIZE_ERR: {e}")),
            Ok(rec) => {
                let keyid = rec
                    .dsse_envelope
                    .as_ref()
                    .and_then(|e| e.signatures.first())
                    .map(|s| s.keyid.clone())
                    .unwrap_or_default();
                let k = if keyid == "ci-sample-key" { &rust_key } else { &js_key };
                let outcome = match verify_record_dsse(&rec, k) {
                    Ok(()) => String::from("OK"),
                    Err(e) => format!("ERR: {e}"),
                };
                (keyid, outcome)
            }
        };
        rows.push(format!("{{\"layer\":\"RUST-NATIVE-DSSE\",\"fixture\":\"dsse/{name}\",\"keyid\":\"{keyid}\",\"result\":\"{outcome}\"}}"));
    }

    let out = format!("[\n {}\n]\n", rows.join(",\n "));
    fs::write(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../evidence/native-rust.json"),
        &out,
    )
    .unwrap();
    println!("{out}");
}
