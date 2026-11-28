# stolen_key_cannot_self_report_measurement

## Submitter

Abisheak P. (@abisheakp197), Neutral Trust Infrastructure (NTI).

## Normative target

NTI-1 §5 "Workload binding: what it does and does not close", at
`nti-spec` commit `0c34e57`, document version `1.0.0-draft`. The claim under test is
the row: *"Workload binding: A stolen key cannot act off a host that the enforcement
point measured"*, with the stated non-claim *"That the enforcement point observes
honestly; that the measurement describes the real code"*
(`SECURITY_LIMITS.md`, §"What the specification does not claim" table).

The vectors are written in NTI's own terms. No mapping to this suite's vocabulary is
proposed, and none is implied.

## Source

Implementation under test: Neutral-Trust-Infrastructure, module `ube-foundation`,
release `v0.2.1`, commit `f00c22d`.
Test: `ube-foundation/tests/workload_binding.rs`, sha256
`06fc8c14e761eaee8654b7ab462b8f4173872e6d8d37160c18e2e86d8a34e10f`.

The verification code is not copied into this directory. It is linked at its pinned
source, per `docs/CANDIDATES.md`.

## License

Apache-2.0. Source repository licence: Apache-2.0 (`LICENSE` at `f00c22d`). No
third-party notices are carried by this test; it uses no external vectors.

## What the vectors test

The engine binds a principal's key to a workload measurement at registration time.
At evaluation the caller supplies an *observed* measurement, standing in for the
enforcement point, and the request optionally carries a *declared* measurement
signed by the caller.

Three cases, expressed in `vectors.json`:

| id | bound | declared by request | observed | expected |
|---|---|---|---|---|
| SK-00 (control) | `sha256:1111…` | `sha256:1111…` | `sha256:1111…` | **Allow** |
| SK-01 | `sha256:1111…` | `sha256:1111…` | none | **Deny** |
| SK-02 | `sha256:1111…` | `sha256:1111…` | `sha256:2222…` | **Deny** |

SK-01 is the attack the name describes: the key is stolen, the host is not the pinned
workload, and the attacker signs a request that declares the expected digest. The
assertion is that a self-declared measurement never satisfies the binding. SK-02
additionally asserts that an observation which contradicts the declaration wins.

SK-00 exists so a passing result cannot be explained by an engine that denies
everything.

## How to run

Requires the Rust toolchain pinned by the project (1.90.0) and a checkout at `f00c22d`:

```
git clone https://github.com/abisheakp197/Neutral-Trust-Infrastructure
cd Neutral-Trust-Infrastructure
git checkout f00c22d
cargo +1.90.0 test --locked --manifest-path ube-foundation/Cargo.toml \
  --test workload_binding -- --nocapture
```

The project's CI runs the same suite with `--lib --tests` in
`.github/workflows/issuer-quorum-regressions.yml`.

## Evidence

`none yet`.

No author-produced run against the pinned revision has been recorded. An earlier
draft of this file linked run 45229840510, which is at commit `7b7cb29`. That
commit predates `f00c22d` and does not contain `tests/workload_binding.rs`, so the
run cannot evidence these vectors. It is recorded as `none yet` rather than
replaced with a different run, because no run of the suite exists at `f00c22d`.

No independent reproduction has been run. `none yet` for independent evidence.

## Known limitations

- **The observation is supplied by the caller.** `evaluate_with_measurement` takes
  `observed_measurement: Option<&str>`. The vectors therefore test the engine's
  behaviour given an honest observation. They do not test that an enforcement point
  observes honestly, which is the non-claim quoted above, and they do not cover a
  stolen key on a host the enforcement point never measured at all.
- **Single hop only.** No delegation chain is exercised. At `f00c22d`,
  `CapabilityToken` carries `id`, `root_actor`, `capability`, `caveats` and
  `signature`, with no parent reference, so ancestor revocation is not expressible
  and is not covered here.
- **No egress containment.** This candidate says nothing about whether an action
  leaves the host; `ube-foundation` at `f00c22d` ships no egress enforcement point.
- **The observation is not in the audit trail.** `AuditEvent` is
  `{sequence, request, decision, previous_hash, hash}`, and the hash is computed over
  `(sequence, request, decision, previous_hash)`. A third party reading the log
  cannot see which workload was authorised.
- **The measurement is synthetic in the test.** `sha256:1111…` and `sha256:2222…`
  are constants. No TPM, enclave or real image digest is involved, so nothing here
  speaks to attestation validity.
- **Mode A only.** The relevant implementation is the implementation under test.
  There is no alternate implementation recomputation (Mode B).
