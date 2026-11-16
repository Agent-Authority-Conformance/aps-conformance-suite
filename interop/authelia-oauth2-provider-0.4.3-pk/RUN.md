# aeoess-presenter-key-possession through Authelia's DPoP resource check (authelia.com/provider/oauth2 v0.4.3)

## Purpose

A record of one run of the candidate `aeoess-presenter-key-possession` (28 cases, RFC 9449) through the DPoP resource server check in the OAuth 2.0 provider library that Authelia pins. It records what that function returned for these inputs. It is not a conformance verdict on Authelia or on the library, and it adds nothing to the candidate.

## Targets

- Library: authelia.com/provider/oauth2 v0.4.3 (source github.com/authelia/oauth2-provider), go.sum `h1:iuD0z/rKGUfQTz4V8PBOBUqAKGOPF2ltxUFXFQmn2vI=`, Apache-2.0.
- Function: `handler/rfc9449.(*DefaultStrategy).ValidateResourceAccess(ctx, r, accessToken, boundJKT, requireNonce)`, which calls `ValidateDPoPProof` and then checks `ath` and the proof key thumbprint against `boundJKT`.
- Consumer: Authelia main 399547ae8a17f37ec89902531ae32db3f87147c4 (2026-11-15), go.mod line 13 requires v0.4.3. Authelia exposes DPoP bound access tokens per client (`internal/oidc/client.go` line 815).
- Cases: lab origin/main 389b7f4, `candidates/aeoess-presenter-key-possession/vectors.json`, sha256 7e108c346475fb6c213827f657c8a4feaa46e48d0f0b5f3e20f119d98296436f (unchanged since dcda0de).

## The harness

`main.go` (sha256 f6e6cbbd5a6b7635764d0a677f8f9e95b9bd8bf3f8ed6e0c75d05f5d7e95c938) builds one `http.Request` per case with `Authorization: DPoP <access_token>` and `DPoP: <proof>` and calls the function above. These parts are the harness, not library code:

1. Time. The library reads `time.Now()`. The signed cases fix now at 1793750400. The harness sets clock skew 0 and proof lifespan to (real now minus case now) plus `iat_window_s`, so the case's window of 300 s before now maps onto the library's window. The future `iat` check cannot be reached this way, so PK-17 is not run.
2. Nonce store. A nonce is valid only when it equals the case's `server_nonce`. `requireNonce` is true when `server_nonce` is set.
3. Replay store. In memory, keyed on `jti` and the normalized `htu` as the library's storage interface asks, preloaded with the case's `seen_jti`.
4. `boundJKT` is the token's `cnf.jkt`, or empty when the token has no `cnf`. The library answers `invalid_token` for an empty value.
5. Algorithms allowed: `EdDSA` (the candidate's keys are Ed25519).
6. The reported axis of a reject is read from the library's error hint. Mapping in `axisOf`: unbound token, `ath` and key mismatch to `key_binding`; `htm`, `htu`, `iat`, nonce and replay to `request_binding`; everything else to `proof_signature`.
7. Authority (scope) is outside RFC 9449 and outside this function. Not evaluated.

`compare.py` (sha256 4f111182395c408fb6c72a18a0aee76920c173d2e347605fc4ac1e6a74b5d120) recomputes each case's possession axes with the candidate's own `check.truth`, takes accept when all three hold, and for a reject also checks that the reported axis is one that failed.

## Run recorded

- Runner: aeoess, 2026-11-15. macOS 26.5 arm64, Go 1.27.0 (toolchain fetched by GOTOOLCHAIN=auto, the library needs 1.27), Python 3.14.6, `cryptography` 49.0.0.
- Two runs, outputs byte identical (`results.json`, sha256 f1e0c34e441fcb5e24285eb0ba2f5790fad8d71115cf52bf2ba39119d260bbb5).
- Result: `agree=27 differ=0 ambiguous=0 not_run=1 of 28; reject axis named a failing axis: 22, did not: 0`, exit 0. Full output in `RUN-compare.txt`.
- Accepted: PK-01, PK-13 (htu differs only in query), PK-19 to PK-21 (possession holds, scope not evaluated).
- Refused at key binding: PK-02 to 04 and PK-22 (attacker's own key), PK-10 (`ath` of another token), PK-11 (token without `cnf`, `invalid_token`), PK-23 and PK-26, 27 (no `ath`).
- Refused at request binding: PK-12, 14, 16, 18 (`htm`, `htu`, window, replay), PK-15, 24, 28 (`use_dpop_nonce`).
- Refused at the proof: PK-05 to 09, PK-25.
- Not run: PK-17 (see harness item 1). The candidate leaves PK-17 open anyway.

### Control

Changing PK-14 to accept in a copy of the results gives `agree=26 differ=1` from `compare.py`, so a wrong answer is reported.

## Commands

    $ git clone https://github.com/authelia/authelia && git -C authelia checkout 399547ae8a17f37ec89902531ae32db3f87147c4
    $ grep -n "authelia.com/provider/oauth2" authelia/go.mod
    $ go mod init pkharness && GOTOOLCHAIN=auto go get authelia.com/provider/oauth2@v0.4.3 && GOTOOLCHAIN=auto go mod tidy
    $ GOTOOLCHAIN=auto go build -o pk_harness .
    $ ./pk_harness vectors.json > results.json
    $ python3 -I compare.py <lab>/candidates/aeoess-presenter-key-possession vectors.json results.json

## Verification split

- possession decision and reject axis per case / this run; aeoess; Mode A; author-produced; authelia.com/provider/oauth2 v0.4.3 `ValidateResourceAccess`. The runner authored the cases and the harness, and the harness decides the time mapping, the nonce and replay stores and the axis reading of each error hint.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## What this does not show

Authelia's own HTTP endpoints, its storage, its stateless nonces, or any algorithm other than EdDSA. Agreement on 27 inputs says nothing about other inputs. No independence and no adoption claim.
