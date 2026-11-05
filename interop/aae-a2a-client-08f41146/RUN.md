# AAE profile for A2A: a client written from the spec against the reference supplier

Run record, 2026-11-02 UTC. Context: a2aproject/A2A#2391 and the cross-run guide in MoltyCel/aae-a2a-extension.

## Pins

    reference repository  MoltyCel/aae-a2a-extension at 08f41146ac0d24d0d3e6212256fd9f3f58079adb
    cases                 tests/vectors/crossrun/cases.json, sha256 831afbda4971b96da18d629c2244c79c724e88dae0a393b1034641654330008f, 24 cases
    draft                 draft-kroehl-agentic-trust-aae-02, sha256 08e202ecc06d245b287e60591098c22d8af480fc88cb455defc9e7612a473b4c, not copied here
    client                client/aae-client.mjs at this repository's commit 58639f603686c5aea9ed529e7080dfc7a4539435
    role                  client (CROSSRUN.md section 1), reference supplier run locally on 127.0.0.1:8790
    environment           macOS 26.5, Node v24.11.1 (client), Python 3.12 venv for the reference supplier and its checker

## What the client is

`client/aae-client.mjs` speaks JSON-RPC A2A over `fetch` and uses Node built-ins only: no a2a-sdk, no protobuf library, no
JCS library. It was written from the draft, the profile text and CROSSRUN.md. It shares no code with the reference
implementation. The run was not blind: the guide prints the expected result of every case, and the reference `build_aae`
was read during a code review before the run.

The client's source and its result files call it an "independent Node.js client (no reference code)". That means it was
written separately from the reference implementation. It is not the lab's `independent` record label, and this record is
author-produced (see Verification split).

## Results

- Run 2 (`results/run-2/`, the published run, client at 58639f6): client exit 0, `24 pass, 0 fail, 0 skipped`, client
  self checks `217 ok, 0 not ok`. The reference checker `python -m aae_a2a.crossrun check` on the result file: exit 0,
  `valid (24 pass, 0 fail, 0 skipped)`.
- Run 1 (`results/run-1-local/`, same client before two metadata arguments were added, local commit 312ac0e): the same
  counts, plus a reference buyer against reference supplier baseline at 24 pass. Kept unchanged with its notes.
- The supplier decision log in each run agrees with the client's records for every task.

## Observations, not failures

1. XR-04 sends `"amount": 120.0` to exercise canonicalization, while section 6.4 of the profile text
   (`spec/aae-a2a-extension-v1.md`) says a client must encode integer valued fields as integers. The case and the section disagree in wording. The observed result does not change.
2. The reference Agent Card serializes `params.max_ancestors` as `16.0`, from the protobuf Struct layer section 6.4
   describes. Whether that conflicts with the integer type that section 4 of the profile text gives `max_ancestors` depends
   on which numeric reading applies.

## What this run does not show

It tests the reference supplier only, not an independent server. It is an interoperability result between two
implementations on 24 published cases, not A2A conformance and not a certification. No supplier network traffic was
monitored at runtime. The safety review of the reference code before running it was by reading.

## Verification split

- AAE receiver behavior of the reference supplier, 24 cases; aeoess; Mode A; author-produced; reference supplier at
  08f41146, driven by client/aae-client.mjs. The verdicts are the reference supplier's own output. The runner wrote the
  client that builds each presentation and applies the pass rule. The reference checker, written by the profile author,
  recomputes the same verdicts from the recorded observations.
- request_digest and the enforce and ratification digests the supplier returned, recomputed by the client as part of its
  217 client checks in run 2; aeoess; Mode B; author-produced; client/aae-client.mjs, written by the runner.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Reproduce

Clone the reference repository at the pinned commit, create its venv per its README, start
`python -m aae_a2a.crossrun serve --port 8790`, then run the client with the arguments in `results/run-2/COMMAND.txt`.

Two logs in results/run-2 (check.log, client.stdout.log) had the local absolute path of the result file. That prefix is replaced with `<worktree>/`. Nothing else in any result file was changed.

## Third-party material

These files under `results/` are output of MolTrust software from MoltyCel/aae-a2a-extension at `08f41146`, Copyright (c) 2026 CryptoKRI GmbH, Zurich (MolTrust), Apache License, Version 2.0, run unmodified. They are the reference supplier logs (`*supplier.log`, `*supplier-decisions.jsonl`), the reference buyer against reference supplier baseline (`baseline-ref-vs-ref.*`) and the crossrun checker output (`*check.log`, `*check.exit`). The client, its transcripts and its result JSON are this record's own. The transcripts contain requests the client built from `tests/vectors/crossrun/` in that repository (the crossrun cases and its public test keys, which its NOTICE says are not secrets), read at run time and not copied here.

The Internet-Draft is not copied here. Source: https://www.ietf.org/archive/id/draft-kroehl-agentic-trust-aae-02.txt, sha256 `08e202ecc06d245b287e60591098c22d8af480fc88cb455defc9e7612a473b4c`.
