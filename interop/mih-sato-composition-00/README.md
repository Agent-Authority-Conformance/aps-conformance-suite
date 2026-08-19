# mih-sato composition pack at its -00 pin: independent run

Two from-scratch adapters, one TypeScript and one Python, for the cross-slot
composition conformance pack published by EMILIA Protocol in
emiliaprotocol/emilia-protocol pull request 521, commit
30916c802dcb60251f6af5e0999912a6306117c3. The pack's manifest pins
draft-mih-sato-agent-accountability-composition-00.

Result: all 27 cases reproduce their pinned expectations, 1 positive, 13
negatives and 13 condition-removed controls. The two adapters produce identical
results, and two runs of each produce byte-identical output.

From-scratch: imports are Node builtins in the TypeScript adapter and the Python
standard library in the Python one. No third-party packages, no JCS library, and
no code from the upstream runner. The canonicalizer, the SHA-256 digest form and
the fourteen join checks are written from the published bundle and the pack's
mechanism document.

This run was independently produced. It was not run by the pack's authors.

## Re-run

    cd interop/mih-sato-composition-00
    OUT_DIR=. npx tsx adapter/ts/run.ts
    OUT_DIR=. python3 adapter/py/run.py

Reference run: sha256(results.json) =
4720733963b29f9f416c674fea651aa81906a36add2e3884d78fd5b24cc68046

results.json carries no toolchain and no adapter name, so both adapters write it
byte-identically. results-ts.json and results-py.json carry their own toolchain
string and are otherwise identical.

## Boundaries

See SCOPE.md. In short: the pack contains no signatures and no profile-native
validation, so neither is exercised here. The run is against the -00 manifest pin
only.

## Lab operating constraints

These bind the lab and its maintainers, quoted from the lab charter:

> 1. The lab certifies nothing. It issues no conformance verdicts and does not
> present its own outputs as verdicts.

> 2. Each vector records its origin and the draft revision it targets. Each
> published run records who executed it and which implementation and revision
> were tested. It also records whether the run was author-produced or
> independently produced.

Accordingly: this directory is a record of a run, not a verdict. It is not a
conformance verdict on any implementation and not an endorsement of the
composition model. Nothing here asks to be listed anywhere.

The external report files record implementation_revision as the SHA-256 of the
adapter source, which is the convention the pack's own report uses. The git
commit for this directory is recorded at merge.
