# Example for one part of OWASP SPVS 2.0 v2.0-V3.10.2

Provisional example, open for review. Passing this example does not establish that a pipeline meets SPVS v2.0-V3.10.2 or any SPVS level.

v2.0-V3.10.2 (Sub-Agent Permission Bounding, L3) asks that sub-agents are technically prevented from operating with permissions beyond those explicitly delegated at invocation. This example tests one part of that. A sub-agent receives limited authority when it is invoked. One enforcement point allows a write inside that authority and refuses eight attempts to write outside it, three of them while the sub-agent also holds a valid standing grant that covers the pipeline file. In a separate invocation that relies on the standing grant, the same pipeline edit is allowed. The test checks the authorization decision and the resource separately, and checks that each refused write never executes.

## What happens

1. A pipeline owner grants the orchestrator `repo:write:*`.
2. At invocation the orchestrator delegates `repo:write:docs:*` to a docs sub-agent.
3. A fixed policy maps each path to the scope a write needs: `docs/README.md` needs `repo:write:docs:readme`, `.github/workflows/ci.yml` needs `repo:write:pipeline:ci`. The scope never comes from the request.
4. Earlier, for other work, the orchestrator gave the same sub-agent a standing grant, `repo:write:docs:*` and `repo:write:pipeline:*`. It is valid under the same trusted root and covers the pipeline file.
5. The orchestrator records which delegation it issued for this invocation. The enforcement point reads that from the invocation, not from the request.
6. The enforcement point verifies the presented chain, checks that the chain's last subject is the calling agent, checks that the chain's last record is the delegation issued for this invocation, looks up the scope for the target path and checks that this delegation covers it. Only then does it call the executor. When a request carries more than one chain, only the one issued for this invocation is evaluated.

| Request | What the sub-agent tries | Decision | File |
|---|---|---|---|
| R1 | Write `docs/README.md` | allow, `ok` | changes from v1 to v2 |
| R2 | Write the pipeline file | deny, `scope_not_covered` | stays v1 |
| R3 | Write the pipeline file while labelling the request with the docs scope | deny, `scope_not_covered` | stays v1 |
| R4 | Present the orchestrator's record alone, which grants `repo:write:*` | deny, `presenter_not_leaf_subject` | stays v1 |
| R5 | Present a root the sub-agent issued to itself | deny, `chain_invalid` with `ROOT_UNTRUSTED` | stays v1 |
| R6 | Write `src/app.js`, a path the policy does not map | deny, `path_unmapped` | stays v1 |
| R7 | Write the pipeline file presenting both the invocation delegation and the standing grant | deny, `scope_not_covered` | stays v1 |
| R7b | As R7, with the two grants presented in reverse order | deny, `scope_not_covered` | stays v1 |
| R8 | Write the pipeline file presenting only the standing grant | deny, `not_invocation_delegation` | stays v1 |
| R9 | In a separate invocation whose delegation is the standing grant, write the pipeline file presenting the standing grant | allow, `ok` | changes from v1 to v2 |

R9 is the positive control for the standing grant. It shows that refusing it in the documentation invocation does not invalidate it everywhere. R9 runs last because it changes the pipeline file.

The run also checks that the standing grant's chain verifies as `valid` and that it covers the pipeline file, so R7, R7b and R8 are refused because of the invocation and not because the standing grant is broken. If either check fails, the run exits 1.

R7, R7b, R8 and R9 follow a reading of question 3 in OWASP/www-project-spvs#37 offered by a participant who is not a maintainer: a sub-agent's permissions for one invocation are those delegated for it, whatever other grants it holds. The maintainers have not confirmed that reading.

For every request the test also checks the exact decision reason, the target file's contents, and that no other file changed and no new file appeared. An allowed request must call the executor once and a refused one must not call it.

## Run

```
npm i agent-passport-system@8.1.1
node spvs_v3_10_2_example.mjs
```

Exit 0 means every expectation held. Each request produces a `decision` line and a separate `effect` line. The effect line is read from the repository contents and the executor's own record of writes. `run-2026-11-26.jsonl` is the output of the current version, run with agent-passport-system 8.1.1.

## Checks that the example can fail

Each of these single changes to the enforcement point or executor was run on 2026-11-19 (UTC), and each run exits 1. The last one was added after review found that the earlier check missed a new file. The requests that catch it are listed. The rows marked 2026-11-26 were run on that date (UTC) against the version with R7 to R9. For those rows the first failing request is listed, since a wrong write also makes later requests fail.

| Change | Caught by |
|---|---|
| Read the orchestrator's record instead of the chain's last record | R1, R2, R3, R6 |
| Skip the scope check | R2 onward |
| Skip the check that the chain's last subject is the caller | R4, R5 |
| Take the scope from the request label | R3, R4, R5 |
| Skip the chain verification result | R5 |
| Trust any root | R5 |
| Match scopes by string equality instead of prefix | R1 |
| Executor writes a different file | R1, R6 |
| Write before checking scope | R1 onward |
| Allow paths the policy does not map | R6 |
| Executor also creates a file it was not asked to write | R1 |
| 2026-11-26: Skip the invocation check, so any valid chain the sub-agent holds is accepted | R8 |
| 2026-11-26: Take coverage from the union of all presented chains | R7 |
| 2026-11-26: Evaluate the last presented chain instead of the one issued for this invocation | R7 |
| 2026-11-26: Evaluate the first presented chain instead of the one issued for this invocation | R7b |
| 2026-11-26: Ignore the invocation a request belongs to and always use the documentation invocation | R9 |
| 2026-11-26: Skip the scope check (rerun on this version) | R2 |

## Limits

- One enforcement point, one process, an in-memory repository. No CI system, runner, token issuer or network is exercised.
- The runner tells the enforcement point who the caller is. Proof that the caller holds the sub-agent's key is not exercised.
- The executor is reachable only through the enforcement point because the example is written that way. Whether a real sub-agent can reach the resource some other way is what a pipeline test of v2.0-V3.10.2 still has to establish.
- The invocation record, like the caller identity, is supplied by the runner. How a real pipeline binds a delegation to one invocation is not exercised.
- Revocation is resolved active throughout. Revocation and expiry are covered by other lab cases.
- The decision and effect pattern does not depend on this SDK. Any chain verifier could take its place inside the enforcement point.
- The lab case `CWA-06` stays the separate case for refusing a child record that widens its parent's scope.

The author of this example also wrote draft-pidlisnyi-aps and the SDK it uses.
