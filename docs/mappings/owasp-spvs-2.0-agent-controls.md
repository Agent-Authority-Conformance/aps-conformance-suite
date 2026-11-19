# Lab cases related to OWASP SPVS 2.0 agent controls

This provisional file lists lab cases that exercise part of nine individual controls in the OWASP Secure Pipeline Verification Standard (SPVS) 2.0, and says what each case leaves untested. The controls were read on 2026-11-18 in the requirements file at [`f092013`](https://github.com/OWASP/www-project-spvs/blob/f0920131ff6ad3580e5861e4b46e92bbc3a81078/2.0/OWASP_SPVS_2.0_-en_Requirements.csv), and the cases are published lab cases at [`aa9c92f`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2).

The nine were selected from the 78 controls tagged `ai-agent` by searching their text for delegation, sub-agents, agent chains, permission ceilings, identity suspension and agent log storage. The other `ai-agent` controls, such as sandboxing, network allowlists and prompt injection handling, were not reviewed here. SPVS gives general assessment guidance in its [usage guide](https://github.com/OWASP/www-project-spvs/blob/f0920131ff6ad3580e5861e4b46e92bbc3a81078/2.0/OWASP_SPVS_How_To_Use_SPVS.md).

This file has no OWASP approval and is not part of SPVS. A case listed here does not establish that a pipeline meets an SPVS control or level. Control identifiers carry the SPVS version prefix, as the SPVS README asks.

The author of this file also wrote draft-pidlisnyi-aps-03 and the SDK these cases use.

## Reading the table

- **Partial.** The case tests a decision rule the control depends on, at a verifier that receives signed records. It does not test that a pipeline enforces the rule.
- **Analog.** The case tests the same kind of rule on a different object, or under a different threat, than the control names.
- **Gap.** No inspected case tests a rule the control depends on. Related cases may be listed, with what they do not show.

Case status:

- **Conformance (aps-03)** cases target a rule in draft-pidlisnyi-aps-03 and run in lab CI. Conformance here means conformance to that draft, not to SPVS.
- **Candidate** cases target proposed text named in the case sources.
- **Published candidate** cases are published under `candidates/` and have not been admitted as reviewed fixtures. They do not run in lab CI.

These cases check signed records at a verifier. They do not test a running pipeline, an agent runtime or its isolation. A pipeline claiming one of these controls still needs a test of the system that enforces it, one that shows an out of scope operation never takes effect. [`owasp-spvs-2.0/`](owasp-spvs-2.0/) holds one runnable example of that kind for part of v2.0-V3.10.2, with its own limits.

## Controls

| SPVS control | Rating | Cases and limits | Status |
|---|---|---|---|
| v2.0-V3.10.2 Sub-Agent Permission Bounding (L3). Sub-agents cannot operate with permissions beyond those explicitly delegated at invocation. | Partial | [single-chain selection][scs], cross-check path of `SCS-03`, `SCS-04`, `SCS-05`. A child record that adds a scope or amount beyond its parent, correctly signed with the leaf agent's own key, fails chain verification as `SCOPE_WIDENING` or `SPEND_WIDENING` at index 1. A verifier applying this rule does not accept a wider grant that a sub-agent signs for itself. The case does not test whether a running sub-agent could bypass the verifier. The main path of these cases tests a different point. The agent holds two chains, the action needs scopes or budget from both, and the one presented chain is refused with `scope_not_covered` or `PER_ACTION_EXCEEDED`. | Conformance (aps-03) |
| v2.0-V3.10.2 | Partial | [conferral without authority][cwa] `CWA-06`. The conferral is authorized, but the child's scope adds `payments:refund`, which the parent never granted. The chain is `invalid`, `SCOPE_WIDENING` at index 1. | Candidate |
| v2.0-V3.10.2 | Partial | [subdelegation edges][sde] `LC-H-007-c`, `LC-H-007-d`, `LC-H-007-e`. These bound a child's validity period, not its scope. A child valid longer than its parent fails verification with `TIME_WIDENING` at index 1 (-c, -d), and issuance of such a child is refused (-e). In -c every record's own validity period includes the verification instant, so a check of each record alone would admit it. This row reads the validity period as part of the delegated permission. SPVS does not say so. | Candidate |
| v2.0-V3.10.2 | Partial | [AAE vectors][aae] `aae-vector-07`, `aae-vector-08`. The vectors expect a delegated envelope to be rejected when it adds an action its parent lacks (`delegated_actions_not_subset`) or raises its parent's value cap (`delegated_constraint_relaxed`). No implementation is run against these vectors in lab CI. | Published candidate |
| v2.0-V5.6.4 Agent Permission Ceiling Enforcement (L3). The maximum scope of any agent or chain is enforced and cannot be expanded through agent-initiated requests. | Partial | [chain selection with no union][csnu] `CSNU-06`, `CSNU-07`, `CSNU-08`. An agent holding two independently rooted chains cannot have an action admitted on grants or budgets spread across them. Each vector records that a verifier pooling the chains would admit what the single selected chain refuses. The ceiling here is the selected chain's own authority. A platform-wide ceiling, and an agent request that tries to change a recorded ceiling, are not tested. | Candidate |
| v2.0-V3.2.6 Prohibition of Agent-Created Identities and Privilege Escalation (L3). Agents cannot create identities, register NHIs or spawn processes with permission scopes beyond those of the invoking agent. | Analog | [single-chain selection][scs], the cross-check path of `SCS-03` to `SCS-05` as in the first row, and [subdelegation edges][sde] `LC-H-008-b`, `LC-H-008-c`, `LC-H-008-d`, where a delegation past the chain's declared maximum depth fails as `DEPTH_EXHAUSTED` at verification (-b, -d) or at issuance (-c). These exercise delegation records. They do not show what permissions a spawned process receives. A depth limit bounds how far delegation continues. It does not compare a child's scope with the invoking agent's. Identity creation and NHI registration are not tested. | Conformance (aps-03), Candidate |
| v2.0-V3.10.4 Agent Chain Blast Radius Bounding (L3). Compromise of one agent cannot grant full orchestrator permission scope. | Analog | [single-chain selection][scs], cross-check path of `SCS-03` to `SCS-05`. A wider child record signed with a sub-agent's key is refused, so that key alone does not produce a valid chain carrying more than the sub-agent's own delegation. The cases do not model a compromise. Stolen credentials of a higher agent, a sub-agent presenting its parent's record as its own, and isolation are not tested. | Conformance (aps-03) |
| v2.0-V5.9.2 Agent Identity Suspension and Credential Rotation (L2). Response procedures can suspend agent identities and rotate credentials without full pipeline shutdown. | Gap | Related cases only. [Ancestor revocation][arc] `AAC-02`, `AAC-03`, `AAC-04`, with `AAC-01` as the active control. A revoked ancestor fails the chain in each case, `REVOKED` at the ancestor's index. The SDK treats a recorded revocation as irreversible, so it cannot stand in for suspension and resumption. [Chain selection with no union][csnu] `CSNU-10`. A revoked selected chain is refused, and the verifier does not fall back to the agent's other chain. [Key rotation][krh] `KRH-03` rejects a record dated after rotation and signed with the earlier key, and `KRH-04` rejects a record dated before rotation and signed with the later key. `KRH-01` and `KRH-02` accept the key authorized at each time, and `KRH-05` is `indeterminate` when the timing evidence is missing. Reversible suspension, rolling out the new credential and continued operation of unaffected work are not tested. | Conformance (aps-03), Candidate |

## Controls not tested by the cases reviewed here

The inspected cases do not test these requirements:

- v2.0-V3.10.1 Explicit Orchestrator to Sub-Agent Trust Policy, a policy document requirement.
- v2.0-V3.10.3 Trust Boundary Approval in Multi-Agent Workflows, approval at each repository or environment boundary crossing.
- v2.0-V5.5.4 Tamper-Evident Agent Log Storage and v2.0-V5.5.5 Inter-Agent Communication Logging. The lab tests records a verifier receives, not how a pipeline stores its logs.

Corrections from the SPVS maintainers or anyone running these cases against a pipeline are welcome as issues or pull requests on this file.

[scs]: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2/fixtures/single-chain-selection/README.md
[cwa]: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2/fixtures/lifecycle-conferral-without-authority/README.md
[sde]: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2/fixtures/lifecycle-subdelegation-edges/README.md
[aae]: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2/candidates/moltycel-aae-vectors/CANDIDATE.md
[csnu]: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2/fixtures/chain-selection-no-union/README.md
[arc]: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2/fixtures/ancestor-revocation-chain/README.md
[krh]: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/aa9c92fad73383f9247f0f22a1b7a0b8c5cf0ca2/fixtures/key-rotation-historical/README.md
