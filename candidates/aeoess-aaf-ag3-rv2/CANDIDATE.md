# Candidate: aeoess-aaf-ag3-rv2

Nine cases for the delegation and revocation requirements of the Accountable Agents Framework
(AAF), run against one implementation. This is a candidate under `docs/CANDIDATES.md`. It is not
a reviewed fixture, it is not an AAF test suite, and it adds nothing to the lab's schema, failure
classes or verifier behavior.

## Submitter

Tymofii Pidlisnyi (Agent Passport System). The submitter also wrote draft-pidlisnyi-aps. Nothing
here uses APS records or code.

## Normative target

Appendix A of "The Accountable Agents Framework (AAF): A Blueprint for AI Agent IDs",
https://www.accountableagents.ai/paper.pdf, fetched 2026-11-26, sha256
`f5c380445421b362373e4d12a5a70c54c3dbe5f1066e23af431f5710e30717f4` (PDF creation date
2026-11-24). The appendix text read for these cases is
https://www.accountableagents.ai/llms-appendix-requirements.txt, fetched 2026-11-26, sha256
`4c1b6d8cf8772b8c29ace0288e45ff93f89c6ea152852258f758aa2f572dfee5`.

Requirements exercised:

- **AG-3 (optional), Delegation.** "The authorizations a sub-agent inherits are no broader than
  those of its delegating agent, and revocation of the delegating agent's registration must
  eventually cascade to its sub-agents (RV-2)."
- **RV-1, Revocation.** A registration or an individual claim can be revoked. Revoking a single
  attested claim, such as an authorization, leaves the agent's registration and other claims
  unaffected.
- **RV-2, Revocation latency.** The directory publishes a revocation latency, the longest time
  after a revocation for which a revoked claim can still verify.

One case is the submitter's reading, not text in the paper. AG-3 states the cascade for
registration revocation. It does not say what happens to authority a sub-agent inherited from
one authorization that is later revoked under RV-1. AG3-03 expects that inherited authority to
end while the parent's registration stays active. That reading is an open question to the
paper's authors.

## Implementation run

- Repository: https://github.com/christortheak/accountable-agents-framework (MIT)
- Commit: `4a5acd5ea8d8af5f277760104e1f5713369a603b` (committed 2026-11-22)
- `run.mjs` imports the implementation's own modules from that checkout and copies none of its
  code.

## License

`run.mjs`, this file and the run record are Apache-2.0, the license of this repository.

## What the cases test

One in-process federation from the implementation (`startFederationInProcess`), one verified
legal-person principal, one counterparty that requires an established ID and an authorization
for `commerce.purchase`.

| case | setup | expected | requirement |
|---|---|---|---|
| AG3-01 | parent holds `commerce.purchase` up to 100 USD, delegates up to 200 USD | refused | AG-3 |
| AG3-02a | parent delegates up to 50 USD, sub-agent buys for 40 USD | allow | AG-3 |
| AG3-02b | same sub-agent buys for 80 USD, within the parent's limit, above its own | deny | AG-3 |
| RV1-01a | principal revokes the parent's authorization, parent buys for 10 USD | deny | RV-1 |
| RV1-01b | after RV1-01a, parent asks the directory for a new ID | ID issued | RV-1 |
| AG3-03 | after RV1-01a, the sub-agent buys for 10 USD under the authorization delegated from the revoked one | deny | AG-3 with RV-1, submitter's reading |
| RV2-00 | second parent and sub-agent, sub-agent buys before any revocation (control) | allow | |
| RV1-02 | principal revokes the second parent's registration, sub-agent asks for a new ID | refused | AG-3, RV-1 |
| RV2-01 | the sub-agent keeps buying with the ID it already used, once a second for up to 45 s | refused within the published bound | RV-2 |

The run also records the directory's published `latency_seconds` from `/v1/practices`.

## Run

```
git clone https://github.com/christortheak/accountable-agents-framework.git aaf
cd aaf && git checkout 4a5acd5ea8d8af5f277760104e1f5713369a603b
mkdir aps-candidates && cp <this directory>/run.mjs aps-candidates/
node aps-candidates/run.mjs
```

Node 22 or later. The implementation has no dependencies to install. One JSON object per line,
exit 0 only if every case passes. The federation uses local ports from offset 9500.

## Evidence

| date (UTC) | runner | revision | claims | mode | relationship | result |
|---|---|---|---|---|---|---|
| 2026-11-26 | Tymofii Pidlisnyi, macOS arm64, Node 24.11.1 | implementation `4a5acd5`, this candidate's first revision | all nine cases | Mode A | author-produced: the runner wrote the cases and `run.mjs`, not the implementation | 9 of 9 pass, [record](runs/run-4a5acd5-2026-11-26.jsonl) |

Published latency in that run: `bound` 300 s, `status_list_refresh` 10 s,
`without_status_check` 300 s. RV2-01 observed a refusal 4 ms after revocation.

## Known limitations

- RV2-01 runs every service in one process. The 4 ms refusal is local behavior. It does not
  establish that the 300 s bound holds for a networked counterparty using cached status
  information, at the boundary of that bound, or on every verification path.
- RV1-01b asks only for an ID. The harness clears the agent's local grant list for that one call,
  because the implementation's `contextFor` also exchanges the agent's first grant, which is the
  revoked one. The directory is not told about grants in that call.
- AG3-03 is the submitter's reading of AG-3 together with RV-1, as stated above.
- One implementation, one principal type, one action, synthetic identities. Nothing here
  establishes conformance to AAF or to any of its requirements.
- No mutation of the implementation was run, so the cases are not yet shown to fail when the
  behavior they check is removed.
