# action-ref-v1 recomputation negatives, revision 2

Revision 2 of `../vectors.json`. Target: argentum-core `docs/spec/action-ref.md` at `main`
96931c9, where `agent_id`, `action_type` and `scope` are ASCII only and `scope` is non-empty. The
2026-08-25 erratum gives the same scope reading for the tag `action-ref-v1.0`. Why the revision
exists is in `../CLARIFICATIONS.md`.

| Section | Vectors | What it holds |
|---------|---------|---------------|
| `positive_fixture` | 3 | 0001-basic, 0004-ms-floor, 0005-ms-ceiling, unchanged from revision 1 |
| `negative_fixture` | 9 | the revision 1 drift negatives, unchanged |
| `domain_negative_fixture` | 2 | `dom-0002-unicode-fields` and `dom-0003-empty-scope`, rejected before any digest |

## Run

```
node run.mjs
```

Exit 0 when every positive is `MATCH` on both paths, every drift negative fails closed at its
declared stage, both domain negatives are rejected at the domain gate by the stdlib path and by
the SDK throwing, and the run matches `results.json`. The SDK path needs
`agent-passport-system` 8.0.0 or later, which the repository pins at 8.0.1.

The vectors and both recomputation paths are by this lab's maintainer, so a run here is
author-produced, as for revision 1 (`docs/OPEN-RUNS.md`).
