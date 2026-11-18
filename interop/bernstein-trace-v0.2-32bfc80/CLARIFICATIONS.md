# Clarifications

## 2026-11-11, on `run-record/RUN.md`

Requested by the Bernstein maintainer on [discussion #6902](https://github.com/sipyourdrink-ltd/bernstein/discussions/6902). `run-record/RUN.md` is covered by `run-record/SHA256SUMS` and stays unchanged.

1. The "Authorship relationship" section omits one earlier Bernstein contribution by the runner, [`3f8d75a6`](https://github.com/sipyourdrink-ltd/bernstein/commit/3f8d75a629ba355481cc58f44e6d163669c16ea1) (2026-07-25), which changed `tests/fixtures/showback/canonical_vectors.json`. That file is not one of the trust-record files. Its statement vectors exercise the RFC 8785 canonicalizer that the trust-record signing path also calls, and the commit added a case with supplementary-plane property names. The run record's history check covered the vector, generator, emitter and suite paths, which is why it did not appear.
2. The trace-spec pin is `e7e2ecab68cf3534c7d5fcb7e9a6f089fcb7d592`.
