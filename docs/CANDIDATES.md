# Candidates

A candidate is test material published in this repository so that other people can examine,
run and challenge it before it has been reviewed for admission. Candidates live under
`candidates/<submitter>-<name>/`. The index at the end of this file lists every candidate.

## What a candidate is and is not

A candidate can be published with whatever evidence its submitter has, including none yet. An
independent reproduction is not required first, because publication is what gives other people
something to reproduce.

A candidate is not a reviewed fixture and is not counted in any corpus total. It may not be
described as admitted to, accepted by, validated by or certified by the lab. Its record below is
the only status it has.

A candidate may use its own protocol's terms. Those terms belong to the submitter and do not
become corpus vocabulary.

## What publication review checks

A maintainer reads each candidate before it is published and checks five things.

1. It is in scope, meaning agent identity, delegated authority, authorization or the evidence
   produced under them.
2. Its source is pinned to a repository and commit or version.
3. It declares a license that allows redistribution under Apache 2.0, and keeps any source
   notices that license requires. The declaration is checked, not the submitter's every right.
4. It contains no credentials, live keys, private personal data or confidential material.
   Contributor names and required attribution are expected.
5. Its stated evidence and limitations are accurate as written.

Publication review does not establish technical correctness or replace admission review. A
reviewer who sees a known contradiction or a misleading claim says so before publishing. A
candidate that fails publication review gets a public reason and, where one exists, a path to
fix it.

## What a candidate pull request contains

A candidate pull request changes only its own `candidates/<submitter>-<name>/` directory and its
row in the index below. A pull request that also changes `package.json`, `scripts/`, `runners/`,
`tests/`, `.github/` or any other path is not a candidate pull request and is reviewed as an
ordinary change.

Lab CI runs only the scripts named in `package.json` and in the workflows. It does not discover or
execute files under `candidates/`. Repository checks may still read them, for example the digest
gate reads any `CHECKSUMS.sha256` file a candidate includes. Verification code is better linked
at its pinned source than copied in.

The directory holds `CANDIDATE.md` and the vectors with their expected results. `CANDIDATE.md`
states the submitter, the normative target and its revision, the source repository and commit,
the license, what the vectors test, how to run them, the evidence available, and known
limitations. The DCO sign-off and license terms in `CONTRIBUTING.md` apply. A passing run does
not.

## The record for each candidate

Three things are recorded separately, because they change independently.

- **Publication.** `published`, `promoted` with a link to the admission pull request, or
  `withdrawn` with the reason.
- **Evidence.** Each run is its own entry: who ran it, against which candidate revision, which
  claims it exercised, Mode A or Mode B, author-produced or independent as defined in
  `CONTRIBUTING.md`, and a link. `none yet` is a valid entry. A run covers only the revision and
  claims it names.
- **Disputes.** Links to open or resolved disputes, or `none`.

Entries are appended. A later run, correction or dispute does not edit an earlier entry, and an
author-produced run does not become independent by being run again elsewhere.

## Index

| candidate | submitter | target | publication | evidence | disputes |
|---|---|---|---|---|---|
| (none yet) | | | | | |
