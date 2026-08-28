# Maintainers

This file follows the LF Decentralized Trust MAINTAINERS file requirements:
https://lf-decentralized-trust.github.io/governance/governing-documents/MAINTAINERS-file/

This repository is a lab repository. Labs sit outside the LFDT project lifecycle, so the
requirements below are adopted voluntarily rather than as an obligation of project status. They are
adopted because the reason for hosting this corpus in a neutral venue is that a reader should be
able to check who decides what, without asking anyone.

## Maintainer scopes and GitHub roles

| Scope | Definition | GitHub Role | GitHub Team |
| --- | --- | --- | --- |
| Maintainer | The GitHub Maintain role | Maintain | `aps-maintainers` |

## Active maintainers

| Name | GitHub ID | Scope | LFID | Discord ID | Email | Company Affiliation |
| --- | --- | --- | --- | --- | --- | --- |
| Tymofii Pidlisnyi | aeoess | Maintainer | | | signal@aeoess.com | None (independent) |

## Emeritus maintainers

| Name | GitHub ID | Scope | LFID | Discord ID | Email | Company Affiliation |
| --- | --- | --- | --- | --- | --- | --- |
| | | | | | | |

## A standing disclosure

There is one active maintainer, and that maintainer is also the author of the specification this
corpus tests. That is a conflict of interest and it is stated here rather than left to be inferred.

The approved lab proposal constrains it in two ways that a reader can check. A maintainer decision
is not described as peer agreement or as consensus because it was merged. And the shared review
requirement, under which removing a vector's disputed status or publishing an aggregate result
summary needs review by a committer other than the author of that change, begins when the
repository has at least two committers who have accepted ongoing maintenance responsibility. It
does not bind today, and this file does not pretend otherwise.

## Maintainer duties

- Review and merge pull requests against the corpus, its runners and its report tooling.
- Reproduce reported divergences before disposing of them, and publish the output.
- Record a disputed vector when a public issue identifies a reproducible divergence or a conflict
  with the pinned draft revision, and keep it disputed until the issue resolves on public technical
  evidence or on clarification of the specification.
- Keep releases and reports free of promotion of any implementation, reference or commercial.
- Answer contributions in public, with a reason and, where one exists, a path.

## How to become a maintainer

Committer access follows the criteria in the approved lab proposal. In summary, a candidate needs:

- a public record of substantive merged contributions to the corpus, or to its runners and report
  tooling, across more than one release or equivalent maintenance cycle;
- demonstrated adherence to the provenance rules, to the dispute handling above, and to the rule
  against preferential treatment;
- explicit acceptance of ongoing maintenance responsibility, recorded in the repository before
  access is granted.

Proposals are made by opening a pull request against this file that sets out how the candidate
meets those criteria. Decisions to grant or deny access are recorded publicly against them. Meeting
the criteria does not create an automatic seat. Running the corpus and publishing results is
welcome from anyone and does not by itself confer committer access.

An emeritus maintainer returns to active status by the same route.

## How maintainers are removed or moved to emeritus

A maintainer moves to emeritus at their own request, or after a sustained period without
maintenance activity, or where the duties above are not being met. Removal is proposed the same way
it is granted, by a pull request against this file stating the reason. The corresponding GitHub team
membership is updated manually once the pull request merges.
