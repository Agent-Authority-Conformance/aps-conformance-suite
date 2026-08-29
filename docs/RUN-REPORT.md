# Run reports

A run report records that someone ran this corpus, in a stated environment, against a
stated implementation, and what came out. Passes and divergences are both worth filing.

## The path today

In order:

1. Clone this repository.
2. `npm ci --include=dev`. This step needs network access.
3. `npm test`. After dependencies are installed the run makes no network calls. Exit 0
   means every APS-native vector passed. External-system families under
   `fixtures/cross-stack/` are not executed by `npm test`; to report on one of them, run
   the command in its README and paste that output instead.
4. Copy the verbatim output of step 3. Do not summarize it and do not trim it.
5. File it, either way:
   - Open a Run report issue at
     https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/new?template=run-report.yml
     (the form asks for the fields below), or
   - Add a directory `interop/<implementation>-<target>-<pin>/` containing `run-report.md`
     and any script needed to recompute your result, and open a pull request.

There is no command in this repository that generates a report file for you. A generated
report is planned as a follow-up. Until it exists, pasting the verbatim output is the
path, and it is the path the six existing directories under `interop/` used.

## Two run modes

**Mode A, reproduction.** You run this repository's runner in your own environment. The
result records that the corpus reproduces outside the environment it was built in. This is
useful and it is not the same as an independent check, because the code computing the
answer is the same code that produced the published values.

**Mode B, independent recomputation.** Your own implementation recomputes the canonical
bytes, signatures or verdicts from the fixture inputs, and you compare what you observe
against the published values, listing every vector as match or diverge and giving your
observed bytes or verdict wherever it diverges. Mode B is the run the lab exists for.

## Required fields

Both modes report the same fields. Mode A satisfies the per-vector field by pasting the
runner output; Mode B satisfies it with your own per-vector list.

| field | what it means |
|---|---|
| who ran it | your GitHub handle or name |
| date | the date of the run |
| run mode | A reproduction, or B independent recomputation |
| implementation name | what was tested |
| implementation repo and commit or version | enough to fetch exactly what you ran |
| corpus reference | the tag or commit sha of this repository you ran against |
| per-vector result | Mode A: the runner output. Mode B: your per-vector match or diverge list |
| verbatim command and output | the commands you ran and what they printed, uncut |
| environment | language, runtime version, operating system |
| author-produced or independent | independent means you are neither the author of the vectors nor the author of the implementation under test |
| suspected defective vectors | optional, any vector you believe is wrong, and why |

The last field is what makes a divergence actionable. If you think the corpus is at fault
rather than the implementation, say so in that field.

## What a published report means

It means what it records, and nothing else.

The lab certifies nothing and issues no conformance verdicts. A merged report is not an
endorsement of the implementation it names. A divergence is not a verdict against the
implementation: it records that two parties computed different values from the same
inputs, and the corpus can be the party that is wrong. A divergence you can reproduce
opens a dispute on the vector under the lab's constraint 5.

Reports stay attributed. A report records who ran it and whether the run was
author-produced or independent, so a reader can tell the two apart without asking.

## Worked example

`interop/mih-sato-composition-00/` is the most complete report in the corpus today, and it
is a Mode B run. Read it before writing your own. It is spread across five files:

- `README.md`: what was run, the result in two sentences, and the re-run commands.
- `PROVENANCE.md`: the upstream repository, pull request, commit read, merge commit, fetch
  date, the pinned draft revisions with their digests and how they were checked, and an
  explicit Independence section stating the run was not produced by the pack's authors.
- `RESULTS.md`: the tally, the recomputed digests next to the published ones, a two-run
  byte-identity check, and the environment table.
- `VECTOR-INVENTORY.md`: per-file digests for every corpus input.
- `SHA256SUMS.txt`: digests of every file in the directory.

It reports two independent adapters, one TypeScript and one Python, written from the
published bytes rather than from upstream code, and it records that both produce identical
results and that two runs of each are byte-identical.

Two things that report does not carry, which the field table above asks for: a named
person or handle for who ran it, and a corpus reference pinning the revision of this
repository. Include both in yours.

## If the run fails

A failing run is a report, not a problem to fix before filing. Paste the failure verbatim,
name the vector, and file it. If a vector fails where it should pass, or passes where it
should fail, that is the most useful thing you can send.
