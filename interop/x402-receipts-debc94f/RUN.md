# x402-receipts vector reproduction at pinned debc94f

## Purpose

Reproduction of the seven conformance vectors published by StelarDigital/x402-receipts,
their pinned envelopeDigest values, and the five negative vectors, at pinned SHA
debc94f39dfa9f62855c4602c1baafc9d61f4642.

## Environment

- macOS 26.5, arm64
- Node v24.11.1 (`node --version` output: `v24.11.1`)
- npm 11.6.2 (`npm --version` output: `11.6.2`)
- Python 3.14.6 (`python3 --version` output: `Python 3.14.6`), standard library only
- x402-receipts 0.5.1, dependencies restored with `npm ci` from the pinned checkout
- vitest 4.1.10, resolved by the checkout's own package-lock.json

## Commands

    $ rm -rf /tmp/x402-receipts-repro
    $ git clone https://github.com/StelarDigital/x402-receipts.git /tmp/x402-receipts-repro
    $ git -C /tmp/x402-receipts-repro checkout debc94f39dfa9f62855c4602c1baafc9d61f4642
    $ git -C /tmp/x402-receipts-repro rev-parse HEAD
    debc94f39dfa9f62855c4602c1baafc9d61f4642

    $ cd /tmp/x402-receipts-repro
    $ npm ci
    exit=0

    $ npm test > /tmp/x402-receipts-repro/test-output.log 2>&1; echo "exit=$?"
    exit=0

    $ npm run build
    exit=0

    $ node -e "import('/tmp/x402-receipts-repro/dist/receipt.js')..."   # envelopeDigest per vector
    exit=0

    $ python3 recompute.py /tmp/x402-receipts-repro > recompute-output.log 2>&1; echo "exit=$?"
    exit=0

`npm run build` is the checkout's own documented build step and is needed only so the
repository's exported `envelopeDigest` can be called from outside its test runner. The
standard-library recomputation does not use it.

## Result

Exit code of the documented test command: 0

The tally lines, verbatim from test-output.log:

     Test Files  15 passed (15)
          Tests  213 passed (213)

Per-vector digests. The pinned column is the value published in the checkout; the repo-code
column is the checkout's own exported `envelopeDigest(vector.receipt)`; the stdlib column is
recompute.py, which imports no repository code.

    vector file                                  pinned digest source        repo-code digest                                                    stdlib digest                                                       identical
    vectors/neg-countersig-not-payer.json        VECTORS.md + vectors.test.ts 05264696dd2c53536b2b1d70ec03fcd9bf539984ba49127d5a4c67964bd73155    05264696dd2c53536b2b1d70ec03fcd9bf539984ba49127d5a4c67964bd73155    yes
    vectors/neg-delivered-not-settled.json       VECTORS.md + vectors.test.ts cef6d26c5eef38bb403942ec5cc95bed6a22976bda19e2a0fec746a23f2d1db7    cef6d26c5eef38bb403942ec5cc95bed6a22976bda19e2a0fec746a23f2d1db7    yes
    vectors/neg-funded-not-delivered.json        VECTORS.md + vectors.test.ts 4fb1ec3149cc40cb503752418a71258f4f55d7a29478075a9f06f9bd36650e33    4fb1ec3149cc40cb503752418a71258f4f55d7a29478075a9f06f9bd36650e33    yes
    vectors/neg-leaf-not-in-anchored-root.json   VECTORS.md + vectors.test.ts e420aac6cbffef025e463af9c7bd10538dd01c5044aa2b80b7897ea48566e806    e420aac6cbffef025e463af9c7bd10538dd01c5044aa2b80b7897ea48566e806    yes
    vectors/neg-settled-to-expected-solver-mismatch.json VECTORS.md + vectors.test.ts 20646a53e788ca9a51fca1ec52e84fb4525bef210b2c177da71b55ff9beaa7e9 20646a53e788ca9a51fca1ec52e84fb4525bef210b2c177da71b55ff9beaa7e9 yes
    vectors/pass-countersigned-anchored.json     VECTORS.md + vectors.test.ts d9a835dfba19cb6da87f390a85ade40202f1281d9a2a2179ab2f0fc3841770bb    d9a835dfba19cb6da87f390a85ade40202f1281d9a2a2179ab2f0fc3841770bb    yes
    vectors/pass-settled-delivered.json          VECTORS.md + vectors.test.ts b287e7addc8f0a06754a39f13a88fdd7e14b8b856a799288ba5ba0c7b526d991    b287e7addc8f0a06754a39f13a88fdd7e14b8b856a799288ba5ba0c7b526d991    yes

Seven vectors, seven identical by the repository's own code, seven identical by the
standard-library recomputation. The checkout's `receiptDigest` alias was called alongside
`envelopeDigest` on every vector and returned the same value in all seven cases.

The five negative vectors through the checkout's own verifier, with each error string
verbatim as the verifier returned it:

    neg-countersig-not-payer
      verifyReceipt.valid      = false
      verifyReceipt.errors     = ["buyer countersignature invalid"]
      deliveryStatusOk         = true
      verifySettlement.settled = true, errors []

    neg-delivered-not-settled
      verifyReceipt.valid      = true, errors []
      deliveryStatusOk         = true
      verifySettlement.settled = false
      verifySettlement.errors  = ["transaction did not succeed on-chain (status: reverted)",
                                  "no ERC-20 Transfer log for the receipt's asset contract in this transaction"]

    neg-funded-not-delivered
      verifyReceipt.valid      = false
      verifyReceipt.errors     = ["goods present but delivery.status is \"failed\" (not \"delivered\"): cannot verify as a successful delivery"]
      deliveryStatusOk         = false
      verifySettlement.settled = true, errors []

    neg-leaf-not-in-anchored-root
      verifyReceipt.valid      = true, errors []
      deliveryStatusOk         = true
      verifySettlement.settled = true, errors []
      verifyInclusion(anchoredLeaf, proof, root)      = false
      verifyInclusion(decoyLeaf,    proof, root)      = true
      verifyAnchored(preAnchor(receipt), proof, root) = false

    neg-settled-to-expected-solver-mismatch
      verifyReceipt.valid      = true, errors []
      deliveryStatusOk         = true
      verifySettlement.settled = false
      verifySettlement.errors  = ["ERC-20 Transfer log(s) found but none match the receipt: e.g. on-chain from=0xe61Bd34fcEdF14E0b41B582166eed69E3a6deF89 to=0x0000000000000000000000000000000000baDbad value=5000, receipt expects payer=0xe61Bd34fcEdF14E0b41B582166eed69E3a6deF89 payee=0x32d711C66dD1AD0c42D0cFe48e58ee5f2dE7c243 amount=5000"]

Each negative fails the one predicate its own `predicate` field names and passes the
others. Settlement checks run against each vector's own `mockOnChain` block, assembled into
a SettlementClient the way the checkout's test/vectors.test.ts assembles it. No chain was
queried and no remote service was called.

The anchoredLeaf comparison on both anchored vectors, under the pre-anchor rule stated in
the checkout's SPEC.md section 8 (the merkle leaf is envelopeDigest over the receipt with
`anchor` set to null):

    neg-leaf-not-in-anchored-root
      pinned anchoredLeaf                = 58b16b0099ce9cd885d71a02f4bd3335a68f90467f1ca5a5fb16c9f7b0eec212
      envelopeDigest(preAnchor(receipt)) = 58b16b0099ce9cd885d71a02f4bd3335a68f90467f1ca5a5fb16c9f7b0eec212
      identical                          = true

    pass-countersigned-anchored
      pinned anchoredLeaf                = 58b16b0099ce9cd885d71a02f4bd3335a68f90467f1ca5a5fb16c9f7b0eec212
      envelopeDigest(preAnchor(receipt)) = 58b16b0099ce9cd885d71a02f4bd3335a68f90467f1ca5a5fb16c9f7b0eec212
      identical                          = true

Qualification 1. No vector file carries an envelopeDigest field. The expected digests are
published in vectors/VECTORS.md, in a table headed "Digest table", and transcribed into a
DIGESTS map in test/vectors.test.ts. Both were read at the pinned SHA and they agree on all
seven entries. The digest-bearing keys inside the vector files are anchoredLeaf and
decoyLeaf, which are merkle leaves rather than the envelope digest of the receipt as given.

Qualification 2. The corpus value domain, measured by recompute.py and recorded in
recompute-output.log, is 52 objects, 0 arrays, 133 strings, 24 integers, 11 nulls, 0
booleans, with 0 non-ASCII keys, 0 non-ASCII string values, 0 control characters, 0
non-integer numbers and 0 astral-plane keys. The JCS rules exercised are member ordering by
UTF-16 code unit (RFC 8785 section 3.2.3), the ECMAScript Number::toString rule (section
3.2.2.3) on integers, string encoding with mandatory escapes only, separators with no
whitespace, and UTF-8 output encoding. The rules NOT exercised, and about which this run is
no evidence, are non-BMP key ordering, float serialization, control-character escaping,
non-ASCII passthrough, and array serialization inside the envelope. recompute.py raises
NotImplementedError on a non-integer number rather than approximating the float rule.

## Scope

This artifact records that the seven vectors published by StelarDigital/x402-receipts at the pinned SHA reproduce, by the repository's own code and by an independent standard-library recomputation, in an environment outside that repository's CI, and that its five negative vectors fail the predicate each one pins. It makes no statement about APS and grades no APS artifact. The corpus exercises ASCII string and integer inputs only, so this artifact claims reproduction of the pinned corpus and its negative cases and makes no claim of general RFC 8785 interoperability. Case definitions are the repository's own, referenced by path at the pinned SHA and not quoted here.

The SPEC.md version string read at the pinned SHA is v0.5.1.
