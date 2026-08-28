# Security Policy

This repository follows the LF Decentralized Trust security policy. The authoritative text and the
current reporting route are published at
https://lf-decentralized-trust.github.io/governance/governing-documents/security/

## What a vulnerability means here

This repository publishes test vectors, schemas and verifiers. It is not a deployed service and it
holds no user data, so the reportable classes are narrower than for an application:

- A verifier that reports a pass where the bytes do not match, or otherwise fails open.
- A vector whose recorded canonical bytes or digest are wrong, since an implementation that matches
  them would be wrongly certified.
- A runner or generation script that executes untrusted input, reaches the network where it claims
  not to, or writes outside its working directory.
- A dependency or workflow change that could alter published artifacts without review.

A cross-implementation behaviour difference is not a vulnerability. Open a normal issue for that,
with the verbatim output, as CONTRIBUTING describes.

## Reporting

Report through the route in the LFDT security policy above. If you would rather reach the
maintainer directly first, use signal@aeoess.com, and expect that anything affecting other
implementations will still be routed to LFDT.

Please do not open a public issue for a fail-open verifier defect until it has been triaged, since
the corpus exists to be trusted by parties who are not watching this repository.

## What you can expect

An acknowledgement that the report was received, an attempt to reproduce it before any disposition,
and the reproduction output published with the outcome. Credit on the fix unless you ask otherwise.
