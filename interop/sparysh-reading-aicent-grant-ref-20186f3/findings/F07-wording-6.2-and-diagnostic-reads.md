# F07 — Wording: 6.2 "authority_revoked or evidence_expired", and "the only observation available"

To: the author of draft-li-rttp-iqa-addressing-02
Cases: GR-P03/P04 (B05/B03), GR-N04 (B18). Draft only; not filed. No verdict depends on either point.

1. 6.2: "the next verification answers authority_revoked or evidence_expired (Section 8.1)". Read alone, "or" could suggest a free choice. This run's reading applied 8.1's priority, under which `evidence_expired` comes first when both apply. Adding "in the priority order of Section 8.1" would close this.

2. 8.1 `authority_not_determined` applies when "the only observation available predates the request". 8.2 says a "later, successful observation" may be "available at answer time" and that "diagnostic reads do not participate in authorisation". When a diagnostic read is available, "the only observation available" is literally false. This run's reading applied 8.2's exclusion. Wording such as "the only observation that participates in authorisation" would align the two.
