# SSP v1 signing

SSP signs only the three live families: case, inert advice, and registry.

1. Parse and structurally validate the received JSON before canonicalization.
2. Remove only the top-level `signature` member.
3. Canonicalize the remaining JSON using RFC 8785 JCS.
4. Sign or verify those exact bytes with Ed25519 and canonical unpadded
   base64url signatures.

The signed bytes include every accepted envelope and body field. There is no
unsigned envelope metadata. Buzz, JetStream, AMQ, and Postgres carry their own
metadata outside SSP; none changes a signature,
registry commitment, or authority decision.

`registry_hash` and advice `case_commitment` use `sha256:` followed by
lowercase SHA-256 of the respective signing bytes. A hash is a binding, not a
trust decision: registry verification must use the independently configured
pinned key, and case/advice verification must use the key resolved from that
accepted registry.

Each signed registry body also contains `previous_commitment`: JSON `null` for
the first accepted snapshot, otherwise a canonical lowercase `sha256:`
commitment to its predecessor. Acceptance and chain continuity remain the
authority's responsibility.

The checked-in vectors use deterministic public test keys derived from RFC
8032 test material. They are not production credentials.
