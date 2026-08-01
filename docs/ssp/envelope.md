# SSP v1 envelopes

The only SSP families are `ssp.case.v1`, `ssp.advice.v1`, and
`ssp.registry.v1`. Any other `schema` value is unknown and fails closed.

Every envelope is a UTF-8 JSON object of at most 65,536 bytes and 32 nested
containers. Duplicate object members, invalid or unpaired-surrogate Unicode,
non-object roots, floats, unsafe integers, unknown top-level members, and
unknown body members are rejected before use. Signing uses RFC 8785 JCS over
the received envelope after removing only its top-level `signature`; a trailing
file newline is not part of the JSON input.

| Field | Rule |
| --- | --- |
| `schema`, `id`, `emitted_at`, `expires_at`, `routing_epoch`, `registry_revision`, `author_key_id`, `signature_alg`, `body`, `signature` | Required for every family. `signature_alg` is exactly `ed25519`. |
| `case_id`, `registry_hash` | Required for case and advice; forbidden for registry. |
| timestamps | UTC `YYYY-MM-DDTHH:MM:SS(.1-.6)?Z`, calendar-valid years 0001–9999; `emitted_at <= verified_at < expires_at`. |
| `routing_epoch`, `registry_revision` | Safe non-negative integers. |
| `registry_hash` | `sha256:` plus lowercase SHA-256 of the exact accepted registry signing bytes. |

`ssp.registry.v1` is a separately pinned, signed snapshot. Its header
`registry_revision` and `routing_epoch` must equal body `revision` and
`routing_epoch`. Its required `previous_commitment` is JSON `null` only for
the first accepted snapshot; every successor uses canonical lowercase
`sha256:` commitment syntax. The body contains only bounded `domains`,
`principals`, `edges`, and `keys`; the registry validator owns graph uniqueness,
bidirectional links, key validity, and anti-rollback/equivocation checks.
Registry-key records do not self-authorize a registry: verification starts with
the caller-pinned registry key and key ID.

`ssp.case.v1` body requires `domain`, `issuer_edge_id`,
`issuer_edge_generation`, `summary`, and `context_manifest`. A case is valid
only when its enrolled edge, generation, signing edge key, route epoch, and
route family resolve from the accepted registry.

`ssp.advice.v1` body requires `case_commitment` and `text`.
`case_commitment` is the SHA-256 commitment to exactly one already accepted
case signing input with the same case ID, registry pair, and routing epoch. Its
author must resolve to that case route's dispatcher advice key. Advice is
inert display content: no component may interpret it as a command, approval,
session injection, or provider effect.

Postgres is the semantic authority for accepted cases and advice. JetStream is
finite delivery only; it may duplicate, delay, or lose a delivery and never
establishes authority. Stock Buzz is an outbound, disposable projection of
accepted artifacts: its event identity, membership, acknowledgements, and
transport metadata are not SSP authority and are never added to an envelope.
