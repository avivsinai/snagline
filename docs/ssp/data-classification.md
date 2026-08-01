# SSP v1 data classification

| Class | Examples | Rule |
| --- | --- | --- |
| Public contract | schemas, synthetic vectors, algorithms, public test keys | Publish only synthetic material. |
| Operational metadata | envelope IDs, key IDs, registry pair, route IDs, commitments | Signed or stored as needed; transport placement proves nothing. |
| Intentional audience disclosure | case/advice `public_summary` | The signed author chooses this bounded text for outbound Buzz projection; never derive it automatically from confidential content. |
| Confidential support content | case `summary`, advice `text`, local context-manifest description | Retain inside Snagline and at the owning edge; never project these fields to Buzz. |
| Restricted data | prompts, transcripts, locators, session IDs, credentials, tokens, private keys, provider responses | Keep only at the owning boundary; never put it in SSP, vectors, logs, JetStream, or Buzz. |

Case `issuer_edge_id` and generation are opaque enrolled identifiers, never a
hostname, filesystem path, account, locator, or provider handle.
`context_manifest` and `case_commitment` are commitments, not carriers for
their plaintext. Confidential advice `text` is human-readable, bounded, and
inert. Both case and advice require an independently authored `public_summary`;
the old bodies without it are invalid.

Postgres retains semantic acceptance state under its own access and retention
controls. JetStream carries finite deliveries, not authoritative history.
Buzz is a disposable outbound projection; recipients must treat publication as
an intentional audience disclosure but never as a grant of authority.

Do not encode commands, approval decisions, effect claims, raw provider data,
URLs with credentials, or transport identifiers into opaque SSP fields. If a
case needs protected context, retain it at the owning edge. Buzz may receive
only the explicit `public_summary`, never a fallback, truncation, or transform
of case `summary` or advice `text`.
