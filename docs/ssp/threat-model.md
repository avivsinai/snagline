# SSP v1 threat model

SSP authenticates three bounded artifacts: cases, inert advice, and registry
snapshots. Postgres is semantic authority. JetStream is finite delivery only;
Buzz is a stock, outbound, disposable projection. Neither can create a case,
accept advice, authorize a key, or cause an effect.

| Threat | Required control |
| --- | --- |
| Spoofed author or registry | Ed25519 over JCS; registry starts from an independently pinned key; case/advice keys resolve only from the accepted snapshot. |
| Tampering or parser ambiguity | UTF-8, duplicate-key, Unicode, depth, size, integer, strict-member, timestamp, JCS, and signature checks before acceptance. |
| Replay or stale delivery | Expiry plus Postgres acceptance/deduplication. JetStream and Buzz delivery order is not semantic evidence. |
| Wrong route or stale edge | Exact registry pair, epoch, route family, edge principal, and positive generation matching. |
| Advice becomes an action | Advice is inert display data. No component may translate it into a provider action. |
| Transport metadata is trusted | Do not use Buzz membership, event IDs, ACKs, channels, or JetStream sequence/consumer state as identity or authority. |
| Data disclosure | Require a separately authored `public_summary`; project only that exact field, never confidential case `summary` or advice `text`; keep restricted provider/session data outside SSP and projections. |
| Local state replacement | Run each edge and projector under a dedicated service UID. Their current-user-owned `0700` SQLite namespaces assume other same-UID processes are trusted. |

An inbound delivery that cannot be authenticated and bound to current Postgres
state is rejected or recorded only as a safe local diagnostic. A successful
Buzz post or JetStream acknowledgement proves delivery activity at most, never
semantic acceptance or a provider-side result.
