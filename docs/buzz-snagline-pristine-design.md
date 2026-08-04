# Snagline with stock Buzz: pristine design and implementation plan

## Status

This is the target architecture for Snagline's first deployment.

There is no installed Snagline topology to preserve. The first release ships
only the target contracts and state described here; it has no dual-write
machinery and imports no cursor or durable position.

Buzz is an unmodified upstream dependency. Snagline uses stock Buzz only through
its supported client/event APIs. It does not fork, patch, embed, or require an
upstream change to Buzz.

The first product is advice-only. Advice is inert data. Provider effects,
commands, proposals, approvals, receipts, revocations, and remote control are
absent from the runtime and API.

## Decision

There is one semantic authority and two asynchronous projections:

```text
edge / dispatcher
       |
       | mTLS identity + exact signed SSP bytes
       v
snagline-control API
       |
       | one PostgreSQL transaction
       v
PostgreSQL
  registry + cases + final advice + delivery log + audit + outbox
       |                              |
       | delivery outbox worker       | read-only projection query
       v                              v
JetStream                         snagline-buzz-projector
bounded delivery/wake                  |
       |                               | stock HTTPS /events + exact-ID /query
       |                               v
       |                           stock Buzz
       |                        agent collaboration
       |
       | exact SSP bytes + DB delivery sequence
       v
encrypted edge SQLite
       |
       +--> CLI
       +--> AMQ
```

- SSP is the signed semantic contract.
- PostgreSQL is the sole global acceptance, uniqueness, ordering, audit, and
  recovery authority.
- A successful database commit is the remote case or advice commit point.
- JetStream provides bounded at-least-once delivery and fast wake-up. It is not
  an acceptance or completeness authority.
- Edge SQLite owns private local bindings, pending submissions, display state,
  and per-generation delivery progress.
- Buzz is an outbound-only, disposable collaboration projection. No Buzz event,
  membership, channel, cursor, reaction, ACP result, or Nostr signature can
  create or mutate Snagline semantic state.

This split deliberately uses each system for what it already does well.
PostgreSQL linearizes invariants across control replicas. JetStream fans out
committed work. Stock Buzz hosts agent conversation. The edge retains local
machine context that cannot safely become global collaboration data.

## Product flows

### Enroll an edge

1. An operator assigns an opaque `edge_id` and a positive `generation`.
2. The root-signed SSP registry binds that tuple to one principal and SSP key.
3. The edge stores its identity, generation, signing key, and encryption key
   locally.
4. Re-enrollment after local-state loss uses a strictly greater generation.
   Reusing or decreasing a generation fails closed.

The generation fences stale credentials and stale delivery acknowledgements.
Private AMQ (Agent Message Queue, an external operator-pinned agent-messaging
CLI the front process invokes; not a message broker)/session/provider
bindings are not recoverable from PostgreSQL. They
require a local encrypted backup or explicit destructive re-enrollment.

### Open a case

1. The session-bound `snagline-case` adapter reads confidential detail and an
   independently authored public summary from stdin, then combines them with
   its private deployment-pinned socket, case, domain, context-manifest, and
   registry binding. An agent cannot select another case or edge.
2. The edge constructs and signs one `ssp.case.v1` envelope containing its
   `edge_id` and `generation`. Provider/session locators never enter SSP.
3. The edge durably stores the exact signed bytes in its encrypted pending spool
   before the first network attempt.
4. `snagline-control` authenticates the workload, strictly verifies the exact
   received SSP bytes, resolves the current accepted registry head, and checks
   the edge tuple, key, domain, epoch, and expiry.
5. One PostgreSQL transaction inserts the immutable case, audit row, required
   delivery rows, and outbox rows.
6. The API returns an authority commit receipt only after that transaction
   commits. A lost response is retried using the exact same bytes.
7. The delivery worker publishes the committed case to the domain dispatcher
   and edge delivery subjects. Independently, the Buzz projector reads the
   committed fact from PostgreSQL and posts only its explicit public summary to
   the configured official stock-Buzz channel.

### Collaborate and finalize

1. Specialist agents discuss the explicit public case card in stock Buzz.
2. A designated dispatcher invokes Snagline's narrow `FinalizeAdvice`
   operation. Buzz content is input to the agent's reasoning, not to Snagline's
   authority.
3. The dispatcher tool constructs and signs one `ssp.advice.v1` envelope. It
   has no generic signing operation.
4. The control API resolves the exact committed case and the registry snapshot
   bound into that case. The request cannot select a target edge or generation.
5. One PostgreSQL transaction locks the case, accepts exactly one immutable
   final advice, derives the destination from the case, allocates the next
   delivery sequence for that edge generation, and inserts audit and outbox
   rows.
6. The edge receives the exact advice bytes through JetStream or PostgreSQL
   reconciliation, verifies them, commits its delivery evidence and inert local
   projection, then acknowledges transport delivery.
7. The Buzz projector posts a deterministic final-advice reply. Its success or
   failure does not affect the accepted advice.

There is no "finalize from Buzz history" endpoint. A Buzz-native agent may call
the narrow Snagline tool, but the resulting signed SSP advice still passes
through the control API and PostgreSQL transaction.

The deployment uses one shared Buzz community. Every ordinary channel is open;
only two-party DMs are private. This lets agents use non-official channels and
DMs for general conversation while Snagline's official case/advice channels
remain explicitly allowlisted in projector and ACP configuration. Humans are
relay members and may join official channels to steer agents, but the topology
does not create dedicated human-to-human chat channels.

Every agent has a distinct key, a raw kind-0 profile whose event ID and BIP340
signature verify signed `name` and `display_name` metadata that visibly names
its human operator, and a NIP-OA credential signed by that same human. The human
owner is a relay member; the agent authenticates as
itself using the owner-signed tag. Specialist and dispatcher ACP harnesses use
the stock rule fields for exact official-channel kind-9 mentions, plus the
separate global `BUZZ_ACP_RESPOND_TO=allowlist` author gate and exact
human-and-agent pubkey list. Open visibility therefore does not silently widen
who can wake them. The projector has a separate identity, so stock ACP does not
discard its case card as self-authored.
Stock Buzz has no per-identity tool RBAC: only the dispatcher process receives
an MCP command, and an external runtime policy permits only the narrow
`snagline-dispatcher` operation. Channel content itself cannot finalize advice.

## SSP contract

The deployed contract has exactly three families:

- `ssp.registry.v1`
- `ssp.case.v1`
- `ssp.advice.v1`

SSP retains strict received-byte verification, RFC 8785 canonicalization,
Ed25519 signatures, duplicate-key and invalid-Unicode rejection, exact field
sets, bounded depth, and a 64 KiB wire ceiling.

Case body:

```json
{
  "domain": "runtime",
  "issuer_edge_id": "edge-7f3a",
  "issuer_edge_generation": 3,
  "summary": "confidential edge-only detail",
  "public_summary": "bounded intentional audience disclosure",
  "context_manifest": "sha256:..."
}
```

The author key must belong to the exact registered edge tuple, and the domain
must explicitly authorize that edge as an issuer.

Advice body:

```json
{
  "case_commitment": "sha256:...",
  "text": "confidential inert edge-only guidance",
  "public_summary": "bounded intentional audience disclosure"
}
```

Bodies without `public_summary` are invalid. Buzz renders only that
field and never derives a fallback from confidential case `summary` or advice
`text`. Advice carries no target. The control service derives `edge_id`, generation,
domain, routing epoch, registry revision/hash, and case commitment from the
committed case. Every value must match before the advice transaction inserts
anything.

No SSP family contains a Buzz community/channel/key/root/event ID, provider or
session locator, command, effect, or unsigned transport provenance.

## PostgreSQL authority

### Transactional invariants

The database owns these invariants:

1. One accepted registry hash per tenant and revision.
2. A monotonically advancing registry head with retained immutable history.
3. One immutable case meaning per `(tenant_id, case_id)`.
4. One immutable envelope meaning per `(tenant_id, envelope_id)`.
5. Exactly one immutable final advice per `(tenant_id, case_id)`.
6. A positive, contiguous delivery sequence per
   `(tenant_id, edge_id, edge_generation)`.
7. Semantic rows, audit evidence, delivery rows, and outbox work commit
   atomically.
8. Exact replay of accepted bytes returns the original receipt; the same
   semantic ID with a different commitment is a conflict before publication.

No in-memory cache, JetStream de-duplication window, consumer cursor, or Buzz
state participates in these decisions.

### Logical schema

The initial migration contains:

- `tenant_registry_heads`
  - one locked head row per tenant;
  - current revision, commitment, routing epoch, and halted/equivocation state.
- `registry_snapshots`
  - exact root-signed wire bytes and commitment;
  - unique tenant/revision and tenant/commitment;
  - immutable accepted history.
- `cases`
  - exact case wire, envelope ID, case ID, commitment, domain, source edge ID
    and generation, registry coordinates, expiry, and authority sequence;
  - unique tenant/case ID, tenant/envelope ID, and tenant/commitment.
- `final_advice`
  - exact advice wire, envelope ID, commitment, case ID, accepted registry
    coordinates, and authority sequence;
  - unique tenant/case ID, tenant/envelope ID, and tenant/commitment.
- `edge_delivery_heads`
  - next/high-watermark sequence for each tenant/edge/generation tuple.
- `edge_deliveries`
  - immutable contiguous sequence, family, semantic IDs, commitment, and exact
    SSP bytes;
  - unique tuple/sequence and tuple/envelope ID.
- `outbox`
  - immutable destination, headers, payload reference or exact payload,
    attempts, next attempt, lease, and published timestamp;
  - unique deterministic outbox ID.
- `audit_events`
  - immutable authority sequence, authenticated workload, decision, semantic
    IDs, commitment, registry coordinates, and redacted reason.
- `buzz_projection_heads`
  - projector checkpoint only; this is operational projection state, never
    semantic authority.

Raw signed SSP bytes use `bytea`. Commitments and parsed routing columns are
stored together: the bytes remain authorship evidence while indexed columns
support constraints and queries. Database permissions deny update/delete on
immutable semantic tables to runtime roles.

### Admission transactions

Registry admission locks the tenant head. The same revision and commitment is
an idempotent retry. The same revision with another commitment is equivocation
and halts that tenant. A lower revision is rollback. An advance must satisfy
the signed predecessor and routing-epoch rules before the snapshot and new head
commit together.

Case admission verifies outside the transaction, then locks the registry head
and rechecks the verified coordinates inside it. It inserts the case with
unique constraints, allocates authority/delivery sequences, and writes audit
and outbox records. A uniqueness conflict is resolved by reading the existing
row: exact commitment and exact wire are idempotent; anything else is
`semantic_conflict`.

Advice admission locks the case row. It verifies the dispatcher against the
registry snapshot bound to that case, rejects expired or mismatched input, and
inserts into the unique final-advice slot. The destination tuple comes only
from the locked case. Exact retry returns the original receipt; another advice
is `already_finalized`.

Transactions use database constraints as the last line of defense. Serializable
retry handles genuine serialization failures; application mutexes are never a
correctness requirement.

## Control API

`snagline-control` is the stateless HTTPS admission/reconciliation process.
`snagline-delivery` is a separately scalable PostgreSQL-outbox worker. Neither
role embeds Buzz.

Authenticated operations:

```text
POST /v1/registries
POST /v1/cases
POST /v1/advice
GET  /v1/registries/{revision}?commitment=sha256:...
GET  /v1/cases/{case_id}?commitment=sha256:...
GET  /v1/edges/{edge_id}/generations/{generation}/deliveries?after_sequence=N&limit=M
```

Submission bodies are the exact signed SSP JSON, not a wrapper that can override
semantic fields. Tenant and workload identity come from the listener and mTLS
mapping, never request JSON. Reconciliation responses carry exact stored SSP
bytes plus authority metadata outside SSP.

Stable outcomes:

- `200` acceptance or exact idempotent replay, returning the stable receipt;
- `400` malformed or structurally invalid SSP;
- `401/403` unauthenticated or unauthorized workload/key/route;
- `404` unknown operation or unresolved resource;
- `409 semantic_conflict`, `already_finalized`, registry rollback, or
  equivocation;
- `410` expired semantic input;
- `413` request body exceeds the exact SSP body limit;
- `422` valid envelope with a case/registry binding mismatch;
- `503` authority unavailable, with no acceptance claim;
- `504` the authenticated control operation exceeded its deadline.

The commit receipt contains stable authority ID/sequence, envelope ID, and
commitment. It contains no broker coordinate.

## JetStream delivery

One bounded stream is sufficient initially:

```text
snagline.ssp.delivery.v1.<tenant_token>.domain.<domain_token>.case
snagline.ssp.delivery.v1.<tenant_token>.edge.<edge_token>.case
snagline.ssp.delivery.v1.<tenant_token>.edge.<edge_token>.advice
```

Every token is lower-case hexadecimal SHA-256 over length-prefixed UTF-8
components. The edge token commits to both `edge_id` and generation; the
generation is never concatenated ambiguously.

The stream uses file storage and three replicas by default. A one-node test
deployment must explicitly set
`SNAGLINE_DELIVERY_SINGLE_NODE_TEST_STREAM=true`; no other replica count and no
automatic downgrade are accepted. Both modes retain explicit
positive `MaxBytes`, positive `MaxAge`, `DiscardOld`, a 64 KiB SSP payload
ceiling plus bounded headers, and explicit-ack durable consumers. Those limits
are safe because PostgreSQL, not the stream, owns history and completeness.
Carrier `MaxAge` is not semantic expiry. Control admission verifies the signed
`emitted_at <= now < expires_at` interval, and advice admission also rejects a
bound case after that case's signed expiry. Once accepted, an edge delivery is
a historical authority fact: live and reconciled paths re-verify its exact
bytes and signature at the signed emission time rather than treating delivery
time as a new admission. Broker retention can delay or remove a wake-up, but it
cannot extend admission or delete the PostgreSQL authority record.

An outbox worker claims committed rows with a lease, publishes with a
deterministic message ID derived from the immutable outbox ID, and marks the row
published only after `PubAck`. A crash can duplicate a publish; consumers are
idempotent.

An edge delivery includes:

- exact signed SSP bytes as payload;
- a subject containing opaque SHA-256 tokens derived from tenant and
  domain-or-edge-plus-generation routing values;
- exact `Snagline-Outbox-ID` and `Snagline-Fact-Sequence` headers, plus
  `Snagline-Delivery-Sequence` and `Snagline-Edge-Generation` for edge
  deliveries. The semantic commitment is recomputed from the exact payload,
  not accepted from a transport header;
- no provider/session locator.

Broker stream sequence is diagnostic only. An edge advances only the contiguous
database delivery sequence for its own generation.

### Reconciliation

On startup, periodically, after consumer recreation, or whenever it observes a
delivery-sequence gap, an edge calls `GET /v1/edge-deliveries` from its last
contiguous database sequence. The response includes a high watermark and a
complete-through boundary.

The edge verifies and applies each exact SSP payload through the same code path
used for JetStream. It resumes live delivery only after reaching the reported
complete-through value. A wrong generation, inconsistent duplicate, skipped
sequence, or changed commitment halts visibly.

JetStream retention and consumer loss therefore affect latency, not semantic
recovery. Buzz is never a recovery source.

## Edge boundary

`snagline-edge` owns:

- one edge ID/generation and narrowly scoped case signer;
- encrypted exact-byte pending case spool;
- accepted authority receipts;
- encrypted delivery evidence and inert case/advice projection;
- last contiguous database delivery sequence for its generation;
- local provider/session/AMQ bindings;
- a versioned Unix-socket API.

The advice-only local API is:

```text
OpenCase(request) -> pending or accepted_remote receipt
RetryCase(case_id) -> pending or accepted_remote receipt
GetCase(case_id) -> local case state
ListAdvice(case_id) -> accepted inert advice
PresentAdvice(advice_id) -> one accepted inert advice
ClaimFrontDeliveries(front, worker, lease) -> leased durable display work
AckFrontDelivery(receipt) -> durable display outcome
```

The Unix-socket HTTP adapter realizes these as a separate
`GET /v1/advice/{advice_id}` read and `POST /v1/fronts/{front}/claims` plus
`POST /v1/fronts/{front}/acks` delivery flow. Reading advice is not itself a
display receipt.

There is no `Execute`, `Inject`, `Approve`, arbitrary mailbox instruction,
generic signer, or remote-control method.

CLI and AMQ are adapters over the same edge API and durable front outbox. AMQ
root/session/sender/recipient values remain encrypted local adapter data and
never enter SSP, PostgreSQL global semantic records, JetStream subjects, or
Buzz.

## Dispatcher boundary

The dispatcher is a one-shot command/client by default. It accepts a bounded
`FinalizeAdvice` request over a permissioned local boundary, resolves the
committed case, constructs exactly one advice schema, uses a narrow dispatcher
signer, and submits the exact bytes.

It has no general-purpose sign endpoint and cannot choose the advice
destination. An automated agent may host the same narrow tool only when
explicitly deployed with a domain-scoped identity.

## Stock-Buzz adapter

`snagline-buzz-projector` is the only Snagline component that talks to Buzz.
Buzz itself is neither changed nor linked into Snagline's authority path.

The projector:

- polls committed case/advice facts directly from PostgreSQL;
- verifies the exact stored SSP bytes before rendering;
- obtains domain-to-channel mapping within the one shared community from separate operator
  configuration;
- renders a bounded card from only the signed `public_summary`;
- prepares and durably stores the exact stock-Buzz/Nostr event before the first
  publish;
- retries the identical event bytes and records root/reply mappings, lag, and
  poison state;
- parks a projection after its bounded retry budget while retaining the exact
  wire and error, then advances to independent committed facts;
- reconciles its checkpoint from PostgreSQL after loss or broker retention.

Projector state is an AES-GCM-encrypted SQLite blob in a descriptor-validated,
current-user-owned `0700` directory. SQLite runs WAL with `synchronous=FULL`,
which is the shipped Linux crash-durability guarantee. It also requires
`fullfsync=ON` and `checkpoint_fullfsync=ON` as macOS `F_FULLFSYNC` insurance;
those pragmas are functionally inert on Linux but are still checked so the
cross-platform profile cannot silently weaken. The prepared-event and
supersession barriers therefore survive a process crash without exposing SSP
or Nostr bytes in the database or WAL.

The local filesystem boundary trusts the runtime UID. Stock portable SQLite
cannot keep WAL sidecars beside a database opened exclusively through an
already-validated directory descriptor, so a different process with the same
UID could still replace the leaf between validation and SQLite's pathname
open. Production edge and projector processes therefore run under dedicated
service UIDs whose state directories are not writable by model or agent
processes. Supporting hostile same-UID processes would require a
descriptor-aware SQLite VFS and is outside this implementation.

The stock client uses only unmodified Buzz's HTTPS `POST /events` operation and
private, exact-ID `POST /query` reconciliation. It never lists or consumes Buzz
history. Prepared event bytes are accepted for posting only inside a
14-minute client horizon, one minute inside stock Buzz's configured admission
window. Once outside that horizon, Snagline never re-signs or POSTs stale bytes:
it resolves that exact event ID inside its one channel. If the event exists, the
projector records success. If it is absent after expiry, the projector
atomically retains the original event evidence and persists a newly signed
superseding projection event before its first POST. Before expiry, an ambiguous
outcome always retries the identical prepared bytes and never re-signs.

### Pinned stock contract

The supported upstream is unmodified
[`block/buzz` v0.5.2](https://github.com/block/buzz/tree/v0.5.2), source commit
`3e48f1b2365d326ee1c9582448d86a99b44ecd5d`. Snagline neither vendors nor
patches it. A deployment must run an artifact built from that commit and record
the resulting immutable image digest.

The adapter pins this contract:

- kind `9` messages with exactly one canonical UUID `h` channel tag;
- NIP-98 authentication on every HTTP request;
- the exact canonical file-backed NIP-OA credential in `x-auth-tag` on every
  `/events` and `/query` request, cryptographically bound to the projector key;
- `POST /events` returns exactly `event_id`, `accepted`, and `message`;
- reconciliation is only
  `[{"ids":[id],"kinds":[9],"#h":[channel],"limit":2}]`;
- raw HTTP `POST /query` returns complete signed Nostr events; stock Buzz's CLI
  removes `sig` only when it normalizes those events for human-facing reads;
- the projection identity is NIP-OA-managed by a human relay member and every
  mapped official channel is open; Snagline's client exposes only message write and the exact
  channel-scoped query above;
- every specialist/dispatcher ACP identity uses a different NIP-OA-managed key,
  exact stock `name`/`channels`/`kinds`/`require_mention` rules, and a separate
  global human-and-agent respond-to allowlist.

Upgrade requires rerunning the stock contract matrix against the candidate
commit: response shape, NIP-98, NIP-OA, channel-scoped exact-ID query, timestamp
expiry, duplicate/ambiguous outcomes, complete open-channel inventory,
human-steered ACP wake, agent reply, and the narrow dispatcher-tool call.

Stock Buzz cannot server-enforce an exact-ID-only query capability. In the
shared community, every ordinary channel is open, so the dedicated projector
key must be treated as a credential able to read community-visible traffic and
publish events under the projector identity, not merely as a credential for
its configured destination channels. Any direct message visible to that
identity is also inside its compromise radius. The key is isolated from all
specialist and dispatcher keys, and the projector code implements only the
narrow calls above. A deployment that requires server-enforced least privilege
must place an independently attested policy gateway in front of Buzz. Even if
the projector key is compromised, it cannot impersonate other identities and
has no control-write credential, SSP signing key, edge key, provider
credential, authority-side inbound Buzz subscription, backfill-to-SSP path, or
finalization API.

The reproducible external deployment contract and fail-closed evidence gate are
defined in [stock-buzz-deployment.md](stock-buzz-deployment.md) and
`deploy/buzz/`. They pin the upstream commit and image digest, one authenticated relay
community, distinct human and NIP-OA-managed agent identities, open ordinary
channels, DM-only privacy, operator-naming agent profiles, exact official-channel
ACP rules, separate global author allowlists, and the externally enforced
dispatcher-only tool boundary without changing Buzz.

Runtime role templates, backup/restore invariants, operational separation, and
rotation sequencing are in [operations/pristine-runtime.md](operations/pristine-runtime.md)
and `deploy/config/`. They intentionally document current gaps rather than
assuming them away: control and delivery expose operations only on private Unix
sockets, as do edge and projector; there is no public health endpoint. Schema
migration and runtime-role provisioning run only through the explicit one-shot
`snagline-control migrate` operation. Stock Buzz remains externally deployed,
unmodified, and outside both migration and authority recovery.

Deleting the projector database or the entire Buzz deployment loses
collaboration history, not Snagline cases or advice. Rebuilding the projection
from PostgreSQL is optional and does not affect edge delivery.

## Failure semantics

- Control response lost after commit: resend exact bytes; PostgreSQL returns the
  original receipt.
- Edge fails before commit: its encrypted pending spool retries exact bytes; no
  remote acceptance is claimed.
- PostgreSQL unavailable: admission returns unavailable and no commit receipt.
- JetStream unavailable: semantic commits succeed; outbox rows remain pending
  and edges reconcile through the authority API.
- Outbox worker crashes after publish: duplicate delivery is harmless.
- Edge crashes after local commit but before broker ACK: duplicate delivery is
  harmless.
- Edge is offline beyond broker retention: HTTP reconciliation restores the
  complete per-generation delivery log.
- Edge local database is lost: global deliveries are recoverable only for the
  still-valid generation; private local bindings require backup or
  re-enrollment with a greater generation.
- Buzz unavailable: edge delivery continues. The projector retries identical
  prepared bytes while their outcome may be ambiguous; after expiry, an
  authenticated channel-scoped absent result permits a persisted superseding
  event while retaining the original evidence.
- Buzz projection exhausts its retry budget: that disposable projection is
  parked with exact evidence and remains visible as poisoned; the next run
  advances past it so independent facts are not globally blocked.
- Same semantic ID with different commitment: PostgreSQL rejects it before any
  outbox row exists.
- Concurrent finalization: one transaction wins; exact replay is idempotent and
  every different advice loses.
- Registry rollback/equivocation: fail closed; equivocation halts that tenant
  for operator intervention.

## Security and custody

Keep these credentials distinct:

- offline registry root;
- edge SSP key and local data-encryption key;
- dispatcher SSP key;
- control API TLS identity and PostgreSQL role;
- outbox worker PostgreSQL role and NATS publisher credential;
- edge target-scoped NATS consumer credential;
- Buzz projector read-only PostgreSQL role, dedicated Buzz/Nostr key, and
  canonical owner-signed NIP-OA auth-tag file;
- system WebPKI roots for the projector's TLS 1.3 HTTPS connection to the
  stock-Buzz proxy's public DigiCert wildcard certificate. An optional
  absolute, bounded, non-symlink extra-CA PEM may be appended when a deployment
  explicitly requires one; it is not substituted for system trust.

No process receives all credentials. The control API has no SSP private key.
The stock Buzz server has no PostgreSQL or NATS credential. A model process has
no private key and no unrestricted signing primitive.

Every production PostgreSQL caller parses one explicit URL connection plan and
retains it for pool construction. The plan requires hostname-verifying TLS and
an explicit system or absolute deployment-CA trust source on the primary and
every fallback. Every host and port is present in the URL authority; host,
port, and service indirection are rejected. Plaintext, non-verifying,
Unix-socket, mixed, or ambiently completed/reparsed plans fail closed;
Unix-socket authority is outside this release.

Logs, metrics, audit reasons, and Buzz cards are allowlisted and redacted. Exact
signed bytes remain in encrypted or access-controlled stores and are never
logged.

## Repository target

The final product tree converges on:

```text
internal/ssp/
internal/registry/
internal/authority/
internal/delivery/
internal/deliverystream/
internal/sspedge/
internal/edge/
internal/front/cli/
internal/front/amq/
internal/collab/buzz/

cmd/snagline-control/
cmd/snagline-delivery/
cmd/snagline-edge/
cmd/snagline-dispatcher/
cmd/snagline-buzz-projector/
cmd/snagline-ssp-verify/
```

The stock Buzz repository remains a separate upstream dependency with zero
Snagline-owned changes.

Before the first installation, remove every exploratory control-plane,
sidecar, concierge, provider-effect, inbound/cursor, store, and command
prototype that is not part of this design. Test-only scaffolding stays only
where it verifies a shipped boundary; no transition phase or compatibility
package is created.

## Implementation plan

### Slice 1 — signed contract

- keep only registry, case, and advice families;
- require positive edge generation in registry and case;
- maintain strict schemas, hostile-input tests, signed vectors, JCS fixtures,
  commitments, and independent verification.

Exit: contract tests and regenerated-vector verification pass.

### Slice 2 — transactional authority

- add migrations and least-privilege roles;
- implement registry, case, final-advice, delivery-sequence, audit, and outbox
  transactions;
- prove exact idempotency and conflict behavior under concurrent gateways;
- expose typed authority interfaces and commit receipts.

Exit: real-PostgreSQL integration tests prove uniqueness, rollback/equivocation
handling, one final advice, contiguous per-generation delivery, and atomic
outbox/audit behavior.

### Slice 3 — control API and workers

- implement mTLS identity mapping and strict raw-body bounds;
- wire authority transactions to stable HTTP outcomes;
- implement leased outbox publication and PostgreSQL-backed reconciliation;
- add readiness for database, migrations, registry head, and worker lag.

Exit: multi-replica admission and crash-after-commit tests pass.

### Slice 4 — edge

- implement encrypted pending submission and advice spools;
- consume authoritative delivery metadata through JetStream;
- implement gap detection and PostgreSQL reconciliation;
- expose the advice-only Unix-socket API and shared CLI/AMQ front outbox.

Exit: offline-beyond-retention and lost-local-consumer tests rebuild the exact
global delivery state without using Buzz.

### Slice 5 — Buzz projection

- wire the outbound projector source to PostgreSQL facts;
- preserve exact prepared-event retry and deterministic root/reply mapping;
- add stock-Buzz client integration behind the outbound-only interface;
- prove Buzz absence, delay, duplicate ACK, and database rebuild cannot affect
  Snagline acceptance or edge delivery.

Exit: the pinned stock Buzz build receives explicit public case/advice cards; a
separate NIP-OA-managed ACP agent wakes from an allowlisted human or agent,
replies, and can invoke only the narrow dispatcher tool; no inbound authority
path or upstream change exists.

### Slice 6 — packaging and pre-launch cleanup

- package `snagline-control`, edge, dispatcher, and projector roles;
- add scoped configuration, migrations, health, metrics, backups, restore, and
  key-rotation runbooks;
- remove pre-launch prototypes, abandoned plans, and tests that exercise
  behavior outside the architecture being packaged;
- run full unit, race, vet, schema/vector, real PostgreSQL, real NATS, and
  stock-Buzz end-to-end gates;
- obtain exact-tree peer review before commit/push.

Exit: only the pristine architecture builds, tests, packages, and appears in
documentation.

## Non-goals

- No Buzz fork, patch, plugin, embedded server, custom correctness extension, or
  upstream change.
- No JetStream semantic authority or infinite-retention requirement.
- No Buzz inbound ingest, cursor, ACP correctness dependency, or recovery path.
- No provider effect or remote command.
- No Snagline human console, ticket workflow, distributed claim engine, or
  generic agent framework. Humans steer agents through the shared Buzz
  community only.
- No provider/session field in SSP.
- No compatibility layer for an undeployed Snagline topology.
