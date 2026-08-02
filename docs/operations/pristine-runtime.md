# Pristine runtime operations

This runbook applies to the first Snagline deployment only. No existing
Snagline installation, state migration, Buzz history import, or legacy runtime
is supported. PostgreSQL is the sole semantic authority. JetStream is bounded
delivery acceleration, edge SQLite is a private encrypted projection, and
stock Buzz is an unmodified disposable outbound collaboration projection.

This repository does not deploy an environment. A successful local build or
static Buzz gate is not deployment acceptance.

## Preflight and role separation

Start from [the secret-free templates](../../deploy/config/README.md). Create
one dedicated Unix UID for every role and a distinct `0700` state directory for
every edge and for the projector. Mount private key, SQLite-key, NATS credential,
and descriptor files to the owning UID only. Do not share an edge UID with an
agent runtime; the only same-UID helper is the shipped, bounded
`snagline-front` process that must traverse the edge's private socket
directory. Do not share a dispatcher UID with a Buzz specialist.

Container targets are packaging artifacts, not production identity
definitions. The image-default `nonroot` user prevents root execution but does
not satisfy this separation. Configure and verify a distinct numeric runtime
UID for every deployed control, delivery, edge generation, dispatcher, and
projector, with exclusive mounts and socket directories. `snagline-front` has
no container target: run the release binary on the edge host under the matching
edge UID so AMQ (Agent Message Queue, an external operator-pinned
agent-messaging CLI the front process invokes; not a message broker) mode can
execute the operator-pinned host AMQ binary.
Release container targets are attached to the single draft-then-publish GitHub
release as loadable `*.docker.tar` assets. They are built and run before the
release becomes visible; Snagline does not publish partially complete GHCR tag
sets.

Provisioning is performed by platform/DB/PKI owners:

1. Create PostgreSQL, its TLS trust, and separate runtime identities. Every
   Snagline DSN must be an explicit PostgreSQL URL with
   every host and port named in its authority, `sslmode=verify-full`, and
   either `sslrootcert=system` for the intended host trust store or an absolute
   clean path to the deployment CA. Host, port, or service query indirection is
   forbidden. The runtime rejects Unix sockets, mixed fallbacks, and any plaintext or
   non-hostname-verifying connection plan. Do not use a superuser or
   schema-owner DSN for any runtime role.
2. Create mTLS identities. Map only exact certificate SANs to the intended
   edge tuple or dispatcher/registry-publisher principal in control config.
3. Create NATS identities scoped to the required JetStream publish/consume
   subjects; use TLS and a private NATS credentials file.
4. Create offline registry-root custody and distinct edge, dispatcher, and
   Buzz Nostr keys. No model or Buzz process receives an SSP signing key.
5. Provision the external stock Buzz deployment according to
   [the stock-Buzz deployment gate](../stock-buzz-deployment.md). It remains
   unmodified and receives no PostgreSQL, NATS, edge, or control credential.
   Put its HTTP bridge behind the approved TLS 1.3 proxy. The production
   DigiCert wildcard certificate is validated with system WebPKI roots, so
   omit `buzz_tls_ca_file`; an absolute, securely loaded extra CA file remains
   available only for deployments that explicitly require one.

Edge and dispatcher projection files use the pinned SQLCipher 4.14.0 community
driver with OpenSSL. The supplied 32-byte root key is separated by HKDF into a
database key and a distinct field-AEAD key. The complete database file,
including schema and routing metadata, is encrypted; rollback journaling uses
`DELETE`, temporary storage is memory-only, and WAL/SHM files are not used.
Opening with a wrong key, an unkeyed ordinary SQLite client, a non-SQLCipher
driver, or a different SQLCipher build fails closed.

The SQLite driver must reopen a pathname after Snagline validates its file
descriptor. The `0700` directory prevents a different unprivileged UID from
replacing that path during the handoff; root and the same service UID remain
able to do so. This is why a dedicated edge-generation/dispatcher UID with no
co-hosted untrusted process is a security requirement, not hygiene: that same
UID can already read the `0600` root key. The runtime retains only the derived
database subkey in a mutable connector for reconnection, never the root key or
field subkey in an immutable database/sql DSN; per-connection key DSNs are
stripped by the driver before SQLite retains its URI and the connector key is
cleared on close.

Source builds require Go 1.26, CGO, `pkg-config`, OpenSSL headers, and
`libcrypto` for `snagline-edge` and `snagline-dispatcher`. The pristine release
matrix deliberately supports one exact target, Linux amd64. Its separate edge
archive dynamically requires the platform's OpenSSL 3 `libcrypto`; the other
commands remain CGO-free and are packaged separately. Only the edge and
dispatcher container targets use the SSL-bearing distroless Debian base.
Expanding the release matrix requires a native runner and the same archive and
loader gates for every new target; do not redistribute an ad hoc binary.

Migration and role provisioning are deliberately separate from runtime:
`snagline-control migrate` takes an owner-level migrator DSN, applies the
embedded schema migration, and provisions the three named NOLOGIN authority
roles. It does not create login credentials. Runtime login principals are
external provisioned identities and must belong to exactly one of the control,
delivery, or projector roles. Normal `snagline-control` startup never runs DDL
or grants roles.

For a schema-changing rollout, stop/drain writers, take a verified authority
backup, run one designated migrator invocation from the dedicated migration
UID, verify the schema and grants, then start runtime replicas. Do not give the
migrator DSN to a control process, an agent runtime, or any long-lived service.

## Startup and readiness

Order dependencies from authority outward:

1. Make PostgreSQL available and restore/verify the intended authority state.
2. For a schema change, run `snagline-control migrate` first and verify it;
   then start control replicas only after their HTTPS mTLS surface is serving.
3. Make JetStream available and start `snagline-delivery` with a stable unique
   worker ID.
4. Start each edge. It reconciles from PostgreSQL before binding its local Unix
   socket, so a bound private socket means startup reconciliation completed.
5. Invoke `snagline-front` as a separate one-shot process under the matching
   dedicated edge service UID. That UID match is required by the edge's `0700`
   socket directory and `0600` socket. In `cli` mode it renders inert advice;
   in `amq` mode it sends an inert passive display to the one protected
   configured lane. It does not read edge SQLite or carry an SSP, PostgreSQL,
   NATS, or Buzz credential and is never an agent/model process.
6. Start `snagline-buzz-projector` last. Its work is optional for semantic
   acceptance and edge delivery.
7. Invoke `snagline-dispatcher` only through the externally constrained
   dispatcher tool policy, with one case ID, exact commitment, and inert text.

Control, delivery, edge, and Buzz projector expose exactly `GET /livez`,
`GET /readyz`, and Prometheus-text `GET /metrics` on their separately
configured private Unix ops sockets. Their directories must be `0700` and
current-service-UID-owned; the sockets are created `0600`, never listen on TCP,
and must not be reverse proxied. Control readiness checks PostgreSQL, the
expected schema ledger, and a non-halted registry head. Delivery readiness
checks PostgreSQL, a connected JetStream stream, and a successful work cycle
newer than its last error and no older than the configured lease plus two poll
intervals; each delivery work cycle is bounded by that lease. Edge readiness
checks an active local delivery state, a connected JetStream carrier, and
performs only a bounded read-only authority query; it does not apply deliveries
or claim completeness. Projector readiness checks PostgreSQL, private projection
state, and a successful work cycle newer than its last error and no older than
the request timeout plus two poll intervals. The metrics contain only bounded
runtime values; they are not an authority ledger or a transport-completeness
claim.

The public mTLS control listener has no unauthenticated health URL. Treat a
successful Buzz post only as projection evidence, never as an authority receipt.

The front is a one-shot operation, not a health endpoint. Its exit status shows
only whether the bounded local render or passive AMQ claim/send/ack completed;
it cannot establish authority completeness. The AMQ binding is a private
current-UID-owned descriptor with fixed executable, root, session, sender, and
recipient. Do not let advice content select that lane.

Do not publish the private metrics socket or treat its values as evidence of
accepted semantic state. Capture bounded redacted observability and preserve
authority/audit records as the incident evidence.

## Backup and restore drill

Run this drill before production acceptance and periodically thereafter. Use
the approved backup system and an operator credential stored outside this
repository; the examples deliberately reference a shell variable rather than a
password or DSN.

1. Record the exact release artifact, `authority_id`, tenant, registry head
   commitment/revision, and expected edge generations. Quiesce control writers
   for a consistent logical backup or use the database platform's consistent
   snapshot procedure. Stop delivery and projector only after authority writes
   are quiesced; their transport state is not a substitute for PostgreSQL.
2. Capture PostgreSQL with its schema, data, ownership policy, and WAL/snapshot
   evidence using the approved mechanism. For a logical drill, an operator may
   use `pg_dump --format=custom --no-owner --file authority.dump
   "$SNAGLINE_OPERATOR_POSTGRES_DSN"`; protect the resulting artifact as it
   contains exact signed SSP bytes.
3. Independently back up every edge and dispatcher encrypted SQLite database
   together with its matching 32-byte SQLite key, and every projector state
   database with its matching key. Encrypt backups and preserve the mapping of
   backup to UID, directory, key version, tenant, edge ID, and generation. A
   database without its matching key is intentionally unusable.
4. Restore into an isolated environment with the same intended PostgreSQL
   release/schema and no production NATS/Buzz credentials. Restore PostgreSQL
   first. Restore SQLite only to an empty `0700` directory owned by the exact
   service UID, never over a live file. Start edges with JetStream disabled if
   necessary: PostgreSQL reconciliation must rebuild the complete accepted
   delivery range for the retained edge generation.
5. Before reconnecting production carriers, verify immutable authority facts:
   registry heads resolve to the recorded commitments; every accepted case and
   advice has its stored exact bytes/commitment; at most one advice exists per
   case; delivery sequences are positive and contiguous per edge generation;
   audit/outbox rows correspond to committed authority revisions. Any mismatch,
   missing range, registry halt, or key mismatch is a stop condition.
6. Prove recovery with a non-production exact-byte retry and an edge
   reconciliation. JetStream and Buzz may then be reconnected. Do not replay
   from Buzz, import a Buzz cursor, or accept a Buzz event as restoration input.

If an edge SQLite backup is unavailable, do not copy another edge's state or
reuse its generation. Re-enrol the edge with a strictly greater generation;
recover global delivery facts only through the authority API. Private local
bindings and unavailable local state are not recoverable from PostgreSQL.

## Rotation and revocation sequence

All rotation is additive before subtractive. Preserve exact pending SSP bytes
until their normal retry/expiry outcome is resolved; do not re-sign them under a
new key.

1. **TLS/CA:** add trust for the new CA/certificates, distribute new client and
   server credentials, update exact control SAN mappings, validate mTLS, then
   remove the old trust after all callers have moved. A SAN mapping change must
   preserve the registered edge tuple and generation.
2. **Edge or dispatcher SSP key:** publish and accept a registry revision that
   authorizes the new key for the same principal/edge tuple before switching
   the process. Verify a signed new-key request, then retire the old key in a
   later registry revision. Compromise requires an immediate registry action
   and may require edge re-enrolment with a higher generation; do not merely
   swap a file under a running process.
3. **Registry root:** use a controlled trust-distribution migration outside the
   normal registry chain, with overlap and an independently reviewed rollback
   plan. The root is the trust anchor; there is no in-band self-rotation claim
   in this runbook.
4. **SQLite encryption key:** take a verified backup, stop the owning service,
   migrate/re-encrypt only with a reviewed tool (none is shipped here), verify
   reopening/reconciliation in isolation, atomically deploy the new key, and
   keep the old backup/key in protected recovery custody until the drill passes.
   Do not edit or copy a live SQLite file.
5. **NATS credential:** provision a new scoped credential, overlap only long
   enough to verify TLS connection and bounded delivery, then revoke the old
   credential. PostgreSQL remains authoritative throughout an outage.
6. **Buzz identity:** create a distinct replacement Nostr key and have the
   declared human operator issue a new file-backed NIP-OA auth tag. Update the
   official open-channel projector/ACP allowlists and the external dispatcher
   policy/attestation if relevant, run the stock live gate against the
   immutable image digest, then revoke/remove the old agent credential. Never
   reuse a Buzz key as an SSP, TLS, PostgreSQL, or NATS identity.

## Incident boundaries

- A PostgreSQL authority outage means no new commit receipt; preserve/retry
  exact local pending bytes after recovery.
- JetStream failure delays delivery but cannot change accepted cases/advice;
  edges reconcile from PostgreSQL.
- Buzz failure delays or loses only collaboration projection. It cannot
  authorize, finalize, recover, or mutate Snagline state.
- Registry equivocation/rollback halts the tenant. Stop affected admissions and
  investigate from exact authority/audit evidence; do not bypass the halt with
  a transport replay.
- A suspected key or state compromise is a containment event. Stop the affected
  UID/credential, preserve disk/authority evidence, rotate through the ordered
  process above, and re-enrol with a higher generation where required.
