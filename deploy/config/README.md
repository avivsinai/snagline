# Runtime configuration templates

These templates are an installation input, not a deployment. They deliberately
contain no usable private key, password, token, certificate, image digest, or
live hostname. Copy a template into a private, current-service-UID-owned file,
replace every `.example.invalid` value, and inject secret file contents through
the deployment's secret mechanism. Do not commit the filled copy.

Every service uses a separate Unix account and a private `0700` state
directory. The `0700` boundary protects against other UIDs, not a hostile
process running as the same UID; do not co-host untrusted workloads under any
of these accounts.

| Role | Example account | Private state directory | Configuration input |
| --- | --- | --- | --- |
| migrator (one-shot) | `snagline-migrator` | none | `migrator.env.example` |
| control | `snagline-control` | none (stateless) | `control.env.example` |
| delivery | `snagline-delivery` | none (stateless) | `delivery.env.example` |
| edge | `snagline-edge-EDGE_ID` | `/var/lib/snagline-edge-EDGE_ID` | `edge.env.example` |
| front (one-shot trusted edge helper) | `snagline-edge-EDGE_ID` | none | `front-cli.args.example` or `front-amq.args.example` |
| dispatcher | `snagline-dispatcher` | `/var/lib/snagline-dispatcher` | `dispatcher.env.example` |
| Buzz projector | `snagline-buzz-projector` | `/var/lib/snagline-buzz-projector` | `buzz-projector.config.example.json` |

The edge socket directory is also `0700`, owned by the edge account. Its
socket is created `0600`. SQLite files, key descriptors, NATS credentials, and
private keys must be current-service-UID owned with no group/other bits; the
programs reject unsafe key/credential files. The edge and projector validate
their SQLite namespace as a private directory boundary; use a different state
directory for every edge generation and projector installation.

The edge and dispatcher root database-key files are exactly 32 random bytes.
They are inputs to HKDF, not direct SQLCipher passphrases: the runtime derives
separate SQLCipher and field-AEAD keys and never permits plaintext fallback.
Do not inspect these databases with ordinary SQLite, enable a plaintext header,
or change their `DELETE` journal and memory-only temporary-storage policy.
Do not run an agent, plugin, shell, or other untrusted process under an edge or
dispatcher service UID: same-UID code can both replace the validated SQLite
pathname and read its root key, and is outside the local-state threat boundary.
Builds require CGO plus OpenSSL; release hosts must provide OpenSSL 3
`libcrypto`. The first release matrix is Linux amd64 only. See the
[runtime runbook](../../docs/operations/pristine-runtime.md) for the supported
artifact target and backup/rotation procedure.

## Provisioning, migration, and runtime are different jobs

Provisioning is external to Snagline. It creates the database, TLS/NATS/Buzz
identities, named secret references, service accounts, and directories. It
must not put passwords in these files. Use the organization's approved
identity/authentication mechanism for PostgreSQL DSNs and secret-file mounts.
No runtime role should be a PostgreSQL superuser or the schema owner; grant
only the minimum table/sequence rights proven by an access review.

Every migrator, control, delivery, and projector PostgreSQL DSN must be an
explicit `postgres://` or `postgresql://` URL whose authority names every host
and port, with exactly one `sslmode=verify-full` and exactly one trust source.
The `host`, `port`, `service`, and `servicefile` query parameters are forbidden.
Use
`sslrootcert=system` only when the host trust store is the intended authority;
otherwise use an absolute, clean path to the deployment CA. The binaries parse
that connection plan once, validate its primary endpoint and every fallback,
and use the retained plan. They reject keyword DSNs, missing or repeated TLS
parameters, plaintext or non-hostname-verifying modes, relative CA paths, Unix
sockets, and mixed TCP/Unix plans. Unix-socket PostgreSQL authority is not
supported in this release. `PG*` environment variables and service files do
not replace or relax the explicit authority endpoints or validated transport
plan.

The explicit one-shot `snagline-control migrate` command is the only schema and
runtime-role provisioning entrypoint. It requires an owner-level migrator DSN
through `SNAGLINE_MIGRATOR_POSTGRES_DSN`, applies embedded migrations, then
creates/grants the three NOLOGIN authority group roles. It never creates login
credentials or passwords. Runtime login principals are provisioned outside
Snagline and must belong to exactly one of those roles.

Normal `snagline-control` startup never runs migration DDL or provisions roles.
Treat a schema change as a controlled maintenance step: drain or stop writers,
take and verify a PostgreSQL backup, run one designated migrator invocation,
verify schema/role results, then start runtime replicas. The migrator account
must be distinct from every runtime account and not available to any agent
runtime.

`snagline-delivery`, `snagline-edge`, `snagline-dispatcher`,
`snagline-buzz-projector`, and `snagline-front` are runtime roles. The front
runs as the matching edge service UID because the edge deliberately exposes a
`0600` socket inside its `0700` directory; it is trusted edge code, not an
agent/model process. These roles do not provision identities or schema. The
dispatcher and front are one-shot commands.
`snagline-front` is distributed as a release binary, not as a container target:
AMQ mode must execute the operator-pinned host AMQ binary and share the edge
host UID. Do not inject an AMQ executable into a generic front container.
The front has no environment-variable interface: its exact flags live in the
two `.args.example` files. In AMQ mode, its private JSON binding pins the
executable and lane; it only displays passive inert advice and does not receive
an edge signing key, SQLite key, PostgreSQL role, NATS credential, or Buzz key.
`snagline-ssp-verify` is an offline verifier utility, not a deployed runtime
role, so it has no service template.

The Dockerfile targets are packaging artifacts, not production deployment
definitions. Their `nonroot` image default prevents root execution but does not
prove the required distinct host/service identities. A production orchestrator
must set and verify a pre-provisioned, distinct numeric runtime UID for each
control, delivery, edge generation, dispatcher, and projector deployment, plus
exclusive mounts and socket directories. Reusing the image-default UID across
those deployments fails the role-separation preflight.

## What this repository currently observes

Control, delivery, edge, and Buzz projector expose exactly three **private
Unix-socket HTTP** paths:
`GET /livez`, `GET /readyz`, and Prometheus-text `GET /metrics`. Their sockets
must live in a dedicated current-service-UID-owned `0700` directory and are
created `0600`; they never bind TCP. Do not publish or reverse-proxy them. The
responses deliberately do not disclose dependency topology or credentials.

- Control readiness checks PostgreSQL reachability, the expected schema ledger,
  and a non-halted tenant registry head. The public mTLS control listener still
  has no unauthenticated health URL.
- Delivery readiness checks PostgreSQL, a connected NATS/JetStream stream, and
  a successful delivery work cycle that is newer than its most recent error
  and no older than the configured lease plus two poll intervals. Each work
  cycle is itself bounded by the configured lease.
- Edge readiness checks a connected JetStream carrier and makes a bounded,
  read-only authority delivery query while confirming local delivery state is
  active. It does not mutate delivery state or claim global completion.
- Dispatcher exits after one result. Its JSON result is the invocation outcome;
  it is not a daemon health signal.
- Front exits after it renders locally or sends passive AMQ displays. Its exit
  status is only that one bounded claim/ack operation; it is not daemon health
  or delivery-completeness evidence.
- Buzz projector readiness checks its PostgreSQL authority connection, private
  projection state, and a successful work cycle newer than its last error and
  no older than the request timeout plus two poll intervals. A successful Buzz
  post is never an authority commit.

The private metrics expose only bounded runtime values (ready, initialized,
last success/error, and any known lag/poison count). They are not an authority
ledger, a JetStream completeness claim, or a Buzz acceptance claim. Collect
supervisor state, bounded redacted logs, database backup results, and explicit
synthetic transaction evidence as well. Alerting must distinguish a PostgreSQL
authority outage from JetStream or Buzz projection lag; neither transport
failure changes accepted semantic state.

See [the operations runbook](../../docs/operations/pristine-runtime.md) for
rollout, backup/restore, rotation, and failure handling.
