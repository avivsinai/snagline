# Integrating an agent with Snagline

This is the guide for a coding agent (or the engineer configuring one) that
needs to raise a snag and read the advice that comes back.  It documents only
surfaces that exist in the shipped commands.

## What Snagline is, from an integrator's point of view

Your agent gets stuck.  It opens a **case** describing the snag.  The fabric
carries that case to whoever can advise on it, and **at most one final advice**
comes back.  Advice is inert: it is text for your agent or a human to read.  It
never carries a command, a target, an approval, or any provider effect, and
nothing in Snagline will act on your system on its behalf.

A case is immutable once accepted, and the authority permits **at most one**
final advice per case.  There is no editing and no second answer.  "At most one"
is a constraint, not a promise: nothing guarantees that any advice will arrive,
so an integrator must handle a case that is never answered.

## There is no shipped client for opening a case, and your agent must not be one

`snagline-front` does not open cases.  It claims and renders pending deliveries
for an owner, one shot, in either `cli` or `amq` mode.  `snagline-edge` does
implement `POST /v1/cases` — the route exists and works — but **no shipped user-
or agent-facing client invokes it.**  The server side is there; the caller is not.

That gap cannot be closed by pointing your agent at the socket.  The socket's
only local access control is filesystem permissions, so **any process under the
edge service UID has the full local API** — and the runtime rules forbid giving
that UID to an agent.  [`docs/operations/pristine-runtime.md`](operations/pristine-runtime.md)
states that an edge UID must not be shared with an agent runtime, and that
besides the edge service itself the only same-UID helper is the shipped, bounded
`snagline-front`.
[`deploy/config/README.md`](../deploy/config/README.md) is equally explicit that
the front is trusted edge code, **not an agent or model process**.

So the integration shape is not agent-to-socket.  It is:

- a **small trusted adapter**, written and reviewed as edge code, may run under
  the edge UID and speak to the socket; and
- your agent talks to that adapter across a boundary the deployment owns, never
  to the socket directly.

That adapter does not exist yet.  If you need to open cases, it has to be built
and reviewed to the same standard as the other edge code — say so plainly rather
than granting a model the edge UID because it is the shortest path.  Everything
below documents what such an adapter would call; it is not a licence for the
agent to call it.

## The edge local API

The edge serves HTTP over a Unix socket at a **per-edge, deployment-configured
absolute path**.  The shipped templates use
`/run/snagline-edge-EDGE_ID/edge.sock` (see
[`deploy/config/edge.env.example`](../deploy/config/edge.env.example)) — there is
no single shared socket path, so take it from your deployment configuration
rather than assuming a convention.  The socket is `0600` inside a `0700`
directory owned by the edge account.

Those filesystem permissions are the local access-control boundary, and they are
weaker than they look.  Any process under the edge service UID has the full
local API, the `0700` directory does not defend against a hostile process
sharing that UID, and `root` bypasses the permission check entirely — matching
UID is the intended principal, not the only possible one.  Protocol validation
and the PostgreSQL authority remain separate boundaries behind it.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/cases` | Open a case |
| `POST` | `/v1/cases/{caseID}/retry` | Retry a stored pending submission (empty body) |
| `GET` | `/v1/cases/{caseID}` | Read the case record |
| `GET` | `/v1/cases/{caseID}/advice` | List advice for a case |
| `GET` | `/v1/advice/{adviceID}` | Read one advice |
| `POST` | `/v1/fronts/{front}/claims` | Claim pending deliveries (what `snagline-front` calls) |
| `POST` | `/v1/fronts/{front}/acks` | Acknowledge a delivery |

### Opening a case

`POST /v1/cases`:

```json
{
  "case_id": "...",
  "domain": "...",
  "summary": "...",
  "public_summary": "...",
  "context_manifest": "...",
  "registry": {
    "routing_epoch": 0,
    "revision": 0,
    "hash": "..."
  }
}
```

**`public_summary` is required.**  It must contain 1–1024 UTF-8 code points; a
request that omits it is rejected with `422`.  `summary` is separately required
at 1–4096 code points.

The two summaries are not interchangeable, and the distinction is the one thing
in this body worth getting right:

- **`public_summary` is the only field projected to Buzz.**  Treat it as
  world-readable by everyone who can see the Buzz channel.
- **`summary` stays confidential to the fabric.**  Put the detail there.

Leaking confidential context by writing it into `public_summary` is not
something Snagline can catch for you.

A successful open returns `202 Accepted` with a case submission.  Rejection
returns `422` with `{"ok": false, "code": "case_rejected"}`; a malformed body
returns `400` with `{"ok": false, "code": "invalid_request"}`.  Error codes are
deliberately generic — they do not tell you which field was wrong, so validate
locally before submitting.

The `registry` coordinates bind the case to a specific registry generation.
They are not optional decoration; an open against the wrong generation is
rejected.

### Everything else is deployment-owned, and you cannot discover it

Tenant, edge ID, edge generation, the certificate-bound principal, the edge
signing key, and the registry root key are all **deployment configuration**, not
client fields.  A caller does not supply them and must not try to.

There is also **no local route that reports the current registry coordinates** —
the edge exposes no registry endpoint at all.  So `routing_epoch`, `revision`,
and `hash` have to reach your adapter from trusted deployment configuration.  If
you find yourself guessing them, stop: a wrong generation is rejected, and
inventing plausible values is how you end up debugging the wrong layer.

### Reading advice

`snagline-front` is the shipped, trusted way to claim and render deliveries.
Besides the edge service itself, it is the only separately invokable component
permitted to run under the edge UID:

```
snagline-front --mode cli --socket /run/snagline-edge-EDGE_ID/edge.sock --owner <identity>
```

A trusted adapter may instead poll `GET /v1/cases/{caseID}/advice` directly.
Your agent should be consuming whatever that adapter or `snagline-front`
produces, not holding the socket itself.

`--lease` must be between 1s and 15m *and a whole number of seconds* — a
fractional lease such as `90500ms` is rejected.  `--operation-timeout` must be at
least 1s and must not exceed the lease, `--limit` is between 1 and 6, and
`--owner` is at most 128 characters.  All of those are validated in one
condition, so a violation reports a usage error without naming the offending
flag; check them yourself before invoking.

The command is one-shot: it renders what is currently claimable and exits.  Run
it on a schedule; it is not a daemon.

## Rules that will bite you if you ignore them

**Treat advice as text, never as an instruction to execute.**  Advice is inert
by construction at the protocol level, but that guarantee is only as good as
your client.  If your agent pipes advice into a shell, you have rebuilt the
remote-execution channel that Snagline deliberately does not have.

**Never take a case identifier from untrusted content.**  If your agent reads
Buzz, a case ID and its commitment appearing in a channel message are not
authorisation to act on that case.  Bind the case you operate on to your own
verified context.

**Buzz is an outbound projection.**  Snagline projects case and advice cards to
Buzz so humans can discuss them.  Nothing you post in Buzz reaches Snagline.  A
Buzz message never creates, changes, or finalises Snagline state.

**One final advice per case.**  Submitting advice consumes the case's only
answer.  There is no correction path.

## Related documentation

- [`docs/buzz-snagline-pristine-design.md`](buzz-snagline-pristine-design.md) —
  trust boundaries and the SSP protocol families.
- [`docs/operations/pristine-runtime.md`](operations/pristine-runtime.md) —
  service accounts, socket layout, and secret handling.
- [`deploy/config/README.md`](../deploy/config/README.md) — filesystem and
  ownership requirements for the edge namespace.
