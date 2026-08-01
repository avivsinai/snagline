# Snagline Agent Guidance

## Current product boundary

Snagline is a pristine, provider-neutral support fabric.  There are no
installed users or compatibility requirements for the removed concierge,
control-plane, sidecar, ticket, intervention, or provider-effect products.
Do not restore their commands, schemas, migrations, deployment assets, or
agent skills.

The current runtime has three trust domains:

- PostgreSQL is the sole global semantic authority.  It atomically accepts
  registries, immutable cases, and one final inert advice per case, together
  with audit, delivery, and outbox rows.
- JetStream is a bounded at-least-once delivery and wake accelerator.  It is
  never an acceptance, ordering, or completeness authority.
- An edge owns its private encrypted SQLite projection, local bindings, pending
  exact signed SSP bytes, and per-generation delivery evidence.

Stock Buzz v0.5.2 is an unmodified, outbound-only, disposable collaboration
projection.  No Buzz event, membership, ACP result, channel, cursor, or
signature may create or change Snagline semantic state.  Buzz content can
inform a dispatcher agent, but only `snagline-dispatcher` may submit the narrow
inert `FinalizeAdvice` operation to the control API.

SSP has exactly these families: `ssp.registry.v1`, `ssp.case.v1`, and
`ssp.advice.v1`.  Keep received-byte verification strict and preserve exact
signed bytes.  Advice has no provider effect, target selector, command,
approval, receipt, revocation, or remote-control semantics.

Read [`docs/buzz-snagline-pristine-design.md`](docs/buzz-snagline-pristine-design.md)
before changing architecture or protocol boundaries.  Read
[`docs/stock-buzz-deployment.md`](docs/stock-buzz-deployment.md) before
changing the stock-Buzz contract.

## Commands and interfaces

The only shipped command roles are:

- `snagline-control`: stateless HTTPS admission and reconciliation over the
  PostgreSQL authority.
- `snagline-delivery`: PostgreSQL-outbox publisher to bounded JetStream.
- `snagline-edge`: local provider-neutral Unix-socket API and encrypted edge
  projection.
- `snagline-front`: one-shot CLI or AMQ delivery through the edge's private
  Unix-socket API, running under the matching edge service UID.
- `snagline-dispatcher`: one-shot, narrow final-advice submitter.
- `snagline-buzz-projector`: read-only PostgreSQL-to-stock-Buzz projection.
- `snagline-ssp-verify`: strict SSP fixture and artifact verifier.

Run `make verify` for the repository gate and `make build` to build every
command.  The stock-Buzz static contract is in `make verify`; its live evidence
gate needs a separately deployed stock instance and immutable image digest.

## Engineering rules

- Orient first: inspect `git status --short --branch`, this guide, and active
  AMQ messages.  Use an isolated worktree for branch work.
- Preserve unrelated work.  Do not reset, stash, switch shared branches, or
  stage another agent's changes.
- Make the smallest composable change in the owning layer.  Verify the real
  invariant with focused tests, then the relevant wider gate.
- Treat filesystem descriptor validation followed by pathname reuse as a
  TOCTOU review point.  Private keys, local state, and credentials must fail
  closed on symlinks, ownership, permissions, or bounds violations.  Edge and
  projector SQLite namespaces additionally require dedicated service UIDs;
  their `0700` directory boundary does not defend against a hostile same-UID
  process.
- Keep PostgreSQL authority, JetStream delivery, edge projection, and Buzz
  projection separate.  Do not introduce dual authority, hidden cursors, or
  a transport-to-effect bridge.
- Coordinate with peers over AMQ; messages should name paths, not paste file
  contents.  Request peer review of the exact tree before committing.  Do not
  commit, push, deploy, or merge without the required authority.
