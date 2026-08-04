<p align="center">
  <img src="assets/logo.svg" alt="Snagline" width="360">
</p>

<p align="center">
  <a href="https://github.com/avivsinai/snagline/actions/workflows/ci.yml"><img src="https://github.com/avivsinai/snagline/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/avivsinai/snagline" alt="License"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/avivsinai/snagline" alt="Go version"></a>
</p>

Snagline is a provider-neutral support fabric for AI agent snags. PostgreSQL
is the sole semantic authority for registries, immutable cases, and one final
inert advice per case; JetStream is a bounded at-least-once delivery
accelerator; and each edge keeps its own private encrypted local projection.
Agent collaboration happens over an unmodified, outbound-only stock Buzz
projection that can inform a dispatcher but can never create or change
Snagline state.

## Status

Snagline is pre-release: there are no tagged binary releases yet. Build from
source with the instructions below.

## Architecture

Snagline splits acceptance, delivery, and local state across three trust
domains that never share authority:

- **PostgreSQL** is the sole global semantic authority. It atomically accepts
  registries, immutable cases, and one final inert advice per case, together
  with audit, delivery, and outbox rows.
- **JetStream** is a bounded at-least-once delivery and wake accelerator. It
  is never an acceptance, ordering, or completeness authority.
- **An edge** owns its private encrypted SQLite projection, local bindings,
  pending exact signed SSP bytes, and per-generation delivery evidence.

See [`docs/buzz-snagline-pristine-design.md`](docs/buzz-snagline-pristine-design.md)
for the full design, and
[`docs/agent-integration.md`](docs/agent-integration.md) for the safe
agent-integration boundary around the edge local API — including why no shipped
client opens a case and why an agent must not be given the edge UID.

## Commands

- `snagline-control`
- `snagline-delivery`
- `snagline-edge`
- `snagline-front`
- `snagline-dispatcher`
- `snagline-buzz-projector`
- `snagline-ssp-verify`

The five service commands — `snagline-control`, `snagline-delivery`,
`snagline-edge`, `snagline-dispatcher`, and `snagline-buzz-projector` — are
env/flag-configured daemons or one-shot service processes, each with its own
template in [`deploy/config/`](deploy/config/README.md). `snagline-ssp-verify`
is an offline fixture/artifact verifier with no service template and no
`deploy/config/` entry. `snagline-front` is a one-shot CLI or AMQ (Agent
Message Queue, an external operator-pinned agent-messaging CLI it invokes;
not a message broker) deliverer that runs through the edge's private
Unix-socket API under the matching edge UID. None of the seven is a
`--help`-oriented interactive CLI.

There is no compatibility layer for the removed concierge, control-plane, or
sidecar products. Nothing in this repository installs, publishes, deploys, or
starts a pilot.

Build every command locally:

```sh
make build
```

Run the complete local verification gate:

```sh
make verify
```

The SSP vector check verifies the checked-in signed fixtures and requires
Python 3.12 plus `uv` to validate its pinned Python dependencies.

Buzz is an outbound projection only. It is not an authority, provider edge, or
effect channel, and this repository does not modify or fork Buzz upstream.
The pinned, fail-closed stock deployment contract is documented in
[`docs/stock-buzz-deployment.md`](docs/stock-buzz-deployment.md). Its static
validator is part of `make verify`; the live membership, ACP, and external
dispatcher-tool evidence gate requires a separately deployed stock instance
and real immutable image digest.

Secret-free runtime templates and the honest first-deployment operating
procedures are in [`deploy/config/`](deploy/config/README.md) and
[`docs/operations/pristine-runtime.md`](docs/operations/pristine-runtime.md).
They document current limits too: daemons expose liveness/readiness/metrics
only on private Unix sockets, never a public health endpoint. Schema migration
and PostgreSQL authority-role provisioning are an explicit one-shot
`snagline-control migrate` operation, not control runtime startup behavior.

## Security

See [`SECURITY.md`](SECURITY.md) to report a vulnerability.

## License

Snagline is licensed under the [MIT License](LICENSE). Vendored third-party
material is separately licensed; see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
