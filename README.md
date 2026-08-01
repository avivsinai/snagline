# Snagline

Snagline is a support fabric for agent snags. This repository's first
implementation is deliberately limited to signed support-protocol boundaries:
control, delivery, edge, local front delivery, dispatcher, Buzz projection,
and SSP verification.

There is no compatibility layer for the removed concierge, control-plane, or
sidecar products. Nothing in this repository installs, publishes, deploys, or
starts a pilot.

## Commands

- `snagline-control`
- `snagline-delivery`
- `snagline-edge`
- `snagline-front`
- `snagline-dispatcher`
- `snagline-buzz-projector`
- `snagline-ssp-verify`

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
