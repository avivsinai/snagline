# Contributing

## Before you start

For anything beyond a small fix, open a discussion or issue describing the
behavior change before writing code. This applies especially to changes that
touch the PostgreSQL authority, JetStream delivery, edge projection, Buzz
projection, or the SSP wire families (`ssp.registry.v1`, `ssp.case.v1`,
`ssp.advice.v1`) — read
[`docs/buzz-snagline-pristine-design.md`](docs/buzz-snagline-pristine-design.md)
first so a proposal doesn't conflict with the current architecture.

## Toolchain

- Go 1.26 (see `go.mod` for the exact pinned version).
- CGO with an OpenSSL development package (`libssl-dev`/`openssl-devel` plus
  `pkg-config`) is required to build `snagline-edge` and `snagline-dispatcher`,
  which link the SQLCipher driver. Commands without local encrypted state
  (`snagline-control`, `snagline-delivery`, `snagline-front`,
  `snagline-buzz-projector`, `snagline-ssp-verify`) build with
  `CGO_ENABLED=0`.
- Python 3.12 and `uv` 0.11.10 to verify the checked-in signed SSP fixtures
  and their pinned Python dependency lock (`make verify-ssp`). Override the
  interpreters with the `PYTHON` and `UV` environment variables if they are
  not first on `PATH` (for example `PYTHON=python3.12 UV=uv make verify-ssp`).

## Making a change

- Make the smallest composable change in the owning layer; keep PostgreSQL
  authority, JetStream delivery, edge projection, and Buzz projection
  separate — do not introduce dual authority, hidden cursors, or a
  transport-to-effect bridge.
- Every behavior change needs tests, including at least one negative case
  (a rejection, a failure-closed path, or an invalid input) — not only the
  happy path.
- Do not vendor, shim, or fork a dependency to route around an existing
  constraint. Use the module system; if a dependency needs to change,
  say so in the discussion or issue first.
- Run `make verify` locally before opening a pull request. It runs
  formatting, vet, unit tests, the build, the SSP vector verification, the
  stock-Buzz static contract check, and a secrets scan. CI additionally runs
  `go test -race` across the full suite and, tagged `integration`, against a
  real PostgreSQL instance — both need a live database and are not part of
  local `make verify`.

## Commit style

Commit subjects are lowercase, imperative, and scoped like the existing
history, for example:

```
fix: require authenticated PostgreSQL authority transport
feat(buzz): implement outbound-only projector
docs: define outbound-only Buzz contract
test(buzz): attest non-allowlisted ACP silence
```

## Pull requests

Open pull requests against `main`. CI runs `make verify`; it must pass, and
a maintainer must review and approve the change before it merges.
