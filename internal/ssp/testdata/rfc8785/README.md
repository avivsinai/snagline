# Vendored RFC 8785 corpus

`input/` and `output/` are the ten canonicalization pairs distributed with
[`github.com/gowebpki/jcs` v1.0.1](https://github.com/gowebpki/jcs/tree/v1.0.1/testdata).
They are vendored so Snagline's RFC 8785 evidence does not depend on a mutable
module-cache path during CI. `SHA256SUMS` records the exact checked-in bytes.
The source attribution and Apache License 2.0 text are retained in
[`THIRD_PARTY_NOTICES.md`](../../../../THIRD_PARTY_NOTICES.md) and
[`LICENSES/Apache-2.0.txt`](../../../../LICENSES/Apache-2.0.txt).

The Go test in `internal/ssp/envelope_test.go` executes every pair.
