# Independent SSP vector checker

The checker independently derives RFC 8785 signing bytes and Ed25519 fixtures
for the three live SSP families: case, inert advice, and registry. It has no
dependency on Snagline's Go canonicalizer. The embedded RFC 8032 seed is public
test material, not a production secret.

```sh
PYTHON=python3.12 python3 docs/ssp/vectors/generator/generate.py --check
```

The dependency lock remains the reproducible Python environment contract.
`--write` regenerates derived fixtures from committed signing-input JSON and
updates `SHA256SUMS`; it never changes those signing inputs.
