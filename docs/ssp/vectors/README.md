# SSP v1 conformance vectors

This deterministic corpus covers only `ssp.case.v1`, `ssp.advice.v1`, and
`ssp.registry.v1`. Each signing-input fixture omits `signature`; its `.jcs`
file is the exact RFC 8785 signing input, and its `.signed.json` file is the
signed wire form.

The registry uses `registry-pinned-public-key.txt`; case and advice keys are
resolved from its signed snapshot. `registry-v1.commitment.txt` is the
registry signing-byte commitment. The negative fixtures demonstrate retained
signature tampering, registry header/body disagreement, wrong registry
bindings, and duplicate JSON members.

The generator uses deterministic RFC 8032 test material only. It verifies
JCS, signatures, schemas, key/route/edge bindings, inert-advice case binding,
and `SHA256SUMS`. Run with Python 3.12:

```sh
python3 docs/ssp/vectors/generator/generate.py --check
```

Use `--write` only after intentionally changing a signing input; it rewrites
derived JCS, signatures, negative fixtures, key files, commitment, and the
manifest.
