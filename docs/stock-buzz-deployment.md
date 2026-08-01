# Stock Buzz deployment gate

This is an external deployment contract for unmodified
[`block/buzz` v0.5.2](https://github.com/block/buzz/tree/v0.5.2), source
commit `3e48f1b2365d326ee1c9582448d86a99b44ecd5d`. It is not a Buzz fork,
vendored copy, or Snagline authority path.

The contract is deliberately fail-closed:

- the relay image must use a real immutable `@sha256:<64-lowercase-hex>`
  digest; the checked-in placeholder is invalid by design;
- membership and NIP-98 must both be required. Stock Buzz additionally needs
  a stable `BUZZ_RELAY_PRIVATE_KEY` and `RELAY_OWNER_PUBKEY` when
  `BUZZ_REQUIRE_RELAY_MEMBERSHIP=true`;
- projector, specialist, and dispatcher use three distinct Nostr keys;
- every declared channel is private and its membership set contains only those
  agent keys;
- specialist and dispatcher provide their actual stock `buzz-acp` TOML files to
  the gate. Every `[[rules]]` entry must cover one configured private channel
  exactly once, permit only kind `9`, require a mention, and use the exact
  other-channel-member author allowlist. Manifest paths/booleans are not proof.

Stock Buzz's ACP supports one optional `BUZZ_ACP_MCP_COMMAND` per harness. It
does **not** provide identity-specific tool authorization. Therefore the only
permitted dispatcher tool is enforced outside Buzz by the MCP/runtime policy:
the projector and specialist have no MCP command, while the dispatcher has one
external command and a separate Ed25519-signed attestation. The gate verifies
its configured public key, manifest digest, dispatcher identity, exact one-tool
policy, and 24-hour evidence age. This is not a correctness or effect authority path; SSP and
Snagline retain their own authority boundaries.

Live attestation verification requires an OpenSSL build with Ed25519 support.
If it is not the default `openssl`, set `SNAGLINE_OPENSSL_BIN` to its absolute
executable path. The gate fails closed when that verifier is absent or rejects
the signature.

## Static gate

Copy the example into a secret-free deployment manifest, replace every sample
pubkey and secret reference, and resolve the actual stock relay image digest.
Never place a private key in the manifest.

```bash
cp deploy/buzz/stock-buzz.manifest.example.json /secure/stock-buzz.json
python3 deploy/buzz/stock-buzz-gate.py validate --manifest /secure/stock-buzz.json \
  --acp-config specialist=/secure/specialist-acp.toml \
  --acp-config dispatcher=/secure/dispatcher-acp.toml
```

The deployment adapter must map the manifest to stock environment names:
`BUZZ_REQUIRE_RELAY_MEMBERSHIP=true`, `BUZZ_REQUIRE_AUTH_TOKEN=true`,
`BUZZ_RELAY_PRIVATE_KEY`, and `RELAY_OWNER_PUBKEY`. It must map each validated
ACP configuration to `BUZZ_ACP_SUBSCRIBE=config`, `BUZZ_ACP_CONFIG`,
`BUZZ_ACP_RESPOND_TO=allowlist`, and `BUZZ_ACP_RESPOND_TO_ALLOWLIST`. It must
obtain private keys from the referenced secret manager, not from this
repository.

## Live acceptance gate

The live proof is intentionally separate because it needs live stock-Buzz
credentials and agent processes. It must be produced against the exact image
digest in the manifest and include:

1. `buzz channels members` results for every channel, equal to the declared
   agent-only membership set;
2. a nonmember `buzz messages get --channel <private-channel>` denial with the
   stock reason `restricted: not a channel member`;
3. a specialist `buzz-acp` run where a projector-authored, allowlisted mention
   wakes the harness and produces a kind-9 reply in that same private channel;
4. an external Ed25519-signed dispatcher-policy attestation bound to the
   manifest digest, dispatcher identity, exact one-tool policy, and fresh
   RFC3339 `observed_at` timestamp.

Bind those results to the canonical JSON SHA-256 of the manifest in an evidence
file. The supplied script validates the binding and every assertion; it refuses
missing, stale, widened, or mismatched evidence.

```bash
deploy/buzz/run-stock-buzz-live-gate.sh \
  --manifest /secure/stock-buzz.json \
  --evidence /secure/stock-buzz-live-evidence.json \
  --acp-config specialist=/secure/specialist-acp.toml \
  --acp-config dispatcher=/secure/dispatcher-acp.toml
```

`deploy/buzz/test-stock-buzz-gate.sh` tests the validator only. It does not
claim to be a live Buzz deployment test.
