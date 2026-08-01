# Stock Buzz deployment gate

This is an external deployment contract for unmodified
[`block/buzz` v0.5.2](https://github.com/block/buzz/tree/v0.5.2), source
commit `3e48f1b2365d326ee1c9582448d86a99b44ecd5d`. It is not a Buzz fork,
vendored copy, or Snagline authority path.

The contract is deliberately fail-closed:

- the relay image must use a real immutable `@sha256:<64-lowercase-hex>`
  digest; the checked-in placeholder is invalid by design;
- membership, NIP-98, and NIP-OA admission must all be enabled. Stock Buzz additionally needs
  a stable `BUZZ_RELAY_PRIVATE_KEY` and `RELAY_OWNER_PUBKEY` when
  `BUZZ_REQUIRE_RELAY_MEMBERSHIP=true`;
- every human and agent uses a distinct Nostr key. The relay owner is one of
  the declared humans; each agent names that human in both signed kind-0
  `name` and `display_name` metadata and carries a file-backed NIP-OA auth tag
  signed by that owner;
- stock Buzz is placed behind the approved HTTPS proxy using the public
  DigiCert wildcard certificate. The projector validates it with system
  WebPKI roots and requires TLS 1.3; the HTTP relay port is not exposed to the
  projector. An optional absolute, bounded, non-symlink extra-CA file remains
  available for deployments that explicitly require one;
- this is one shared community. Every ordinary channel is `open`; privacy is
  reserved for two-party `dm` channels. Humans may join ordinary channels and
  steer agents, while the deployment does not create a human-to-human chat
  surface;
- channel types are exactly stock `stream`, `forum`, `dm`, or `workflow`;
  unknown values fail the gate rather than being treated as ordinary channels;
- projector, specialist, and dispatcher have explicit official-channel
  allowlists. Other open channels and DMs remain available for general
  agent-to-agent discussion without becoming Snagline authority;
- specialist and dispatcher provide their actual stock `buzz-acp` TOML and
  runtime environment files to the gate. Each `[[rules]]` entry uses the pinned
  v0.5.2 fields `name`, `channels`, `kinds`, and `require_mention`, covers
  official open channels exactly once, permits only kind `9`, and requires a
  mention. The global author gate is proven separately by
  `BUZZ_ACP_RESPOND_TO=allowlist` and the exact comma-separated
  `BUZZ_ACP_RESPOND_TO_ALLOWLIST`; respond-to fields do not exist inside a
  stock rule.

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

Copy the example into a secret-free deployment manifest, replace every invalid
identity, relay-owner, and attestor placeholder plus every Kubernetes
`SecretKeySelector`, and resolve the actual stock relay image digest. The gate
also permanently rejects the historical committed sample-key fingerprints;
they cannot become production identities merely by completing the other
fields. Create the referenced Secrets in the workload namespace and use only
`valueFrom.secretKeyRef`; never place decoded Secret data in the manifest.

```bash
cp deploy/buzz/stock-buzz.manifest.example.json /secure/stock-buzz.json
python3 deploy/buzz/stock-buzz-gate.py validate --manifest /secure/stock-buzz.json \
  --acp-config specialist=/secure/specialist-acp.toml \
  --acp-config dispatcher=/secure/dispatcher-acp.toml \
  --acp-runtime-env specialist=/secure/specialist-acp.env \
  --acp-runtime-env dispatcher=/secure/dispatcher-acp.env
```

The deployment adapter must map the manifest to stock environment names:
`BUZZ_REQUIRE_RELAY_MEMBERSHIP=true`, `BUZZ_REQUIRE_AUTH_TOKEN=true`,
`BUZZ_ALLOW_NIP_OA_AUTH=true`,
`BUZZ_RELAY_PRIVATE_KEY`, and `RELAY_OWNER_PUBKEY`. It must map each validated
ACP configuration to `BUZZ_ACP_SUBSCRIBE=config`, `BUZZ_ACP_CONFIG`,
`BUZZ_ACP_RESPOND_TO=allowlist`, and `BUZZ_ACP_RESPOND_TO_ALLOWLIST`. It must
mount or inject private values from the exact Kubernetes Secret key selectors
declared in the manifest. No external secret-store abstraction is part of this
contract.

## Live acceptance gate

The live proof is intentionally separate because it needs live stock-Buzz
credentials and agent processes. It must be produced against the exact image
digest in the manifest and include:

1. a complete channel inventory proving every non-DM channel is `open` and
   every declared DM is `private`;
2. relay membership equal to the declared human keys, plus a verified NIP-OA
   agent-to-human owner binding for every declared agent;
3. the complete raw signed kind-0 Nostr profile event for every agent. The gate
   strictly parses its seven event fields, recomputes the event ID from the
   exact NIP-01 serialization, verifies the BIP340 signature and author, then
   requires signed `name` and `display_name` content to equal the declared
   metadata and visibly name its human operator;
4. a specialist `buzz-acp` run where a human-authored, allowlisted mention
   wakes the harness and produces a kind-9 reply in an official open channel;
5. an external Ed25519-signed dispatcher-policy attestation bound to the
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
  --acp-config dispatcher=/secure/dispatcher-acp.toml \
  --acp-runtime-env specialist=/secure/specialist-acp.env \
  --acp-runtime-env dispatcher=/secure/dispatcher-acp.env
```

`deploy/buzz/test-stock-buzz-gate.sh` tests the validator only. It does not
claim to be a live Buzz deployment test.
