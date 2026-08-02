# pkg/provision

## What it is

`pkg/provision` is the curated, exported surface an operator uses to
provision a Snagline deployment from outside this module. It exists because
`internal/identity`, `internal/registry`, and `internal/ssp` — the packages
that actually implement key custody, registry trust, and the SSP wire
contract — cannot be imported from outside `github.com/avivsinai/snagline`
by Go's own `internal/` visibility rule. Every deployer needs to do the same
three things before a Snagline deployment can run: generate and custody an
Ed25519 signing key, build and sign a root-authorized `ssp.registry.v1`
envelope, and independently verify that envelope to obtain the commitment
every case/advice envelope binds to as `registry_hash`. `pkg/provision` is
exactly that surface, and no more.

Every exported function is a thin, fail-closed wrapper: the cryptographic
and validation logic all still lives in `internal/identity`,
`internal/registry`, and `internal/ssp`, which remain the sole owners of key
custody semantics, registry trust, and the frozen SSP contract. This package
duplicates none of it.

## Surface

**Signing-key custody** (`signing_key.go`, `custody_unix.go` /
`custody_unsupported.go`):

- `GenerateSigningKey() (SigningKey, error)` — fresh Ed25519 key pair.
- `(SigningKey) WriteTo(path string) error` — persists a generated key as a
  PKCS8 "PRIVATE KEY" PEM file, and succeeds at most once per generated key.
  See "Custody rules" below.
- `LoadSigningKey(path string) (SigningKey, error)` — reads a previously
  provisioned key under the same path rules as `WriteTo`, requiring a
  current-user-owned regular file with no group or other permission bits and
  exactly one PKCS8 Ed25519 "PRIVATE KEY" PEM block. The returned key can
  sign but has no private material to re-persist, so `WriteTo` always fails
  for it.
- `(SigningKey) PublicKey() (ed25519.PublicKey, error)`.
- `MarshalVerifyingKeyPEM(ed25519.PublicKey) ([]byte, error)` — PKIX "PUBLIC
  KEY" PEM encoding for distributing a verifying key to edge/control/
  projector. Encoding only; a verifying key is not secret, so where it is
  written and with what permissions is left to the caller's deployment
  topology.

**Registry construction, signing, and verification** (`registry.go`):

- `Domain`, `Principal`, `Edge`, `Key`, `KeyUsage` — plain value types
  mirroring the `ssp.registry.v1` body's `domains`/`principals`/`edges`/
  `keys` entries. `Domain` has no family field: every domain implicitly
  authorizes exactly `ssp.case.v1` and `ssp.advice.v1`, the only two
  families a registry may ever route, so `SignRegistry` fixes that pair
  itself rather than exposing it as something a caller could get wrong.
- `RegistryDraft` — the unsigned content of one registry envelope: id,
  validity window, revision, routing epoch, optional previous commitment
  (empty string means genesis), and the four record lists above.
- `SignRegistry(root SigningKey, rootKeyID string, draft RegistryDraft)
  ([]byte, error)` — serializes the draft to the frozen wire shape and signs
  it via `ssp.Sign`. It either returns a registry that will verify or an
  error naming the defect; it never produces signed bytes the verifier would
  reject. Two layers run before any bytes are produced. Every *structural*
  rule `internal/ssp` enforces on verify (non-empty issuer edges, opaque-id
  shapes, bounded integers, canonical timestamps, the fixed family pair,
  ...), and every *semantic* rule the registry graph must satisfy:
  duplicate ids, references that do not resolve, two-way principal/edge and
  principal/key ownership, and the role and key-usage bindings that case and
  advice admission depend on. The semantic pass is the same one
  `internal/registry` applies on the way back in, so a draft that signs here
  is a draft that verifies there.
- `NewRegistryTrust(rootKeyID string, rootPublicKey ed25519.PublicKey)
  (RegistryTrust, error)` — pins a trust root, wrapping
  `registry.NewTrust`.
- `VerifyRegistryEnvelope(trust RegistryTrust, raw []byte, now time.Time)
  (string, error)` — re-verifies signed bytes against `trust` as of `now`
  and returns the canonical commitment, wrapping `registry.NewVerifier` /
  `Verify` / `Commitment`.

## Custody rules

A generated private key has exactly one point of custody, and both the write
and the read path enforce that rather than merely documenting it.

**One write per generated key.** `WriteTo` succeeds at most once; every later
attempt fails. The write-once state is shared, not copied: `SigningKey` is a
value type, but its custody state lives behind a pointer, so a copied value
(`copied := key`) and concurrent goroutines all observe the same state and
exactly one write wins.

Custody is spent when the key file is **created**, not when the write
completes. The distinction matters on failure:

- A failure *before* creation — a relative path, a symlinked ancestor, a path
  already occupied — persists nothing and leaves the key writable, so a
  mistyped path is recoverable.
- A failure *after* creation still spends custody and leaves the artifact in
  place. POSIX has no atomic "unlink only if this is the inode I created"
  operation: checking identity and then unlinking would race a concurrent
  replacement. The caller must generate a new key rather than retry at
  another path, and recover only through the deployment's own controlled
  procedure.

**Provisioned keys are crash-durable.** On success `WriteTo` flushes both the
file's contents and the directory entry naming it to stable storage before
returning. A key that vanishes on power loss is worse than a write that
errors, because the operator has already been told provisioning succeeded.

**No symlink anywhere in a custody path.** `WriteTo` and `LoadSigningKey`
both reach the file by opening each directory component in turn with
`O_NOFOLLOW`, starting from the filesystem root, instead of handing the whole
pathname to the kernel. `O_NOFOLLOW` on a single open refuses a symlink only
at the *final* component, so a symlinked parent — or grandparent — would
otherwise silently redirect the key to a location the operator never named,
in either direction. The walk refuses a symlink at any depth.

Consequences a caller must plan for:

- `path` must be absolute and already clean. A path containing `.` or `..` is
  rejected rather than normalized, because cleaning it lexically and then
  walking the result would open something other than what the caller named.
- A custody path may not traverse a symlink even when that symlink is a
  legitimate part of the platform. On macOS, `/etc`, `/var`, and `/tmp` are
  all symlinks, so pass the resolved path (`/private/var/...`) instead.
- `WriteTo` additionally uses `O_EXCL`, so it never overwrites or follows
  anything already at the leaf, and the file is created with and left at
  exactly `0600`.
- `WriteTo` validates that the named parent and leaf still denote its
  descriptors at its final check. No POSIX call can prevent a concurrent
  same-directory writer from changing the pathname after that instant; use a
  directory controlled exclusively by the provisioning operation when an
  enduring named-path guarantee is required.

Signing-key custody is implemented for Unix-like platforms; elsewhere
`WriteTo` and `LoadSigningKey` fail closed with an unsupported-platform
error.

## What was deliberately left out

- **Case/advice envelope signing.** Provisioning references `ssp.case.v1`
  and `ssp.advice.v1` only as the literal family pair inside a domain
  declaration; it never builds or signs an envelope in either family. There
  is no provisioning-time need for that capability, so it is not exposed.
- **A general-purpose secure-file surface.** Reading other deployment
  material — transport credentials, projection keys, component
  configuration — is a deployment concern rather than a registry/key
  provisioning one, and depends on the topology a deployer chose.
  `LoadSigningKey` already applies the module's fail-closed read semantics
  to the one file this package owns, so no separate file-reading surface is
  re-exported.
- **Key revocation.** `internal/registry.KeyRecord` supports a revocation
  timestamp, which the frozen schema treats as optional. `provision.Key`
  omits it, keeping the surface to what provisioning uses today; adding
  key-rotation and revocation support is a natural, separately-reviewable
  follow-up rather than something to fold in silently here.
