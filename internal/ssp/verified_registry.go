package ssp

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
)

// ErrUnverifiedProof reports use of a VerifiedRegistryEnvelope that was never
// minted by VerifyRegistry — in practice, a zero value.
var ErrUnverifiedProof = errors.New("ssp: registry proof was not produced by VerifyRegistry")

// VerifiedRegistryEnvelope is evidence that a registry envelope was verified
// against a caller-pinned key at a specific instant.
//
// It exists because "the caller verified first" is a convention, and a
// convention is not an invariant. A downstream package that must not admit
// unverified authority cannot check a convention, but it can require this type,
// which has no exported fields and no public constructor other than
// VerifyRegistry. The zero value therefore proves nothing and every accessor
// rejects it.
//
// The proof retains the pinned key and author key id so it can be re-verified
// at a later instant without the holder having to carry trust configuration
// around. That matters because verification is time-dependent: an envelope
// valid when it was received may be expired by the time something durable is
// done with it, and the layer performing that durable action is the one that
// must re-check.
type VerifiedRegistryEnvelope struct {
	verified     bool
	raw          []byte
	envelope     Envelope
	commitment   string
	authorKeyID  string
	verifyingKey identity.Ed25519VerifyingKey
	verifiedAt   time.Time
}

// VerifyRegistry authenticates a registry envelope against a pinned key and
// returns proof of that verification.
//
// Both halves of the trust anchor come from the caller and neither is read out
// of the input: expectedAuthorKeyID is the id the key is pinned under, and the
// verifying key set is built from that pair alone. An envelope naming any other
// author cannot reach the pinned key, so relabelling the author does not help
// an attacker. The family is required to be ssp.registry.v1, so a validly
// signed envelope of some other family cannot be laundered into registry
// authority.
func VerifyRegistry(raw []byte, expectedAuthorKeyID string, key identity.Ed25519VerifyingKey, now time.Time) (VerifiedRegistryEnvelope, error) {
	if expectedAuthorKeyID == "" {
		return VerifiedRegistryEnvelope{}, errors.New("ssp: expected author key id is required")
	}
	if key.IsZero() {
		return VerifiedRegistryEnvelope{}, errors.New("ssp: verifying key is required")
	}

	envelope, err := Verify(raw, map[string]identity.Ed25519VerifyingKey{expectedAuthorKeyID: key}, now)
	if err != nil {
		return VerifiedRegistryEnvelope{}, fmt.Errorf("ssp: verify registry envelope: %w", err)
	}
	if envelope.Schema != FamilyRegistry {
		return VerifiedRegistryEnvelope{}, fmt.Errorf("%w: envelope family is %q, want %q",
			ErrUnknownFamily, envelope.Schema, FamilyRegistry)
	}
	// The key-set construction above already makes any other author
	// unverifiable. Asserting it explicitly turns a silent unknown-key error
	// into a precise one and keeps the invariant true if that construction is
	// ever refactored.
	if envelope.AuthorKeyID != expectedAuthorKeyID {
		return VerifiedRegistryEnvelope{}, fmt.Errorf("ssp: author_key_id %q is not the pinned %q",
			envelope.AuthorKeyID, expectedAuthorKeyID)
	}

	commitment, err := EnvelopeCommitment(raw, now)
	if err != nil {
		return VerifiedRegistryEnvelope{}, err
	}

	// Copy the bytes the proof is about, so a caller mutating its own buffer
	// afterwards cannot change what was verified.
	//
	// Copy the mutable body slice before retaining this proof.
	sealed := append([]byte(nil), raw...)
	envelope.Body = copyRaw(envelope.Body)
	return VerifiedRegistryEnvelope{
		verified:     true,
		raw:          sealed,
		envelope:     envelope,
		commitment:   commitment,
		authorKeyID:  expectedAuthorKeyID,
		verifyingKey: key,
		verifiedAt:   now,
	}, nil
}

// ReverifyAt re-runs the full verification at a new instant and returns fresh
// proof.
//
// This is what lets a durable-write boundary bind the evaluation instant to the
// instant of the write. Without it, a caller could verify while an envelope was
// live, wait until it expired, and still perform an action that ought to have
// required current authority.
func (v VerifiedRegistryEnvelope) ReverifyAt(now time.Time) (VerifiedRegistryEnvelope, error) {
	if !v.verified {
		return VerifiedRegistryEnvelope{}, ErrUnverifiedProof
	}
	return VerifyRegistry(v.raw, v.authorKeyID, v.verifyingKey, now)
}

// IsZero reports whether this value carries no proof.
func (v VerifiedRegistryEnvelope) IsZero() bool { return !v.verified }

// Raw returns a copy of the exact verified bytes.
func (v VerifiedRegistryEnvelope) Raw() ([]byte, error) {
	if !v.verified {
		return nil, ErrUnverifiedProof
	}
	return append([]byte(nil), v.raw...), nil
}

// Envelope returns a copy of the verified envelope with every mutable member
// defensively copied, so a holder cannot edit the retained proof in place.
func (v VerifiedRegistryEnvelope) Envelope() (Envelope, error) {
	if !v.verified {
		return Envelope{}, ErrUnverifiedProof
	}
	envelope := v.envelope
	envelope.Body = copyRaw(v.envelope.Body)
	return envelope, nil
}

// copyRaw returns an independent copy of a raw JSON member, preserving the
// distinction between absent (nil) and present-but-empty.
func copyRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage{}, raw...)
}

// Commitment returns the canonical commitment over the verified envelope's
// signing bytes: the value every other family binds to as registry_hash.
func (v VerifiedRegistryEnvelope) Commitment() (string, error) {
	if !v.verified {
		return "", ErrUnverifiedProof
	}
	return v.commitment, nil
}

// AuthorKeyID returns the pinned author key id the envelope was verified under.
func (v VerifiedRegistryEnvelope) AuthorKeyID() (string, error) {
	if !v.verified {
		return "", ErrUnverifiedProof
	}
	return v.authorKeyID, nil
}

// Revision returns the verified registry revision.
func (v VerifiedRegistryEnvelope) Revision() (int64, error) {
	if !v.verified {
		return 0, ErrUnverifiedProof
	}
	return v.envelope.RegistryRevision, nil
}

// RoutingEpoch returns the verified routing epoch.
func (v VerifiedRegistryEnvelope) RoutingEpoch() (int64, error) {
	if !v.verified {
		return 0, ErrUnverifiedProof
	}
	return v.envelope.RoutingEpoch, nil
}

// VerifiedAt returns the instant this proof was minted.
func (v VerifiedRegistryEnvelope) VerifiedAt() (time.Time, error) {
	if !v.verified {
		return time.Time{}, ErrUnverifiedProof
	}
	return v.verifiedAt, nil
}
