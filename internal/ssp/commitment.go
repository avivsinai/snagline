package ssp

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// EnvelopeCommitment returns the canonical commitment to an SSP envelope:
// "sha256:" followed by lowercase hex over the envelope's signing bytes.
//
// The commitment is taken over signing bytes — the received JSON with only
// signature removed, canonicalized with JCS — and never over
// the raw wire.  That makes it stable across insignificant framing differences
// while still covering every signed value.  This is the one construction the
// frozen contract uses for cross-family binding: registry_hash commits a case
// or advice to an exact registry snapshot, and case_commitment binds inert
// advice to the accepted case it describes.
//
// A commitment exists only for an envelope that passes the same guards and
// family validation Verify applies, so an unsupported family, a malformed
// registry header, or a registry body that contradicts its header has no
// commitment at all.  A commitment is an identity, not a trust decision:
// callers that need authenticity must verify the signature against a key they
// already trust, and should do so before computing a commitment.
func EnvelopeCommitment(raw []byte, now time.Time) (string, error) {
	if _, err := decodeAndValidate(raw, now); err != nil {
		return "", err
	}
	unsigned, err := stripUnsignedTopLevel(raw)
	if err != nil {
		return "", invalidEnvelope(err)
	}
	signingBytes, err := canonical(unsigned)
	if err != nil {
		return "", invalidEnvelope(err)
	}
	sum := sha256.Sum256(signingBytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
