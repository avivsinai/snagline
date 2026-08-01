package registry

import (
	"errors"
	"testing"
)

func TestVerifierOwnsVerifiedEvidence(t *testing.T) {
	first := newVerifier(t)
	verified, err := first.Verify(readVector(t, "registry-v1.signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Snapshot(); err != nil {
		t.Fatal(err)
	}
	verified.owner = nil
	if _, err := verified.Snapshot(); !errors.Is(err, ErrUnverified) {
		t.Fatalf("ownerless evidence error = %v", err)
	}
}
