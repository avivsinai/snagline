package buzz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestPrivateKeySignerProducesVerifiableBIP340Signature(t *testing.T) {
	raw := make([]byte, 32)
	raw[31] = 1
	signer, err := NewPrivateKeySignerBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("snagline"))
	encoded, err := signer.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	signatureRaw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := schnorr.ParseSignature(signatureRaw)
	if err != nil {
		t.Fatal(err)
	}
	publicRaw, err := hex.DecodeString(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := schnorr.ParsePubKey(publicRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !signature.Verify(digest[:], publicKey) {
		t.Fatal("signature did not verify")
	}
}

func TestPrivateKeySignerRejectsInvalidScalarAndHonorsCancellation(t *testing.T) {
	for _, raw := range []string{"", "01", "zz", "0000000000000000000000000000000000000000000000000000000000000000"} {
		if _, err := NewPrivateKeySigner(raw); err == nil {
			t.Fatalf("accepted invalid private key %q", raw)
		}
	}
	signer, err := NewPrivateKeySigner("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.SignDigest(ctx, sha256.Sum256(nil)); err != context.Canceled {
		t.Fatalf("canceled sign error = %v", err)
	}
}
