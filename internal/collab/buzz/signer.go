package buzz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var errDigestSign = errors.New("collab buzz: digest signing failed")

type privateKeySigner struct {
	privateKey *btcec.PrivateKey
	publicKey  string
}

// NewPrivateKeySigner constructs the narrow Nostr BIP-340 signer used by the
// outbound stock-Buzz projector. The input must be exactly one 32-byte scalar
// encoded as hexadecimal; the signer never exposes it again.
func NewPrivateKeySigner(privateKeyHex string) (DigestSigner, error) {
	raw, err := hex.DecodeString(privateKeyHex)
	if err != nil || len(raw) != btcec.PrivKeyBytesLen {
		return nil, errors.New("collab buzz: private key must be exactly 32 bytes of hex")
	}
	defer clearSecret(raw)
	return NewPrivateKeySignerBytes(raw)
}

// NewPrivateKeySignerBytes constructs the same signer from a raw deployment
// secret, avoiding a long-lived environment string in production composition.
func NewPrivateKeySignerBytes(raw []byte) (DigestSigner, error) {
	if len(raw) != btcec.PrivKeyBytesLen {
		return nil, errors.New("collab buzz: private key must be exactly 32 bytes")
	}
	privateKey, publicKey := btcec.PrivKeyFromBytes(raw)
	if privateKey.Key.IsZero() || !bytes.Equal(privateKey.Serialize(), raw) {
		return nil, errors.New("collab buzz: private key scalar is out of range")
	}
	return &privateKeySigner{
		privateKey: privateKey,
		publicKey:  hex.EncodeToString(schnorr.SerializePubKey(publicKey)),
	}, nil
}

func (s *privateKeySigner) PublicKey() string {
	if s == nil {
		return ""
	}
	return s.publicKey
}

func (s *privateKeySigner) SignDigest(ctx context.Context, digest [sha256.Size]byte) (string, error) {
	if s == nil || s.privateKey == nil {
		return "", errDigestSign
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	signature, err := schnorr.Sign(s.privateKey, digest[:])
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return "", contextErr
		}
		return "", errDigestSign
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(signature.Serialize()), nil
}

func clearSecret(raw []byte) {
	for index := range raw {
		raw[index] = 0
	}
}
