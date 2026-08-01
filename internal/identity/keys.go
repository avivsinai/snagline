// Package identity contains only the Ed25519 key boundary used by SSP.
package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/avivsinai/snagline/internal/securefile"
)

const maxPEMBytes int64 = 64 << 10

type Ed25519SigningKey struct {
	privateKey ed25519.PrivateKey
}

type Ed25519VerifyingKey struct {
	publicKey ed25519.PublicKey
}

func NewEd25519SigningKey(privateKey ed25519.PrivateKey) (Ed25519SigningKey, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Ed25519SigningKey{}, fmt.Errorf("ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	return Ed25519SigningKey{privateKey: append(ed25519.PrivateKey(nil), privateKey...)}, nil
}

func NewEd25519VerifyingKey(publicKey ed25519.PublicKey) (Ed25519VerifyingKey, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Ed25519VerifyingKey{}, fmt.Errorf("ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	return Ed25519VerifyingKey{publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

func (key Ed25519SigningKey) IsZero() bool {
	return len(key.privateKey) == 0
}

func (key Ed25519VerifyingKey) IsZero() bool {
	return len(key.publicKey) == 0
}

func (key Ed25519SigningKey) VerifyingKey() (Ed25519VerifyingKey, error) {
	publicKey, err := key.PublicKey()
	if err != nil {
		return Ed25519VerifyingKey{}, err
	}
	return NewEd25519VerifyingKey(publicKey)
}

func (key Ed25519SigningKey) PublicKey() (ed25519.PublicKey, error) {
	if key.IsZero() {
		return nil, errors.New("ed25519 signing key is not configured")
	}
	publicKey, ok := key.privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("ed25519 signing key public key type mismatch")
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func (key Ed25519VerifyingKey) PublicKey() (ed25519.PublicKey, error) {
	if key.IsZero() {
		return nil, errors.New("ed25519 verifying key is not configured")
	}
	return append(ed25519.PublicKey(nil), key.publicKey...), nil
}

func (key Ed25519SigningKey) Sign(message []byte) ([]byte, error) {
	if key.IsZero() {
		return nil, errors.New("ed25519 signing key is not configured")
	}
	return ed25519.Sign(key.privateKey, message), nil
}

func LoadEd25519SigningKey(path string) (Ed25519SigningKey, error) {
	block, err := loadEd25519PEMBlock(path, "ed25519 signing key", "PRIVATE KEY", true)
	if err != nil {
		return Ed25519SigningKey{}, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Ed25519SigningKey{}, fmt.Errorf("parse ed25519 signing key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return Ed25519SigningKey{}, errors.New("signing key must be ed25519")
	}
	return NewEd25519SigningKey(privateKey)
}

func LoadEd25519VerifyingKey(path string) (Ed25519VerifyingKey, error) {
	block, err := loadEd25519PEMBlock(path, "ed25519 verifying key", "PUBLIC KEY", false)
	if err != nil {
		return Ed25519VerifyingKey{}, err
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return Ed25519VerifyingKey{}, fmt.Errorf("parse ed25519 verifying key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return Ed25519VerifyingKey{}, errors.New("verifying key must be ed25519")
	}
	return NewEd25519VerifyingKey(publicKey)
}

func loadEd25519PEMBlock(path, keyName, wantType string, private bool) (*pem.Block, error) {
	var (
		raw []byte
		err error
	)
	if private {
		raw, err = securefile.ReadPrivateBounded(strings.TrimSpace(path), maxPEMBytes)
	} else {
		raw, err = securefile.ReadRegularBounded(strings.TrimSpace(path), maxPEMBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", keyName, err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s must contain exactly one PEM block", keyName)
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("%s must be a %s PEM", keyName, wantType)
	}
	return block, nil
}
