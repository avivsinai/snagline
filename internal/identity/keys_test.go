package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519KeysSignAndDefensivelyCopy(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := NewEd25519SigningKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifyingKey, err := NewEd25519VerifyingKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	clear(privateKey)
	clear(publicKey)
	message := []byte("exact SSP canonical bytes")
	signature, err := signingKey.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	verificationKey, err := verifyingKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(verificationKey, message, signature) {
		t.Fatal("signature did not verify after caller key buffers were cleared")
	}
}

func TestLoadEd25519KeysUsesPrivateAndPublicFilePolicies(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "signing.pem")
	publicPath := filepath.Join(dir, "verifying.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	signingKey, err := LoadEd25519SigningKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	verifyingKey, err := LoadEd25519VerifyingKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signingKey.Sign([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	loadedPublic, err := verifyingKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(loadedPublic, []byte("message"), signature) {
		t.Fatal("loaded keys did not round trip")
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEd25519SigningKey(privatePath); err == nil {
		t.Fatal("accepted a group/world-readable signing key")
	}
	if _, err := LoadEd25519VerifyingKey(privatePath); err == nil {
		t.Fatal("accepted a private-key PEM as a public key")
	}
}

func TestLoadEd25519KeyRejectsTrailingPEMData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	raw := append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bytes.Repeat([]byte{1}, 32)}), []byte("trailing")...)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEd25519VerifyingKey(path); err == nil {
		t.Fatal("accepted trailing data after the public key PEM block")
	}
}
