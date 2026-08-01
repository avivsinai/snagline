package securetransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadClientTLSSeparatesPublicAndPrivateDeploymentFiles(t *testing.T) {
	certificatePath, privateKeyPath, rootPath := writeTestTLSFiles(t)
	config, err := LoadClientTLS(certificatePath, privateKeyPath, rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != 0x0304 || len(config.Certificates) != 1 || config.RootCAs == nil {
		t.Fatalf("TLS config = %#v", config)
	}
	if err := os.Chmod(privateKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientTLS(certificatePath, privateKeyPath, rootPath); err == nil {
		t.Fatal("accepted group/world-readable TLS private key")
	}
}

func TestConnectNATSRejectsInsecureURLBeforeReadingCredentials(t *testing.T) {
	_, err := ConnectNATS(NATSConfig{URL: "nats://example.test:4222", CredentialsFile: "/missing", RootCAFile: "/missing"})
	if err == nil {
		t.Fatal("accepted insecure NATS URL")
	}
}

func writeTestTLSFiles(t *testing.T) (string, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "snagline-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certificatePath := filepath.Join(dir, "client.pem")
	privateKeyPath := filepath.Join(dir, "client-key.pem")
	rootPath := filepath.Join(dir, "root.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if err := os.WriteFile(certificatePath, certificatePEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, certificatePEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return certificatePath, privateKeyPath, rootPath
}
