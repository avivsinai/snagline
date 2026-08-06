// Package securetransport composes outbound TLS and NATS clients from
// descriptor-validated deployment files.
package securetransport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/avivsinai/snagline/internal/securefile"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const (
	maxPEMBytes        int64 = 1 << 20
	maxCredentialBytes int64 = 1 << 20
)

func LoadClientTLS(certificatePath, privateKeyPath, rootCAPath string) (*tls.Config, error) {
	certificatePEM, err := securefile.ReadRegularBounded(certificatePath, maxPEMBytes)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := securefile.ReadPrivateBounded(privateKeyPath, maxPEMBytes)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	rootPEM, err := securefile.ReadRegularBounded(rootCAPath, maxPEMBytes)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("securetransport: invalid root CA")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
	}, nil
}

func LoadServerTLS(certificatePath, privateKeyPath, clientCAPath string) (*tls.Config, error) {
	certificatePEM, err := securefile.ReadRegularBounded(certificatePath, maxPEMBytes)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := securefile.ReadPrivateBounded(privateKeyPath, maxPEMBytes)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	clientCAPEM, err := securefile.ReadRegularBounded(clientCAPath, maxPEMBytes)
	if err != nil {
		return nil, err
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("securetransport: invalid client CA")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
	}, nil
}

type NATSConfig struct {
	URL             string
	CredentialsFile string
	RootCAFile      string
	Timeout         time.Duration
}

type NATSConnection struct {
	Conn    *nats.Conn
	keyPair nkeys.KeyPair
	once    sync.Once
}

func ConnectNATS(config NATSConfig) (*NATSConnection, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Host == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("securetransport: root tls NATS URL is required")
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("securetransport: NATS timeout must be within one minute")
	}
	rawCredentials, err := securefile.ReadPrivateBounded(config.CredentialsFile, maxCredentialBytes)
	if err != nil {
		return nil, err
	}
	defer clear(rawCredentials)
	userJWT, err := nkeys.ParseDecoratedJWT(rawCredentials)
	if err != nil || strings.Count(userJWT, ".") != 2 {
		return nil, errors.New("securetransport: invalid NATS user credentials")
	}
	keyPair, err := nkeys.ParseDecoratedUserNKey(rawCredentials)
	if err != nil {
		return nil, errors.New("securetransport: invalid NATS user credentials")
	}
	rootPEM, err := securefile.ReadRegularBounded(config.RootCAFile, maxPEMBytes)
	if err != nil {
		keyPair.Wipe()
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		keyPair.Wipe()
		return nil, errors.New("securetransport: invalid NATS root CA")
	}
	auth := nats.UserJWT(
		func() (string, error) { return userJWT, nil },
		func(nonce []byte) ([]byte, error) { return keyPair.Sign(nonce) },
	)
	connection, err := nats.Connect(config.URL,
		auth,
		nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}),
		nats.Timeout(timeout),
	)
	if err != nil {
		keyPair.Wipe()
		return nil, err
	}
	return &NATSConnection{Conn: connection, keyPair: keyPair}, nil
}

func (connection *NATSConnection) Close() error {
	if connection == nil {
		return nil
	}
	var err error
	connection.once.Do(func() {
		if connection.Conn != nil {
			err = connection.Conn.Drain()
		}
		if connection.keyPair != nil {
			connection.keyPair.Wipe()
		}
	})
	return err
}
