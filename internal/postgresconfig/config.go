// Package postgresconfig constructs PostgreSQL pools whose connection plans
// cannot downgrade from authenticated, hostname-verifying TLS.
package postgresconfig

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errInvalid = errors.New("PostgreSQL connection configuration is invalid")

// ParsePoolConfig parses an explicit PostgreSQL URL and rejects every
// connection attempt that is not TCP with hostname-verifying TLS. The URL
// must name its trust source so ambient libpq settings cannot silently choose
// the authority transport policy.
func ParsePoolConfig(dsn string) (*pgxpool.Config, error) {
	if dsn == "" || strings.TrimSpace(dsn) != dsn {
		return nil, errInvalid
	}
	endpoint, err := url.Parse(dsn)
	if err != nil ||
		(endpoint.Scheme != "postgres" && endpoint.Scheme != "postgresql") ||
		endpoint.Opaque != "" ||
		endpoint.Fragment != "" {
		return nil, errInvalid
	}
	expected, ok := explicitEndpoints(endpoint.Host)
	if !ok {
		return nil, errInvalid
	}
	query, err := url.ParseQuery(endpoint.RawQuery)
	if err != nil ||
		hasAny(query, "host", "port", "service", "servicefile") ||
		len(query["sslmode"]) != 1 ||
		query["sslmode"][0] != "verify-full" ||
		len(query["sslrootcert"]) != 1 ||
		!validTrustSource(query["sslrootcert"][0]) {
		return nil, errInvalid
	}

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || config == nil || config.ConnConfig == nil {
		return nil, errInvalid
	}
	if len(config.ConnConfig.Fallbacks)+1 != len(expected) ||
		!secureAttempt(expected[0], config.ConnConfig.Host, config.ConnConfig.Port, config.ConnConfig.TLSConfig) {
		return nil, errInvalid
	}
	for i, fallback := range config.ConnConfig.Fallbacks {
		if fallback == nil || !secureAttempt(expected[i+1], fallback.Host, fallback.Port, fallback.TLSConfig) {
			return nil, errInvalid
		}
	}
	return config, nil
}

type tcpEndpoint struct {
	host string
	port uint16
}

func explicitEndpoints(authority string) ([]tcpEndpoint, bool) {
	parts := strings.Split(authority, ",")
	if len(parts) == 0 {
		return nil, false
	}
	endpoints := make([]tcpEndpoint, 0, len(parts))
	for _, part := range parts {
		host, rawPort, err := net.SplitHostPort(part)
		if err != nil || host == "" || strings.TrimSpace(host) != host {
			return nil, false
		}
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 {
			return nil, false
		}
		endpoints = append(endpoints, tcpEndpoint{host: host, port: uint16(port)})
	}
	return endpoints, true
}

func hasAny(query url.Values, keys ...string) bool {
	for _, key := range keys {
		if _, ok := query[key]; ok {
			return true
		}
	}
	return false
}

func validTrustSource(value string) bool {
	return value == "system" ||
		(filepath.IsAbs(value) && filepath.Clean(value) == value)
}

func secureAttempt(expected tcpEndpoint, host string, port uint16, config *tls.Config) bool {
	network, _ := pgconn.NetworkAddress(host, port)
	return network == "tcp" &&
		host == expected.host &&
		port == expected.port &&
		config != nil &&
		!config.InsecureSkipVerify &&
		config.VerifyPeerCertificate == nil &&
		config.ServerName == expected.host &&
		config.RootCAs != nil
}
