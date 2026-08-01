package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avivsinai/snagline/internal/ssp"
)

func vectorPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "docs", "ssp", "vectors", name)
}

func readVectorFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(vectorPath(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(raw)
}

func publicKeyText(t *testing.T, name string) string {
	t.Helper()
	return strings.TrimSpace(string(readVectorFile(t, name)))
}

func runVerifier(t *testing.T, publicKey, keyID string, stdin []byte) (int, result) {
	t.Helper()
	var out bytes.Buffer
	code := run([]string{
		"--public-key", publicKey,
		"--key-id", keyID,
		"--now", "2026-07-28T12:00:00Z",
	}, bytes.NewReader(stdin), &out)

	var parsed result
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &parsed); err != nil {
		t.Fatalf("verifier output %q: %v", out.String(), err)
	}
	return code, parsed
}

// TestVerifierAcceptsCanonicalVector is the control. Without it, the bounding
// and canonicalisation tests below could pass simply because the verifier
// rejects everything.
func TestVerifierAcceptsCanonicalVector(t *testing.T) {
	code, got := runVerifier(t, publicKeyText(t, "edge-public-key.txt"), "edge-key-2026-07",
		readVectorFile(t, "case-v1.signed.json"))
	if code != 0 || !got.OK || got.Code != "verified" {
		t.Fatalf("code=%d result=%+v, want verified", code, got)
	}
}

// TestVerifierBoundsStdin proves oversize input is refused by size, before
// verification, and without the process consuming the whole stream. An
// operator-facing tool that reads all of stdin first can be pushed into
// unbounded memory by input it was always going to reject.
func TestVerifierBoundsStdin(t *testing.T) {
	// Far larger than the normative maximum, and larger than the limited read,
	// so a regression that removes the LimitReader would consume all of it.
	oversize := bytes.Repeat([]byte("A"), ssp.MaxEnvelopeBytes*4)

	code, got := runVerifier(t, publicKeyText(t, "edge-public-key.txt"), "edge-key-2026-07", oversize)
	if code == 0 || got.OK {
		t.Fatalf("oversize input accepted: code=%d result=%+v", code, got)
	}
	if got.Code != "input_too_large" {
		t.Fatalf("code = %q, want input_too_large (a size refusal, not a generic verification failure)", got.Code)
	}

	// Exactly at the boundary the read must not truncate into a false size
	// refusal: MaxEnvelopeBytes of junk is refused, but as invalid content.
	atLimit := bytes.Repeat([]byte("A"), ssp.MaxEnvelopeBytes)
	_, got = runVerifier(t, publicKeyText(t, "edge-public-key.txt"), "edge-key-2026-07", atLimit)
	if got.Code == "input_too_large" {
		t.Fatal("input exactly at MaxEnvelopeBytes was reported too large")
	}
	if got.OK {
		t.Fatal("junk at the size limit verified")
	}
}

// TestVerifierReadsNoMoreThanTheBound proves the bound is on the READ, not just
// on a length check afterwards: the reader records how much was consumed.
func TestVerifierReadsNoMoreThanTheBound(t *testing.T) {
	oversize := bytes.Repeat([]byte("A"), ssp.MaxEnvelopeBytes*4)
	counter := &countingReader{inner: bytes.NewReader(oversize)}

	var out bytes.Buffer
	run([]string{
		"--public-key", publicKeyText(t, "edge-public-key.txt"),
		"--key-id", "edge-key-2026-07",
		"--now", "2026-07-28T12:00:00Z",
	}, counter, &out)

	if counter.read > ssp.MaxEnvelopeBytes+1 {
		t.Fatalf("consumed %d bytes, want at most %d", counter.read, ssp.MaxEnvelopeBytes+1)
	}
}

type countingReader struct {
	inner io.Reader
	read  int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	c.read += n
	return n, err
}

// TestVerifierRequiresCanonicalPublicKey pins the trust anchor to one textual
// form. A key with several accepted encodings can be named several ways, which
// makes operator review and config fingerprinting unreliable.
func TestVerifierRequiresCanonicalPublicKey(t *testing.T) {
	canonical := publicKeyText(t, "edge-public-key.txt")
	decoded, err := base64.RawURLEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal(err)
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var alternate string
	for i := 0; i < len(alphabet); i++ {
		candidate := canonical[:len(canonical)-1] + string(alphabet[i])
		if candidate == canonical {
			continue
		}
		got, err := base64.RawURLEncoding.DecodeString(candidate)
		if err == nil && string(got) == string(decoded) {
			alternate = candidate
			break
		}
	}
	if alternate == "" {
		t.Fatal("no alternate tail encoding exists for this key; this test would prove nothing")
	}

	code, got := runVerifier(t, alternate, "edge-key-2026-07", readVectorFile(t, "case-v1.signed.json"))
	if code == 0 || got.OK {
		t.Fatalf("accepted a non-canonical public key encoding: code=%d result=%+v", code, got)
	}
	if got.Code != "invalid_public_key" {
		t.Fatalf("code = %q, want invalid_public_key", got.Code)
	}

	// Padded standard-alphabet form is also refused.
	_, got = runVerifier(t, base64.URLEncoding.EncodeToString(decoded), "edge-key-2026-07",
		readVectorFile(t, "case-v1.signed.json"))
	if got.Code != "invalid_public_key" {
		t.Fatalf("padded key code = %q, want invalid_public_key", got.Code)
	}
}

// TestVerifierRejectsWhitespaceAroundPublicKey pins the trust anchor to EXACTLY
// the canonical text, with no normalisation.
//
// This is a regression test for a real defect: the first version of this code
// called strings.TrimSpace on the argument, so " <key>", "<key> ", "\n<key>"
// and "<key>\t" were all accepted as the same trust anchor and every one of
// them returned verified. Silently normalising trust input means the anchor has
// many spellings, so two configurations that a fingerprint comparison calls
// different both verify — exactly the ambiguity canonical encoding exists to
// remove.
func TestVerifierRejectsWhitespaceAroundPublicKey(t *testing.T) {
	canonical := publicKeyText(t, "edge-public-key.txt")
	wire := readVectorFile(t, "case-v1.signed.json")

	// Control: the canonical text still verifies, so the cases below cannot be
	// passing merely because the key is broken.
	code, got := runVerifier(t, canonical, "edge-key-2026-07", wire)
	if code != 0 || !got.OK || got.Code != "verified" {
		t.Fatalf("canonical key: code=%d result=%+v, want verified", code, got)
	}

	for name, key := range map[string]string{
		"leading space":    " " + canonical,
		"trailing space":   canonical + " ",
		"leading newline":  "\n" + canonical,
		"trailing newline": canonical + "\n",
		"leading tab":      "\t" + canonical,
		"trailing tab":     canonical + "\t",
		"leading crlf":     "\r\n" + canonical,
		"trailing crlf":    canonical + "\r\n",
		"surrounded":       " " + canonical + " ",
		"inner space":      canonical[:10] + " " + canonical[10:],
	} {
		t.Run(name, func(t *testing.T) {
			code, got := runVerifier(t, key, "edge-key-2026-07", wire)
			if code == 0 || got.OK {
				t.Fatalf("accepted a public key with %s: code=%d result=%+v", name, code, got)
			}
			if got.Code != "invalid_public_key" {
				t.Fatalf("code = %q, want invalid_public_key", got.Code)
			}
		})
	}
}
