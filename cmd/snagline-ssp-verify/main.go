package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/ssp"
)

type result struct {
	OK   bool   `json:"ok"`
	Code string `json:"code"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout))
}

func run(args []string, stdin io.Reader, stdout io.Writer) int {
	flags := flag.NewFlagSet("snagline-ssp-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	publicKeyRaw := flags.String("public-key", "", "base64url Ed25519 public key")
	keyID := flags.String("key-id", "", "author key id")
	nowRaw := flags.String("now", "", "SSP v1 UTC verification timestamp")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return writeResult(stdout, false, "invalid_arguments")
	}

	if strings.TrimSpace(*keyID) == "" {
		return writeResult(stdout, false, "missing_key_id")
	}
	if strings.TrimSpace(*nowRaw) == "" {
		return writeResult(stdout, false, "missing_now")
	}
	now, err := ssp.ParseTimestamp(*nowRaw)
	if err != nil {
		return writeResult(stdout, false, "invalid_now")
	}

	publicKey, err := decodePublicKey(*publicKeyRaw)
	if err != nil {
		return writeResult(stdout, false, "invalid_public_key")
	}

	// Bound the read before doing anything with it. Reading the whole of stdin
	// and checking the size afterwards lets an operator-facing tool be pushed
	// into unbounded memory by input it was always going to reject. Reading one
	// byte past the normative maximum is what makes oversize detectable without
	// consuming the oversize input.
	wire, err := io.ReadAll(io.LimitReader(stdin, ssp.MaxEnvelopeBytes+1))
	if err != nil {
		return writeResult(stdout, false, "read_input_failed")
	}
	if len(wire) > ssp.MaxEnvelopeBytes {
		return writeResult(stdout, false, "input_too_large")
	}
	if _, err := ssp.Verify(wire, map[string]identity.Ed25519VerifyingKey{
		*keyID: publicKey,
	}, now); err != nil {
		return writeResult(stdout, false, "verification_failed")
	}
	return writeResult(stdout, true, "verified")
}

// decodePublicKey requires the pinned key to be given in its one canonical
// base64url form. A key with alternate textual encodings would let the same
// trust anchor be named several ways, which makes operator review and any
// config-fingerprint comparison unreliable.
//
// The argument is used exactly as supplied — no trimming. Trimming would defeat
// the whole point: " key" and "key\n" would become aliases for the canonical
// text, so the trust anchor would again have many spellings and a
// config-fingerprint comparison across them would disagree while verification
// succeeded. Callers that read a key from a file strip their own line endings;
// this tool does not silently normalise its trust input.
func decodePublicKey(encoded string) (identity.Ed25519VerifyingKey, error) {
	raw, err := ssp.DecodeCanonicalBase64(encoded, ed25519.PublicKeySize)
	if err != nil {
		return identity.Ed25519VerifyingKey{}, err
	}
	return identity.NewEd25519VerifyingKey(ed25519.PublicKey(raw))
}

func writeResult(stdout io.Writer, ok bool, code string) int {
	if err := json.NewEncoder(stdout).Encode(result{OK: ok, Code: code}); err != nil {
		return 1
	}
	if ok {
		return 0
	}
	return 1
}
