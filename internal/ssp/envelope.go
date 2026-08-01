package ssp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/gowebpki/jcs"
)

const MaxEnvelopeBytes = 64 << 10
const MaxDepth = 32

// Family names for the frozen SSP v1 schemas.  Only the families listed here
// are implemented; every other schema string fails closed with
// ErrUnknownFamily so an unreviewed family can never be machine-accepted.
const (
	FamilyCase     = "ssp.case.v1"
	FamilyAdvice   = "ssp.advice.v1"
	FamilyRegistry = "ssp.registry.v1"
)

var (
	ErrUnknownFamily   = errors.New("ssp: unknown family")
	ErrUnknownField    = errors.New("ssp: unknown envelope field")
	ErrDuplicateKey    = errors.New("ssp: duplicate object key")
	ErrInvalidEnvelope = errors.New("ssp: malformed or structurally invalid envelope")
	ErrExpiredEnvelope = errors.New("ssp: expired envelope")
)

var sha256HexPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Envelope struct {
	Schema           string          `json:"schema"`
	ID               string          `json:"id"`
	CaseID           string          `json:"case_id,omitempty"`
	EmittedAt        string          `json:"emitted_at"`
	ExpiresAt        string          `json:"expires_at"`
	RoutingEpoch     int64           `json:"routing_epoch"`
	RegistryRevision int64           `json:"registry_revision"`
	RegistryHash     string          `json:"registry_hash,omitempty"`
	AuthorKeyID      string          `json:"author_key_id"`
	SignatureAlg     string          `json:"signature_alg"`
	Body             json.RawMessage `json:"body"`
	Signature        string          `json:"signature,omitempty"`
}

func rawGuard(raw []byte) error {
	if len(raw) > MaxEnvelopeBytes {
		return fmt.Errorf("ssp: envelope exceeds %d bytes", MaxEnvelopeBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("ssp: invalid UTF-8")
	}
	// Valid UTF-8 bytes are not sufficient. A JSON \uXXXX escape can name a
	// UTF-16 surrogate code unit using nothing but ASCII, so a malformed pair
	// survives the byte-level check above and is only resolved later, during
	// decoding or canonicalization, where distinct malformed inputs collapse to
	// the same replacement character. That must be refused here, at the parse
	// boundary, before either happens.
	if err := validateStringEscapes(raw); err != nil {
		return err
	}
	start := skipSpace(raw, 0)
	if start >= len(raw) || raw[start] != '{' {
		return errors.New("ssp: envelope root must be an object")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := scanValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("ssp: malformed JSON: multiple values")
		}
		return fmt.Errorf("ssp: malformed JSON: %w", err)
	}
	return nil
}

// Surrogate escape validation.
//
// RFC 8785 requires canonicalization to terminate on invalid Unicode, and this
// is where that rule is enforced. It is enforced here, on the raw bytes, rather
// than relied upon from a downstream library, for a concrete reason: the JCS
// implementation this package delegates to treats either half of a surrogate
// pair as the start of a pair and decodes without proving the first unit is
// high and the second is low. Distinct malformed inputs therefore produce the
// SAME canonical output.
//
// Measured on this tree before this check existed, all three of
// "\uD800\uD800", "\uD800\uD801" and "\uDC00\uD800" canonicalized to the
// identical bytes {"id":"\ufffd"}. One Ed25519 signature verifies all three, so
// the signature no longer identifies a single wire — and putting such a value in
// id, case_id, author_key_id or domain turns that into replay, dedup and
// authority-lookup ambiguity.
//
// There is a second, quieter failure in the same place: encoding/json produces
// its own replacement-character expansion, so the typed Envelope the
// application consumes is not the string the canonicalizer authenticated. Both
// problems disappear only if malformed escapes never reach either component.
const (
	surrogateHighMin = 0xD800
	surrogateHighMax = 0xDBFF
	surrogateLowMin  = 0xDC00
	surrogateLowMax  = 0xDFFF
)

func isHighSurrogate(unit int) bool { return unit >= surrogateHighMin && unit <= surrogateHighMax }
func isLowSurrogate(unit int) bool  { return unit >= surrogateLowMin && unit <= surrogateLowMax }

// validateStringEscapes rejects every surrogate escape that is not exactly one
// high unit immediately followed by one low unit. A valid pair is accepted, so
// astral-plane characters remain expressible.
func validateStringEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			i++
			continue
		}
		switch c {
		case '"':
			inString = false
			i++
			continue
		case '\\':
			if i+1 >= len(raw) {
				return errors.New("ssp: truncated escape sequence")
			}
			if raw[i+1] != 'u' {
				// Any other escape is two bytes, including \\ — skipping both is
				// what keeps a literal backslash from being mistaken for the
				// start of an escape.
				i += 2
				continue
			}
			first, err := readHex4(raw, i+2)
			if err != nil {
				return err
			}
			next := i + 6
			if isLowSurrogate(first) {
				return fmt.Errorf("ssp: lone low surrogate escape U+%04X", first)
			}
			if isHighSurrogate(first) {
				if next+6 > len(raw) || raw[next] != '\\' || raw[next+1] != 'u' {
					return fmt.Errorf("ssp: high surrogate escape U+%04X is not followed by a low surrogate escape", first)
				}
				second, err := readHex4(raw, next+2)
				if err != nil {
					return err
				}
				if !isLowSurrogate(second) {
					return fmt.Errorf("ssp: high surrogate escape U+%04X is followed by U+%04X, which is not a low surrogate", first, second)
				}
				next += 6
			}
			i = next
			continue
		default:
			i++
		}
	}
	return nil
}

// readHex4 reads exactly four hexadecimal digits. It is deliberately strict
// about case and length rather than tolerant, because a partially parsed escape
// is how a malformed unit slips past a scan.
func readHex4(raw []byte, pos int) (int, error) {
	if pos+4 > len(raw) {
		return 0, errors.New("ssp: truncated unicode escape")
	}
	value := 0
	for offset := 0; offset < 4; offset++ {
		digit := raw[pos+offset]
		switch {
		case digit >= '0' && digit <= '9':
			value = value<<4 | int(digit-'0')
		case digit >= 'a' && digit <= 'f':
			value = value<<4 | int(digit-'a'+10)
		case digit >= 'A' && digit <= 'F':
			value = value<<4 | int(digit-'A'+10)
		default:
			return 0, fmt.Errorf("ssp: invalid unicode escape digit %q", digit)
		}
	}
	return value, nil
}

// scanValue consumes exactly one JSON value while retaining the two checks the
// standard library's map/struct decoding cannot provide: duplicate object keys
// and a bounded nesting depth.  It intentionally scans tokens rather than
// decoding into an intermediate Go value so the caller can later canonicalize
// the original JSON representation.
func scanValue(dec *json.Decoder, depth int) error {
	if depth > MaxDepth {
		return errors.New("ssp: nesting depth exceeded")
	}
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("ssp: malformed JSON: %w", err)
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaxDepth && (delim == '{' || delim == '[') {
		return errors.New("ssp: nesting depth exceeded")
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return fmt.Errorf("ssp: malformed JSON: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("ssp: malformed JSON: object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			keys[key] = struct{}{}
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			if err != nil {
				return fmt.Errorf("ssp: malformed JSON: %w", err)
			}
			return errors.New("ssp: malformed JSON: expected object terminator")
		}
	case '[':
		for dec.More() {
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			if err != nil {
				return fmt.Errorf("ssp: malformed JSON: %w", err)
			}
			return errors.New("ssp: malformed JSON: expected array terminator")
		}
	default:
		return errors.New("ssp: malformed JSON: unexpected delimiter")
	}
	return nil
}

func canonical(raw []byte) ([]byte, error) {
	if err := rawGuard(raw); err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

func Sign(e Envelope, key identity.Ed25519SigningKey, now time.Time) ([]byte, error) {
	e.Signature = ""
	if err := e.Validate(now); err != nil {
		return nil, err
	}
	unsigned, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("ssp: marshal unsigned envelope: %w", err)
	}
	c, err := canonical(unsigned)
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(c)
	if err != nil {
		return nil, fmt.Errorf("ssp: sign envelope: %w", err)
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(sig)
	wire, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("ssp: marshal signed envelope: %w", err)
	}
	if err := rawGuard(wire); err != nil {
		return nil, err
	}
	return wire, nil
}

// DecodeCanonicalBase64 decodes base64url-without-padding and requires the
// input to be the ONE canonical encoding of the bytes it yields.
//
// Plain RawURLEncoding is not enough. It ignores the unused low bits of the
// final character, so a 64-byte signature has many distinct textual forms that
// all decode identically — for example tails "zADQ" and "zADR". Every one of
// them would verify, so the signature text alone would not identify one wire.
//
// Scope of what this fixes, stated narrowly on purpose. Canonical base64 closes
// exactly ONE alias class: the signature and key encodings. It does NOT make the
// wire unique, and neither does adding validateStringEscapes. JCS canonicalizes
// away member ordering, insignificant whitespace, and equivalent string escapes,
// which is precisely its job — so by design many distinct byte sequences share
// one set of signing bytes and one valid signature. That is correct behaviour,
// not a defect.
//
// The consequence for callers is the part worth stating plainly, because getting
// it wrong is easy: raw received wire bytes are NOT an identity. They must not be
// used as a deduplication key, a replay-protection key, or an audit identity,
// because two honest re-encodings of one signed statement differ in those bytes
// while denoting the same statement. Use the signed envelope id, or a digest
// computed over the canonical signing bytes — what stripUnsignedTopLevel followed
// by canonical produces — for any of those purposes.
//
// Two checks, deliberately belt-and-braces: Strict() rejects non-zero padding
// bits, and the re-encode equality check rejects anything else that is not the
// canonical text — including a form Strict happens not to catch. wantLen pins
// the exact decoded length so a short or long value cannot slip through as
// "valid base64".
func DecodeCanonicalBase64(encoded string, wantLen int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("ssp: not canonical base64url: %w", err)
	}
	if len(decoded) != wantLen {
		return nil, fmt.Errorf("ssp: decoded %d bytes, want %d", len(decoded), wantLen)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("ssp: base64url encoding is not canonical")
	}
	return decoded, nil
}

// decodeAndValidate applies every check that precedes signature verification:
// the raw guards, literal-member decoding, and family validation. Verify and
// EnvelopeCommitment share it so a commitment can never be computed for an
// envelope the verifier would refuse before its key lookup.
func decodeAndValidate(raw []byte, now time.Time) (Envelope, error) {
	e, err := decodeStrictEnvelope(raw)
	if err != nil {
		return Envelope{}, invalidEnvelope(err)
	}
	if err := e.Validate(now); err != nil {
		return Envelope{}, invalidEnvelope(err)
	}
	return e, nil
}

func Verify(raw []byte, keys map[string]identity.Ed25519VerifyingKey, now time.Time) (Envelope, error) {
	e, err := decodeAndValidate(raw, now)
	if err != nil {
		return Envelope{}, err
	}
	sig, err := DecodeCanonicalBase64(e.Signature, ed25519.SignatureSize)
	if err != nil {
		return Envelope{}, errors.New("ssp: invalid signature")
	}
	unsigned, err := stripUnsignedTopLevel(raw)
	if err != nil {
		return Envelope{}, invalidEnvelope(err)
	}
	c, err := canonical(unsigned)
	if err != nil {
		return Envelope{}, invalidEnvelope(err)
	}
	key, ok := keys[e.AuthorKeyID]
	if !ok {
		return Envelope{}, errors.New("ssp: author key is unknown")
	}
	pk, err := key.PublicKey()
	if err != nil || !ed25519.Verify(pk, c, sig) {
		return Envelope{}, errors.New("ssp: signature verification failed")
	}
	return e, nil
}

var envelopeCommonRequiredMembers = []string{
	"schema", "id", "emitted_at", "expires_at", "routing_epoch",
	"registry_revision", "author_key_id", "signature_alg", "body", "signature",
}

// decodeStrictEnvelope rejects every ambiguity that encoding/json's
// case-insensitive struct matching would otherwise accept. It deliberately
// validates literal JSON member names, presence, and nullability before
// constructing the typed Envelope used by family validation.
func decodeStrictEnvelope(raw []byte) (Envelope, error) {
	if err := rawGuard(raw); err != nil {
		return Envelope{}, err
	}
	members, err := exactObject(raw, "envelope")
	if err != nil {
		return Envelope{}, err
	}
	schema, err := requiredString(members, "schema", "envelope")
	if err != nil {
		return Envelope{}, err
	}
	required := append([]string{}, envelopeCommonRequiredMembers...)
	switch schema {
	case FamilyCase, FamilyAdvice:
		required = append(required, "case_id", "registry_hash")
	case FamilyRegistry:
		for _, forbidden := range []string{"case_id", "registry_hash"} {
			if _, present := members[forbidden]; present {
				return Envelope{}, fmt.Errorf("ssp: %s is forbidden for %s", forbidden, FamilyRegistry)
			}
		}
	default:
		return Envelope{}, ErrUnknownFamily
	}
	allowed := memberSet(required)
	if err := requireExactMembers(members, allowed, required, "envelope"); err != nil {
		return Envelope{}, err
	}
	routingEpoch, err := requiredNonNegativeInteger(members, "routing_epoch", "envelope")
	if err != nil {
		return Envelope{}, err
	}
	registryRevision, err := requiredNonNegativeInteger(members, "registry_revision", "envelope")
	if err != nil {
		return Envelope{}, err
	}

	e := Envelope{
		Schema:           schema,
		RoutingEpoch:     routingEpoch,
		RegistryRevision: registryRevision,
	}
	for _, field := range []struct {
		name   string
		target *string
	}{
		{"id", &e.ID},
		{"emitted_at", &e.EmittedAt},
		{"expires_at", &e.ExpiresAt},
		{"author_key_id", &e.AuthorKeyID},
		{"signature_alg", &e.SignatureAlg},
		{"signature", &e.Signature},
	} {
		value, err := requiredString(members, field.name, "envelope")
		if err != nil {
			return Envelope{}, err
		}
		*field.target = value
	}
	if schema != FamilyRegistry {
		for _, field := range []struct {
			name   string
			target *string
		}{
			{"case_id", &e.CaseID},
			{"registry_hash", &e.RegistryHash},
		} {
			value, err := requiredString(members, field.name, "envelope")
			if err != nil {
				return Envelope{}, err
			}
			*field.target = value
		}
	}
	e.Body = append(json.RawMessage(nil), members["body"]...)
	return e, nil
}

func memberSet(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

func exactObject(raw []byte, label string) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("ssp: %s must be an object", label)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil || members == nil {
		if err != nil {
			return nil, fmt.Errorf("ssp: invalid %s: %w", label, err)
		}
		return nil, fmt.Errorf("ssp: %s must be an object", label)
	}
	return members, nil
}

func requireExactMembers(members map[string]json.RawMessage, allowed map[string]struct{}, required []string, label string) error {
	for name := range members {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("%w: %s member %q", ErrUnknownField, label, name)
		}
	}
	for _, name := range required {
		if _, ok := members[name]; !ok {
			return fmt.Errorf("ssp: %s missing required member %q", label, name)
		}
		if bytes.Equal(bytes.TrimSpace(members[name]), []byte("null")) {
			return fmt.Errorf("ssp: %s required member %q is null", label, name)
		}
	}
	return nil
}

func requiredString(members map[string]json.RawMessage, name, label string) (string, error) {
	raw, ok := members[name]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("ssp: %s required member %q is missing or null", label, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("ssp: %s member %q must be a string", label, name)
	}
	return value, nil
}

func requiredNonNegativeInteger(members map[string]json.RawMessage, name, label string) (int64, error) {
	raw, ok := members[name]
	text := string(bytes.TrimSpace(raw))
	if !ok || text == "null" {
		return 0, fmt.Errorf("ssp: %s required member %q is missing or null", label, name)
	}
	if !regexp.MustCompile(`^(-?0|[1-9][0-9]*)$`).MatchString(text) {
		return 0, fmt.Errorf("ssp: %s member %q must be a non-negative integer", label, name)
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value > 1<<53-1 {
		return 0, fmt.Errorf("ssp: %s member %q is outside the safe integer range", label, name)
	}
	return value, nil
}

func (e Envelope) Validate(now time.Time) error {
	switch e.Schema {
	case FamilyCase, FamilyAdvice, FamilyRegistry:
	default:
		return ErrUnknownFamily
	}
	if !validOpaqueID(e.ID) || !validOpaqueID(e.AuthorKeyID) || e.SignatureAlg != "ed25519" || len(e.Body) == 0 {
		return errors.New("ssp: missing required field")
	}
	// Header shape is family-specific.  case/advice bind to exactly one case
	// and commit to one accepted registry snapshot; registry is
	// case-independent and must not commit to its own hash.
	if e.Schema == FamilyRegistry {
		if e.CaseID != "" {
			return errors.New("ssp: case_id is forbidden for ssp.registry.v1")
		}
		if e.RegistryHash != "" {
			return errors.New("ssp: registry_hash is forbidden for ssp.registry.v1")
		}
	} else if !validOpaqueID(e.CaseID) || e.RegistryHash == "" {
		return errors.New("ssp: missing required field")
	}
	emitted, err := ParseTimestamp(e.EmittedAt)
	if err != nil {
		return errors.New("ssp: invalid emitted_at")
	}
	expires, err := ParseTimestamp(e.ExpiresAt)
	if err != nil {
		return errors.New("ssp: invalid expires_at")
	}
	if emitted.After(now) {
		return errors.New("ssp: emitted_at is in the future")
	}
	if !expires.After(now) {
		return ErrExpiredEnvelope
	}
	if !expires.After(emitted) {
		return errors.New("ssp: invalid time range")
	}
	if e.RoutingEpoch < 0 || e.RegistryRevision < 0 || e.RoutingEpoch > 1<<53-1 || e.RegistryRevision > 1<<53-1 {
		return errors.New("ssp: invalid revision")
	}
	if e.Schema != FamilyRegistry && !sha256HexPattern.MatchString(e.RegistryHash) {
		return errors.New("ssp: invalid registry_hash")
	}
	if err := validateNumbers(e.Body); err != nil {
		return err
	}
	return validateBody(e)
}

func invalidEnvelope(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
}

var timestampV1 = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`)

// ParseTimestamp accepts the one SSP v1 timestamp grammar. It rejects
// alternate RFC3339 spellings before time.Parse can normalize them.
func ParseTimestamp(value string) (time.Time, error) {
	if !timestampV1.MatchString(value) || value[:4] == "0000" {
		return time.Time{}, errors.New("ssp: invalid timestamp grammar")
	}
	return time.Parse(time.RFC3339, value)
}

func validOpaqueID(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= 1 && length <= 512
}

func validateNumbers(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("ssp: invalid body: %w", err)
	}
	var walk func(any) error
	walk = func(v any) error {
		switch value := v.(type) {
		case json.Number:
			text := value.String()
			if strings.ContainsAny(text, ".eE") {
				return errors.New("ssp: floating-point numbers are not allowed")
			}
			n, err := strconv.ParseInt(text, 10, 64)
			if err != nil || n < -(1<<53-1) || n > 1<<53-1 {
				return errors.New("ssp: integer exceeds safe range")
			}
		case []any:
			for _, item := range value {
				if err := walk(item); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, item := range value {
				if err := walk(item); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func validateBody(e Envelope) error {
	switch e.Schema {
	case FamilyRegistry:
		return validateRegistryBody(e)
	case FamilyCase, FamilyAdvice:
		return validateCaseAdviceBody(e.Schema, e.Body)
	default:
		return ErrUnknownFamily
	}
}

func validateCaseAdviceBody(schema string, raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("ssp: invalid UTF-8 body")
	}
	members, err := exactObject(raw, schema+" body")
	if err != nil {
		return err
	}
	switch schema {
	case FamilyCase:
		required := []string{"domain", "issuer_edge_id", "issuer_edge_generation", "summary", "public_summary", "context_manifest"}
		if err := requireExactMembers(members, memberSet(required), required, schema+" body"); err != nil {
			return err
		}
		domain, err := requiredString(members, "domain", schema+" body")
		if err != nil {
			return err
		}
		issuerEdgeID, err := requiredString(members, "issuer_edge_id", schema+" body")
		if err != nil {
			return err
		}
		issuerEdgeGeneration, err := requiredNonNegativeInteger(members, "issuer_edge_generation", schema+" body")
		if err != nil || issuerEdgeGeneration == 0 {
			return errors.New("ssp: invalid ssp.case.v1 body")
		}
		summary, err := requiredString(members, "summary", schema+" body")
		if err != nil {
			return err
		}
		publicSummary, err := requiredString(members, "public_summary", schema+" body")
		if err != nil {
			return err
		}
		contextManifest, err := requiredString(members, "context_manifest", schema+" body")
		if err != nil {
			return err
		}
		summaryLength := utf8.RuneCountInString(summary)
		publicSummaryLength := utf8.RuneCountInString(publicSummary)
		if !validOpaqueID(domain) || !validOpaqueID(issuerEdgeID) || summaryLength == 0 || summaryLength > 4096 || publicSummaryLength == 0 || publicSummaryLength > 1024 || !sha256HexPattern.MatchString(contextManifest) {
			return errors.New("ssp: invalid ssp.case.v1 body")
		}
	case FamilyAdvice:
		required := []string{"case_commitment", "text", "public_summary"}
		if err := requireExactMembers(members, memberSet(required), required, schema+" body"); err != nil {
			return err
		}
		caseCommitment, err := requiredString(members, "case_commitment", schema+" body")
		if err != nil {
			return err
		}
		text, err := requiredString(members, "text", schema+" body")
		if err != nil {
			return err
		}
		publicSummary, err := requiredString(members, "public_summary", schema+" body")
		if err != nil {
			return err
		}
		textLength := utf8.RuneCountInString(text)
		publicSummaryLength := utf8.RuneCountInString(publicSummary)
		if !sha256HexPattern.MatchString(caseCommitment) || textLength == 0 || textLength > 8192 || publicSummaryLength == 0 || publicSummaryLength > 1024 {
			return errors.New("ssp: invalid ssp.advice.v1 body")
		}
	default:
		return ErrUnknownFamily
	}
	return nil
}

// stripUnsignedTopLevel removes only signature while preserving every other
// received JSON value byte-for-byte. JCS then canonicalizes that reconstructed
// object; no signed value passes through a Go representation.
func stripUnsignedTopLevel(raw []byte) ([]byte, error) {
	i := skipSpace(raw, 0)
	if i >= len(raw) || raw[i] != '{' {
		return nil, errors.New("ssp: envelope root must be an object")
	}
	i++
	var kept [][]byte
	for {
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return nil, errors.New("ssp: malformed JSON")
		}
		if raw[i] == '}' {
			break
		}
		memberStart := i
		keyEnd, err := stringEnd(raw, i)
		if err != nil {
			return nil, err
		}
		var key string
		if err := json.Unmarshal(raw[i:keyEnd], &key); err != nil {
			return nil, err
		}
		i = skipSpace(raw, keyEnd)
		if i >= len(raw) || raw[i] != ':' {
			return nil, errors.New("ssp: malformed JSON")
		}
		i = skipSpace(raw, i+1)
		valueEnd, err := valueEnd(raw, i)
		if err != nil {
			return nil, err
		}
		if key != "signature" {
			member := make([]byte, valueEnd-memberStart)
			copy(member, raw[memberStart:valueEnd])
			kept = append(kept, member)
		}
		i = skipSpace(raw, valueEnd)
		if i < len(raw) && raw[i] == ',' {
			i++
			continue
		}
		if i < len(raw) && raw[i] == '}' {
			break
		}
		return nil, errors.New("ssp: malformed JSON")
	}
	return append(append([]byte{'{'}, bytes.Join(kept, []byte{','})...), '}'), nil
}

func skipSpace(raw []byte, i int) int {
	for i < len(raw) && bytes.ContainsRune([]byte(" \t\r\n"), rune(raw[i])) {
		i++
	}
	return i
}
func stringEnd(raw []byte, start int) (int, error) {
	if start >= len(raw) || raw[start] != '"' {
		return 0, errors.New("ssp: malformed JSON string")
	}
	escaped := false
	for i := start + 1; i < len(raw); i++ {
		if escaped {
			escaped = false
			continue
		}
		if raw[i] == '\\' {
			escaped = true
			continue
		}
		if raw[i] == '"' {
			return i + 1, nil
		}
	}
	return 0, errors.New("ssp: unterminated JSON string")
}
func valueEnd(raw []byte, start int) (int, error) {
	if start >= len(raw) {
		return 0, errors.New("ssp: missing JSON value")
	}
	if raw[start] == '"' {
		return stringEnd(raw, start)
	}
	if raw[start] == '{' || raw[start] == '[' {
		stack := []byte{raw[start]}
		inString := false
		escaped := false
		for i := start + 1; i < len(raw); i++ {
			c := raw[i]
			if inString {
				if escaped {
					escaped = false
				} else if c == '\\' {
					escaped = true
				} else if c == '"' {
					inString = false
				}
				continue
			}
			if c == '"' {
				inString = true
				continue
			}
			if c == '{' || c == '[' {
				stack = append(stack, c)
			} else if c == '}' || c == ']' {
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					return i + 1, nil
				}
			}
		}
		return 0, errors.New("ssp: unterminated JSON container")
	}
	i := start
	for i < len(raw) && raw[i] != ',' && raw[i] != '}' && raw[i] != ']' && raw[i] != ' ' && raw[i] != '\t' && raw[i] != '\r' && raw[i] != '\n' {
		i++
	}
	if i == start {
		return 0, errors.New("ssp: missing JSON value")
	}
	return i, nil
}
