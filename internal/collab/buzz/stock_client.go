package buzz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
)

const (
	stockNIP98Kind        = 27235
	stockMaxWireBytes     = 1 << 20
	stockMaxResponseBytes = stockMaxWireBytes + (64 << 10)
	stockMaxJSONDepth     = 64
	stockRequestTimeout   = 15 * time.Second
	// Stock Buzz admits events only inside its pinned +/-15-minute window.
	// Staying one minute inside that boundary avoids a write that can cross
	// the relay cutoff while preserving an immutable prepared event.
	stockPublishHorizon    = 14 * time.Minute
	stockResolveEventLimit = 2
)

var (
	ErrPublishOutcomeUnknown = errors.New("collab buzz: publish outcome unknown")
	ErrPublishConflict       = errors.New("collab buzz: resolved event conflicts with prepared wire")
	ErrPreparedExpiredAbsent = errors.New("collab buzz: prepared event expired and is absent")
	errNIP98Sign             = errors.New("collab buzz: NIP-98 signing failed")
	errPublishWindowClosed   = errors.New("collab buzz: immutable event publish window closed")
	errStockResponseTooLarge = errors.New("collab buzz: relay response exceeds size limit")
)

// StockRelayConfig configures the narrow stock-Buzz HTTP publisher. RelayURL
// is a relay root, not an endpoint. Plain HTTP is intentionally available only
// through the conspicuously named local-test escape hatch.
type StockRelayConfig struct {
	RelayURL                  string
	Signer                    DigestSigner
	HTTPClient                *http.Client
	Clock                     func() time.Time
	AllowInsecureHTTPForTests bool
}

// StockRelayClient implements only RelayClient. Its private HTTP /query use is
// limited to exact-ID reconciliation after an ambiguous publish outcome. Stock
// Buzz v0.5.2 returns the raw signed Nostr Event on that bridge; its CLI strips
// sig only while formatting human-facing reads. This client exposes no inbound
// scan, subscription, cursor, wake, or backfill surface.
type StockRelayClient struct {
	httpClient   *http.Client
	httpBase     *url.URL
	signer       DigestSigner
	signerPubKey string
	clock        func() time.Time
}

var _ RelayClient = (*StockRelayClient)(nil)

func NewStockRelayClient(config StockRelayConfig) (*StockRelayClient, error) {
	root, err := parseStockRelayRoot(config.RelayURL, config.AllowInsecureHTTPForTests)
	if err != nil {
		return nil, err
	}
	if config.Signer == nil {
		return nil, errors.New("collab buzz: relay signer is required")
	}
	publicKey := config.Signer.PublicKey()
	publicKeyBytes, err := decodeStockHex(publicKey, schnorr.PubKeyBytesLen, "relay signer pubkey")
	if err != nil {
		return nil, err
	}
	if _, err := schnorr.ParsePubKey(publicKeyBytes); err != nil {
		return nil, errors.New("collab buzz: relay signer pubkey is invalid")
	}

	var httpClient http.Client
	if config.HTTPClient != nil {
		httpClient = *config.HTTPClient
	}
	if httpClient.Timeout <= 0 || httpClient.Timeout > stockRequestTimeout {
		httpClient.Timeout = stockRequestTimeout
	}
	// Do not attach ambient cookies to a credentialed relay request, and do
	// not allow a redirect to replay its body or NIP-98 authorization.
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &StockRelayClient{
		httpClient:   &httpClient,
		httpBase:     root,
		signer:       config.Signer,
		signerPubKey: publicKey,
		clock:        clock,
	}, nil
}

func parseStockRelayRoot(raw string, allowHTTPForTests bool) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return nil, errors.New("collab buzz: relay URL is required without surrounding whitespace")
	}
	root, err := url.Parse(raw)
	if err != nil ||
		root.Opaque != "" ||
		root.Host == "" ||
		root.Hostname() == "" ||
		root.User != nil ||
		root.RawQuery != "" ||
		root.ForceQuery ||
		root.Fragment != "" ||
		root.RawFragment != "" ||
		root.RawPath != "" ||
		(root.Path != "" && root.Path != "/") {
		return nil, errors.New("collab buzz: relay URL must be an absolute root without credentials, path, query, or fragment")
	}
	switch strings.ToLower(root.Scheme) {
	case "https":
		root.Scheme = "https"
	case "http":
		if !allowHTTPForTests {
			return nil, errors.New("collab buzz: relay URL must use HTTPS")
		}
		root.Scheme = "http"
	default:
		return nil, errors.New("collab buzz: relay URL must use HTTPS")
	}
	root.Path = ""
	return root, nil
}

func (c *StockRelayClient) Publish(ctx context.Context, wire []byte) error {
	if c == nil {
		return errors.New("collab buzz: nil stock relay client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	event, err := c.validatePreparedWire(wire)
	if err != nil {
		return err
	}
	writeDeadline := time.Unix(event.CreatedAt, 0).UTC().Add(stockPublishHorizon)
	if !c.clock().UTC().Before(writeDeadline) {
		// A prior process may have attempted this persisted wire while it was
		// fresh. Never POST stale bytes; resolve only this exact signed ID.
		return c.reconcilePublish(ctx, event, errPublishWindowClosed)
	}

	body, status, contentType, attempted, err := c.post(ctx, "/events", wire, writeDeadline)
	if err != nil {
		if errors.Is(err, errPublishWindowClosed) {
			return c.reconcilePublish(ctx, event, err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			if attempted {
				return fmt.Errorf("%w: %w", ErrPublishOutcomeUnknown, ctxErr)
			}
			return ctxErr
		}
		if !attempted {
			return err
		}
		return c.reconcilePublish(ctx, event, err)
	}
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		response, err := decodeStockPublishResponse(body, contentType)
		if err == nil && response.Accepted && response.EventID == event.ID {
			return nil
		}
		if err == nil {
			err = errors.New("collab buzz: relay did not acknowledge the exact event")
		}
		return c.reconcilePublish(ctx, event, err)
	}
	if status == http.StatusConflict || status >= http.StatusInternalServerError {
		return c.reconcilePublish(ctx, event, stockStatusError("publish", status))
	}
	return stockStatusError("publish", status)
}

func (c *StockRelayClient) validatePreparedWire(wire []byte) (nostrEvent, error) {
	if err := c.requireStableSigner(); err != nil {
		return nostrEvent{}, err
	}
	event, err := decodeStockEvent(wire)
	if err != nil {
		return nostrEvent{}, err
	}
	if event.Kind != stockBuzzMessageKind {
		return nostrEvent{}, errors.New("collab buzz: unsupported prepared event kind")
	}
	if event.PubKey != c.signerPubKey {
		return nostrEvent{}, errors.New("collab buzz: prepared event author differs from NIP-98 signer")
	}
	if _, err := stockEventChannel(event); err != nil {
		return nostrEvent{}, err
	}
	return event, nil
}

func (c *StockRelayClient) requireStableSigner() error {
	if c.signer.PublicKey() != c.signerPubKey {
		return errors.New("collab buzz: relay signer public key drifted")
	}
	return nil
}

type stockPublishResponse struct {
	EventID  string `json:"event_id"`
	Accepted bool   `json:"accepted"`
	Message  string `json:"message"`
}

func decodeStockPublishResponse(body []byte, contentType string) (stockPublishResponse, error) {
	if err := requireStockJSONContentType(contentType); err != nil {
		return stockPublishResponse{}, err
	}
	fields, err := decodeStockObject(body, []string{"event_id", "accepted", "message"})
	if err != nil {
		return stockPublishResponse{}, errors.New("collab buzz: invalid publish response")
	}
	var response stockPublishResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return stockPublishResponse{}, errors.New("collab buzz: invalid publish response")
	}
	if _, ok := fields["event_id"]; !ok {
		return stockPublishResponse{}, errors.New("collab buzz: publish response is missing event_id")
	}
	if _, ok := fields["accepted"]; !ok {
		return stockPublishResponse{}, errors.New("collab buzz: publish response is missing accepted")
	}
	if _, ok := fields["message"]; !ok {
		return stockPublishResponse{}, errors.New("collab buzz: publish response is missing message")
	}
	if _, err := decodeStockHex(response.EventID, sha256.Size, "publish response event id"); err != nil {
		return stockPublishResponse{}, err
	}
	return response, nil
}

func (c *StockRelayClient) reconcilePublish(ctx context.Context, prepared nostrEvent, publishErr error) error {
	channel, err := stockEventChannel(prepared)
	if err != nil {
		return err
	}
	resolved, found, err := c.resolveExactID(ctx, prepared.ID, channel)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("%w: %w", ErrPublishOutcomeUnknown, ctxErr)
		}
		return fmt.Errorf("%w: %v", ErrPublishOutcomeUnknown, err)
	}
	if !found {
		if errors.Is(publishErr, errPublishWindowClosed) {
			return ErrPreparedExpiredAbsent
		}
		if publishErr != nil {
			return fmt.Errorf("%w: %v", ErrPublishOutcomeUnknown, publishErr)
		}
		return ErrPublishOutcomeUnknown
	}
	if !sameStockSignedEvent(prepared, resolved) {
		return ErrPublishConflict
	}
	return nil
}

type stockIDFilter struct {
	IDs      []string `json:"ids"`
	Kinds    []int    `json:"kinds"`
	Channels []string `json:"#h"`
	Limit    int      `json:"limit"`
}

func (c *StockRelayClient) resolveExactID(ctx context.Context, id, channel string) (nostrEvent, bool, error) {
	if _, err := decodeStockHex(id, sha256.Size, "event id"); err != nil {
		return nostrEvent{}, false, err
	}
	queryBody, err := marshalStockJSON([]stockIDFilter{{
		IDs: []string{id}, Kinds: []int{stockBuzzMessageKind},
		Channels: []string{channel}, Limit: stockResolveEventLimit,
	}})
	if err != nil {
		return nostrEvent{}, false, errors.New("collab buzz: encode exact-ID query failed")
	}
	body, status, contentType, _, err := c.post(ctx, "/query", queryBody, time.Time{})
	if err != nil {
		return nostrEvent{}, false, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nostrEvent{}, false, stockStatusError("resolve", status)
	}
	if err := requireStockJSONContentType(contentType); err != nil {
		return nostrEvent{}, false, err
	}
	if err := validateStockJSON(body); err != nil {
		return nostrEvent{}, false, errors.New("collab buzz: invalid exact-ID query response")
	}
	var events []json.RawMessage
	if err := json.Unmarshal(body, &events); err != nil {
		return nostrEvent{}, false, errors.New("collab buzz: exact-ID query response must be an array")
	}
	switch len(events) {
	case 0:
		return nostrEvent{}, false, nil
	case 1:
	default:
		return nostrEvent{}, false, errors.New("collab buzz: exact-ID query returned multiple events")
	}
	resolved, err := decodeStockEvent(events[0])
	if err != nil {
		return nostrEvent{}, false, err
	}
	if resolved.ID != id {
		return nostrEvent{}, false, errors.New("collab buzz: exact-ID query returned a different event")
	}
	return resolved, true, nil
}

func stockEventChannel(event nostrEvent) (string, error) {
	channel := ""
	for _, tag := range event.Tags {
		if len(tag) == 0 || tag[0] != "h" {
			continue
		}
		if len(tag) != 2 || channel != "" {
			return "", errors.New("collab buzz: prepared event must have exactly one channel tag")
		}
		parsed, err := uuid.Parse(tag[1])
		if err != nil || parsed.String() != tag[1] {
			return "", errors.New("collab buzz: prepared event channel tag is not a canonical UUID")
		}
		channel = tag[1]
	}
	if channel == "" {
		return "", errors.New("collab buzz: prepared event must have exactly one channel tag")
	}
	return channel, nil
}

func sameStockSignedEvent(left, right nostrEvent) bool {
	if left.ID != right.ID ||
		left.PubKey != right.PubKey ||
		left.CreatedAt != right.CreatedAt ||
		left.Kind != right.Kind ||
		left.Content != right.Content ||
		left.Sig != right.Sig ||
		len(left.Tags) != len(right.Tags) {
		return false
	}
	for i := range left.Tags {
		if !slices.Equal(left.Tags[i], right.Tags[i]) {
			return false
		}
	}
	return true
}

func (c *StockRelayClient) post(ctx context.Context, path string, body []byte, writeDeadline time.Time) ([]byte, int, string, bool, error) {
	endpoint := *c.httpBase
	endpoint.Path = path
	authorization, err := c.nip98Authorization(ctx, endpoint.String(), body, writeDeadline)
	if err != nil {
		return nil, 0, "", false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", false, errors.New("collab buzz: build relay request failed")
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if stockDeadlineReached(c.clock().UTC(), writeDeadline) {
		return nil, 0, "", false, errPublishWindowClosed
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, "", true, ctxErr
		}
		return nil, 0, "", true, errors.New("collab buzz: relay request failed")
	}
	defer response.Body.Close()
	responseBody, err := readStockBounded(response.Body)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, response.StatusCode, response.Header.Get("Content-Type"), true, ctxErr
		}
		return nil, response.StatusCode, response.Header.Get("Content-Type"), true, err
	}
	return responseBody, response.StatusCode, response.Header.Get("Content-Type"), true, nil
}

func (c *StockRelayClient) nip98Authorization(ctx context.Context, endpoint string, body []byte, writeDeadline time.Time) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := c.requireStableSigner(); err != nil {
		return "", err
	}
	payload := sha256.Sum256(body)
	event := nostrEvent{
		PubKey:    c.signerPubKey,
		CreatedAt: c.clock().UTC().Unix(),
		Kind:      stockNIP98Kind,
		Tags: [][]string{
			{"u", endpoint},
			{"method", http.MethodPost},
			{"nonce", uuid.NewString()},
			{"payload", hex.EncodeToString(payload[:])},
		},
		Content: "",
	}
	digest, err := stockEventDigest(event)
	if err != nil {
		return "", err
	}
	event.ID = hex.EncodeToString(digest[:])
	signature, err := c.signer.SignDigest(ctx, digest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", errNIP98Sign
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	event.Sig = signature
	if stockDeadlineReached(c.clock().UTC(), writeDeadline) {
		return "", errPublishWindowClosed
	}
	if err := verifyStockEvent(event); err != nil {
		return "", errors.New("collab buzz: invalid NIP-98 signature")
	}
	wire, err := marshalStockJSON(event)
	if err != nil {
		return "", errors.New("collab buzz: encode NIP-98 event failed")
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(wire), nil
}

func stockDeadlineReached(now, deadline time.Time) bool {
	return !deadline.IsZero() && !now.Before(deadline)
}

func decodeStockEvent(wire []byte) (nostrEvent, error) {
	if len(wire) == 0 || len(wire) > stockMaxWireBytes {
		return nostrEvent{}, errors.New("collab buzz: prepared wire is empty or too large")
	}
	required := []string{"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
	if _, err := decodeStockObject(wire, required); err != nil {
		return nostrEvent{}, errors.New("collab buzz: invalid Nostr event object")
	}
	var event nostrEvent
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return nostrEvent{}, errors.New("collab buzz: invalid Nostr event object")
	}
	if event.CreatedAt < 0 || event.Tags == nil {
		return nostrEvent{}, errors.New("collab buzz: invalid Nostr event fields")
	}
	for _, tag := range event.Tags {
		if len(tag) == 0 {
			return nostrEvent{}, errors.New("collab buzz: empty Nostr event tag")
		}
	}
	if err := verifyStockEvent(event); err != nil {
		return nostrEvent{}, err
	}
	return event, nil
}

func verifyStockEvent(event nostrEvent) error {
	digest, err := stockEventDigest(event)
	if err != nil {
		return err
	}
	if event.ID != hex.EncodeToString(digest[:]) {
		return errors.New("collab buzz: Nostr event ID does not match signed fields")
	}
	publicKeyBytes, err := decodeStockHex(event.PubKey, schnorr.PubKeyBytesLen, "Nostr pubkey")
	if err != nil {
		return err
	}
	publicKey, err := schnorr.ParsePubKey(publicKeyBytes)
	if err != nil {
		return errors.New("collab buzz: invalid Nostr pubkey")
	}
	signatureBytes, err := decodeStockHex(event.Sig, schnorr.SignatureSize, "Nostr signature")
	if err != nil {
		return err
	}
	signature, err := schnorr.ParseSignature(signatureBytes)
	if err != nil || !signature.Verify(digest[:], publicKey) {
		return errors.New("collab buzz: invalid Nostr signature")
	}
	return nil
}

func stockEventDigest(event nostrEvent) ([sha256.Size]byte, error) {
	serialized, err := marshalStockJSON([]any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	if err != nil {
		return [sha256.Size]byte{}, errors.New("collab buzz: serialize Nostr event ID input failed")
	}
	serialized = stockUnescapeLineSeparators(serialized)
	return sha256.Sum256(serialized), nil
}

func stockUnescapeLineSeparators(serialized []byte) []byte {
	var normalized []byte
	for i := 0; i < len(serialized); i++ {
		if serialized[i] != '\\' ||
			i+5 >= len(serialized) ||
			serialized[i+1] != 'u' ||
			serialized[i+2] != '2' ||
			serialized[i+3] != '0' ||
			serialized[i+4] != '2' ||
			(serialized[i+5] != '8' && serialized[i+5] != '9') ||
			stockJSONBackslashEscaped(serialized, i) {
			if normalized != nil {
				normalized = append(normalized, serialized[i])
			}
			continue
		}
		if normalized == nil {
			normalized = make([]byte, 0, len(serialized))
			normalized = append(normalized, serialized[:i]...)
		}
		normalized = append(normalized, 0xe2, 0x80, 0xa8+serialized[i+5]-'8')
		i += 5
	}
	if normalized == nil {
		return serialized
	}
	return normalized
}

func stockJSONBackslashEscaped(serialized []byte, at int) bool {
	preceding := 0
	for i := at - 1; i >= 0 && serialized[i] == '\\'; i-- {
		preceding++
	}
	return preceding%2 != 0
}

func decodeStockHex(value string, size int, label string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != size || hex.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("collab buzz: %s must be %d bytes of lowercase hex", label, size)
	}
	return decoded, nil
}

func marshalStockJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func decodeStockObject(raw []byte, allowed []string) (map[string]json.RawMessage, error) {
	if err := validateStockJSON(raw); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, errors.New("collab buzz: JSON value must be an object")
	}
	if len(fields) != len(allowed) {
		return nil, errors.New("collab buzz: JSON object fields do not match contract")
	}
	for _, name := range allowed {
		if _, ok := fields[name]; !ok {
			return nil, errors.New("collab buzz: JSON object fields do not match contract")
		}
	}
	return fields, nil
}

func validateStockJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("collab buzz: JSON must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := walkStockJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("collab buzz: trailing JSON data")
	}
	return nil
}

func walkStockJSON(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("collab buzz: invalid JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= stockMaxJSONDepth {
		return errors.New("collab buzz: JSON nesting exceeds limit")
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errors.New("collab buzz: invalid JSON object key")
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("collab buzz: JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("collab buzz: duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := walkStockJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("collab buzz: unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkStockJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("collab buzz: unterminated JSON array")
		}
	default:
		return errors.New("collab buzz: unexpected JSON delimiter")
	}
	return nil
}

func requireStockJSONContentType(value string) error {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return errors.New("collab buzz: relay response is not application/json")
	}
	return nil
}

func stockStatusError(operation string, status int) error {
	return fmt.Errorf("collab buzz: relay %s failed with HTTP %d", operation, status)
}

func readStockBounded(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, int64(stockMaxResponseBytes)+1))
	if err != nil {
		return nil, errors.New("collab buzz: read relay response failed")
	}
	if len(body) > stockMaxResponseBytes {
		return nil, errStockResponseTooLarge
	}
	return body, nil
}
