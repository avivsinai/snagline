package buzz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestStockRelayClientRequiresTLSRootUnlessExplicitTestMode(t *testing.T) {
	signer := newStockTestSigner(t)
	for _, raw := range []string{
		"",
		"http://buzz.example",
		"https://user@buzz.example",
		"https://buzz.example/events",
		"https://buzz.example?query=1",
		"https://buzz.example#fragment",
		"wss://buzz.example",
	} {
		if client, err := NewStockRelayClient(StockRelayConfig{RelayURL: raw, Signer: signer}); err == nil || client != nil {
			t.Fatalf("NewStockRelayClient(%q)=(%v,%v), want nil/error", raw, client, err)
		}
	}
	if client, err := NewStockRelayClient(StockRelayConfig{
		RelayURL:                  "http://127.0.0.1:8080",
		Signer:                    signer,
		AllowInsecureHTTPForTests: true,
	}); err != nil || client == nil {
		t.Fatalf("explicit HTTP test mode=(%v,%v)", client, err)
	}
	if client, err := NewStockRelayClient(StockRelayConfig{
		RelayURL: "https://buzz.example/",
		Signer:   signer,
	}); err != nil || client == nil {
		t.Fatalf("TLS root=(%v,%v)", client, err)
	}
}

func TestStockRelayClientBoundsTimeoutAndDisablesRedirects(t *testing.T) {
	signer := newStockTestSigner(t)
	provided := &http.Client{Timeout: time.Hour}
	client, err := NewStockRelayClient(StockRelayConfig{
		RelayURL:   "https://buzz.example",
		Signer:     signer,
		HTTPClient: provided,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.httpClient == provided || client.httpClient.Timeout != stockRequestTimeout {
		t.Fatalf("HTTP client copy/timeout=%p/%v", client.httpClient, client.httpClient.Timeout)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://other.example", nil)
	if err := client.httpClient.CheckRedirect(request, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy=%v", err)
	}
}

func TestStockRelayClientPublishesExactPreparedBytesWithNIP98(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	wire := stockTestWire(t, signer.privateKey, now)
	var requests atomic.Int32
	var relay *httptest.Server
	relay = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/events" || r.Method != http.MethodPost {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
			http.Error(w, "wrong endpoint", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(body, wire) {
			t.Errorf("published bytes changed:\n got %s\nwant %s", body, wire)
		}
		assertStockNIP98(t, r, signer.publicKey, body, now)
		event := decodeStockTestEvent(t, wire)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"event_id":"`+event.ID+`","accepted":true,"message":""}`)
	}))
	defer relay.Close()

	client := newStockTestClient(t, relay, signer, now)
	if err := client.Publish(context.Background(), wire); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("successful publish made %d requests; /query is ambiguity-only", requests.Load())
	}
}

func TestStockPublishResponseRequiresStockThreeFieldContract(t *testing.T) {
	eventID := strings.Repeat("a", 64)
	if _, err := decodeStockPublishResponse(
		[]byte(`{"event_id":"`+eventID+`","accepted":true}`),
		"application/json",
	); err == nil {
		t.Fatal("accepted obsolete two-field publish response")
	}
	response, err := decodeStockPublishResponse(
		[]byte(`{"event_id":"`+eventID+`","accepted":true,"message":""}`),
		"application/json",
	)
	if err != nil || response.EventID != eventID || !response.Accepted || response.Message != "" {
		t.Fatalf("stock publish response = %#v, %v", response, err)
	}
}

func TestStockRelayClientReconcilesAmbiguousWriteByExactIDOnly(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	wire := stockTestWire(t, signer.privateKey, now)
	event := decodeStockTestEvent(t, wire)
	var events, queries atomic.Int32
	var relay *httptest.Server
	relay = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		assertStockNIP98(t, r, signer.publicKey, body, now)
		switch r.URL.Path {
		case "/events":
			events.Add(1)
			if !bytes.Equal(body, wire) {
				t.Errorf("publish bytes changed")
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server cannot hijack")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		case "/query":
			queries.Add(1)
			assertExactIDQuery(t, body, event.ID, "11111111-1111-1111-1111-111111111111")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append(append([]byte{'['}, wire...), ']'))
		default:
			http.Error(w, "wrong endpoint", http.StatusNotFound)
		}
	}))
	defer relay.Close()

	client := newStockTestClient(t, relay, signer, now)
	if err := client.Publish(context.Background(), wire); err != nil {
		t.Fatal(err)
	}
	if events.Load() != 1 || queries.Load() != 1 {
		t.Fatalf("requests events/query=%d/%d", events.Load(), queries.Load())
	}
}

func TestStockRelayClientBoundsResponseAndReturnsUnknownWhenUnresolved(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	wire := stockTestWire(t, signer.privateKey, now)
	event := decodeStockTestEvent(t, wire)
	var queried atomic.Bool
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/events":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"padding":"`+strings.Repeat("x", stockMaxResponseBytes+1)+`"}`)
		case "/query":
			queried.Store(true)
			assertExactIDQuery(t, body, event.ID, "11111111-1111-1111-1111-111111111111")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "[]")
		}
	}))
	defer relay.Close()

	client := newStockTestClient(t, relay, signer, now)
	err := client.Publish(context.Background(), wire)
	if !errors.Is(err, ErrPublishOutcomeUnknown) || !queried.Load() {
		t.Fatalf("oversize response=%v queried=%v", err, queried.Load())
	}
}

func TestStockRelayClientRejectsResolvedSignatureConflict(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	wire := stockTestWire(t, signer.privateKey, now)
	event := decodeStockTestEvent(t, wire)
	digest := stockTestDigest(t, event)
	var auxiliary [32]byte
	auxiliary[0] = 1
	alternate, err := schnorr.Sign(signer.privateKey, digest[:], schnorr.CustomNonce(auxiliary))
	if err != nil {
		t.Fatal(err)
	}
	event.Sig = hex.EncodeToString(alternate.Serialize())
	conflictWire := marshalStockTestJSON(t, event)

	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events":
			hijacker := w.(http.Hijacker)
			connection, _, _ := hijacker.Hijack()
			_ = connection.Close()
		case "/query":
			body, _ := io.ReadAll(r.Body)
			assertExactIDQuery(t, body, event.ID, "11111111-1111-1111-1111-111111111111")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append(append([]byte{'['}, conflictWire...), ']'))
		}
	}))
	defer relay.Close()

	client := newStockTestClient(t, relay, signer, now)
	if err := client.Publish(context.Background(), wire); !errors.Is(err, ErrPublishConflict) {
		t.Fatalf("conflict=%v", err)
	}
}

func TestStockRelayClientRejectsCLIFormattedSigStrippedQueryResponse(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	wire := stockTestWire(t, signer.privateKey, now)
	event := decodeStockTestEvent(t, wire)
	var formatted map[string]any
	if err := json.Unmarshal(wire, &formatted); err != nil {
		t.Fatal(err)
	}
	delete(formatted, "sig")
	formattedWire := marshalStockTestJSON(t, formatted)

	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events":
			hijacker := w.(http.Hijacker)
			connection, _, _ := hijacker.Hijack()
			_ = connection.Close()
		case "/query":
			body, _ := io.ReadAll(r.Body)
			assertExactIDQuery(t, body, event.ID, "11111111-1111-1111-1111-111111111111")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append(append([]byte{'['}, formattedWire...), ']'))
		}
	}))
	defer relay.Close()

	client := newStockTestClient(t, relay, signer, now)
	if err := client.Publish(context.Background(), wire); !errors.Is(err, ErrPublishOutcomeUnknown) {
		t.Fatalf("sig-stripped bridge response=%v", err)
	}
}

func TestStockRelayClientRejectsOversizeOrInvalidPreparedWireBeforeNetwork(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	var requests atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer relay.Close()
	client := newStockTestClient(t, relay, signer, now)

	if err := client.Publish(context.Background(), bytes.Repeat([]byte{'x'}, stockMaxWireBytes+1)); err == nil {
		t.Fatal("oversize prepared wire accepted")
	}
	wire := stockTestWire(t, signer.privateKey, now)
	var event nostrEvent
	if err := json.Unmarshal(wire, &event); err != nil {
		t.Fatal(err)
	}
	event.Content = "mutated after signing"
	if err := client.Publish(context.Background(), marshalStockTestJSON(t, event)); err == nil {
		t.Fatal("invalid event ID/signature accepted")
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid input made %d network requests", requests.Load())
	}
}

func TestStockRelayClientPastHorizonQueriesExactIDWithoutPostingStaleBytes(t *testing.T) {
	createdAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	wire := stockTestWire(t, signer.privateKey, createdAt)
	event := decodeStockTestEvent(t, wire)
	var events, queries atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/events":
			events.Add(1)
		case "/query":
			queries.Add(1)
			assertExactIDQuery(t, body, event.ID, "11111111-1111-1111-1111-111111111111")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append(append([]byte{'['}, wire...), ']'))
		}
	}))
	defer relay.Close()
	client := newStockTestClient(t, relay, signer, createdAt.Add(stockPublishHorizon))

	if err := client.Publish(context.Background(), wire); err != nil {
		t.Fatalf("past-horizon reconciliation=%v", err)
	}
	if events.Load() != 0 || queries.Load() != 1 {
		t.Fatalf("past-horizon requests events/query=%d/%d", events.Load(), queries.Load())
	}
}

func TestStockRelayClientPastHorizonReturnsTypedAbsentResult(t *testing.T) {
	createdAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer := newStockTestSigner(t)
	wire := stockTestWire(t, signer.privateKey, createdAt)
	event := decodeStockTestEvent(t, wire)
	var events atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/events":
			events.Add(1)
		case "/query":
			assertExactIDQuery(t, body, event.ID, "11111111-1111-1111-1111-111111111111")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "[]")
		}
	}))
	defer relay.Close()
	client := newStockTestClient(t, relay, signer, createdAt.Add(stockPublishHorizon))

	if err := client.Publish(context.Background(), wire); !errors.Is(err, ErrPreparedExpiredAbsent) {
		t.Fatalf("past-horizon absent error = %v", err)
	}
	if events.Load() != 0 {
		t.Fatal("past-horizon absent reconciliation posted stale bytes")
	}
}

type stockTestSigner struct {
	privateKey *btcec.PrivateKey
	publicKey  string
}

func newStockTestSigner(t *testing.T) *stockTestSigner {
	t.Helper()
	raw := make([]byte, 32)
	raw[31] = 1
	privateKey, publicKey := btcec.PrivKeyFromBytes(raw)
	return &stockTestSigner{
		privateKey: privateKey,
		publicKey:  hex.EncodeToString(schnorr.SerializePubKey(publicKey)),
	}
}

func (s *stockTestSigner) PublicKey() string { return s.publicKey }
func (s *stockTestSigner) SignDigest(ctx context.Context, digest [32]byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	signature, err := schnorr.Sign(s.privateKey, digest[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature.Serialize()), nil
}

func newStockTestClient(t *testing.T, relay *httptest.Server, signer DigestSigner, now time.Time) *StockRelayClient {
	t.Helper()
	client, err := NewStockRelayClient(StockRelayConfig{
		RelayURL:                  relay.URL,
		Signer:                    signer,
		HTTPClient:                relay.Client(),
		Clock:                     func() time.Time { return now },
		AllowInsecureHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func stockTestWire(t *testing.T, privateKey *btcec.PrivateKey, now time.Time, options ...schnorr.SignOption) []byte {
	t.Helper()
	event := nostrEvent{
		PubKey:    hex.EncodeToString(schnorr.SerializePubKey(privateKey.PubKey())),
		CreatedAt: now.Unix(),
		Kind:      stockBuzzMessageKind,
		Tags:      [][]string{{"h", "11111111-1111-1111-1111-111111111111"}},
		Content:   `{"family":"case","summary":"redacted"}`,
	}
	digest := stockTestDigest(t, event)
	event.ID = hex.EncodeToString(digest[:])
	signature, err := schnorr.Sign(privateKey, digest[:], options...)
	if err != nil {
		t.Fatal(err)
	}
	event.Sig = hex.EncodeToString(signature.Serialize())
	return marshalStockTestJSON(t, event)
}

func stockTestDigest(t *testing.T, event nostrEvent) [32]byte {
	t.Helper()
	serialized := marshalStockTestJSON(t, []any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	serialized = bytes.ReplaceAll(serialized, []byte(`\u2028`), []byte("\u2028"))
	serialized = bytes.ReplaceAll(serialized, []byte(`\u2029`), []byte("\u2029"))
	return sha256.Sum256(serialized)
}

func marshalStockTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
}

func decodeStockTestEvent(t *testing.T, wire []byte) nostrEvent {
	t.Helper()
	var event nostrEvent
	if err := json.Unmarshal(wire, &event); err != nil {
		t.Fatal(err)
	}
	return event
}

func assertStockNIP98(t *testing.T, request *http.Request, publicKey string, body []byte, now time.Time) {
	t.Helper()
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Nostr ") {
		t.Errorf("authorization=%q", header)
		return
	}
	wire, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Nostr "))
	if err != nil {
		t.Error(err)
		return
	}
	event := decodeStockTestEvent(t, wire)
	digest := stockTestDigest(t, event)
	if event.ID != hex.EncodeToString(digest[:]) || event.PubKey != publicKey || event.Kind != stockNIP98Kind || event.CreatedAt != now.Unix() || event.Content != "" {
		t.Errorf("NIP-98 event=%+v", event)
	}
	publicBytes, _ := hex.DecodeString(publicKey)
	key, err := schnorr.ParsePubKey(publicBytes)
	if err != nil {
		t.Error(err)
		return
	}
	signatureBytes, _ := hex.DecodeString(event.Sig)
	signature, err := schnorr.ParseSignature(signatureBytes)
	if err != nil || !signature.Verify(digest[:], key) {
		t.Errorf("NIP-98 signature valid=false err=%v", err)
	}
	tags := make(map[string]string)
	for _, tag := range event.Tags {
		if len(tag) != 2 {
			t.Errorf("NIP-98 tag=%q", tag)
			continue
		}
		tags[tag[0]] = tag[1]
	}
	payload := sha256.Sum256(body)
	authURL, err := url.Parse(tags["u"])
	if err != nil ||
		authURL.Scheme == "" ||
		authURL.Host != request.Host ||
		authURL.Path != request.URL.Path ||
		tags["method"] != http.MethodPost ||
		tags["payload"] != hex.EncodeToString(payload[:]) ||
		tags["nonce"] == "" {
		t.Errorf("NIP-98 tags=%v", tags)
	}
}

func assertExactIDQuery(t *testing.T, body []byte, id, channel string) {
	t.Helper()
	var filters []map[string]any
	if err := json.Unmarshal(body, &filters); err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 || len(filters[0]) != 4 {
		t.Fatalf("query=%s", body)
	}
	ids, ok := filters[0]["ids"].([]any)
	kinds, kindsOK := filters[0]["kinds"].([]any)
	channels, channelsOK := filters[0]["#h"].([]any)
	if !ok || len(ids) != 1 || ids[0] != id ||
		!kindsOK || len(kinds) != 1 || kinds[0] != float64(stockBuzzMessageKind) ||
		!channelsOK || len(channels) != 1 || channels[0] != channel ||
		filters[0]["limit"] != float64(stockResolveEventLimit) {
		t.Fatalf("query=%s", body)
	}
}
