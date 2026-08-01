package edgeclient

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientClaimsAndAcknowledgesOnlyThroughVersionedUnixAPI(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "slc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/fronts/cli/claims", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type=%q", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deliveries":[{"case_id":"case-1","advice_id":"advice-1","message_id":"snagline.cli.advice.v1/advice-1","text":"inert","claim_token":"claim"}]}`))
	})
	mux.HandleFunc("POST /v1/fronts/cli/acks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"outcome":"recorded"}`))
	})
	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	client, err := New(Config{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := client.Claim(context.Background(), ClaimRequest{Front: FrontCLI, Owner: "front", LeaseTTL: time.Minute, Limit: 1})
	if err != nil || len(deliveries) != 1 || deliveries[0].Text != "inert" {
		t.Fatalf("claim = %#v, %v", deliveries, err)
	}
	outcome, err := client.Ack(context.Background(), AckRequest{Front: FrontCLI, MessageID: deliveries[0].MessageID, ClaimToken: deliveries[0].ClaimToken, ReceiptID: "cli-render/v1/" + deliveries[0].MessageID})
	if err != nil || outcome != DeliveryRecorded {
		t.Fatalf("ack = %q, %v", outcome, err)
	}
}

func TestClientRejectsUnsafeSocketAndInvalidLocalInputsBeforeNetwork(t *testing.T) {
	for _, cfg := range []Config{{}, {Socket: "relative.sock"}, {Socket: "/tmp/../tmp/edge.sock"}} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("accepted unsafe config %#v", cfg)
		}
	}
	client, err := New(Config{Socket: "/tmp/edge.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Claim(context.Background(), ClaimRequest{Front: "bad", Owner: "front", LeaseTTL: time.Minute, Limit: 1}); err == nil {
		t.Fatal("accepted unknown front")
	}
	if _, err := client.Claim(context.Background(), ClaimRequest{Front: FrontCLI, Owner: "front", LeaseTTL: time.Minute, Limit: 7}); err == nil {
		t.Fatal("accepted response-unbounded claim limit")
	}
	if _, err := client.Ack(context.Background(), AckRequest{Front: FrontCLI, MessageID: "", ClaimToken: "claim", ReceiptID: "receipt"}); err == nil {
		t.Fatal("accepted incomplete acknowledgement")
	}
}

func TestClientRejectsNonJSONEdgeResponses(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "slc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"deliveries":[]}`))
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	client, err := New(Config{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Claim(context.Background(), ClaimRequest{Front: FrontCLI, Owner: "front", LeaseTTL: time.Minute, Limit: 1}); err == nil {
		t.Fatal("accepted a response without application/json content type")
	}
}

func TestClientAcceptsBoundedWorstCaseEscapedClaimResponse(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "slc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := struct {
			Deliveries []Delivery `json:"deliveries"`
		}{Deliveries: make([]Delivery, 6)}
		for i := range response.Deliveries {
			response.Deliveries[i] = Delivery{CaseID: "case", AdviceID: "advice", MessageID: "message", ClaimToken: "claim", Text: strings.Repeat("\"", 8192)}
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	client, err := New(Config{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := client.Claim(context.Background(), ClaimRequest{Front: FrontCLI, Owner: "front", LeaseTTL: time.Minute, Limit: 6})
	if err != nil || len(deliveries) != 6 {
		t.Fatalf("claim count=%d err=%v", len(deliveries), err)
	}
}

func TestClientRejectsOversizeResponseEvenWhenExcessIsWhitespace(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "slc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deliveries":[]}` + strings.Repeat(" ", maxResponseBodyBytes)))
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	client, err := New(Config{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Claim(context.Background(), ClaimRequest{Front: FrontCLI, Owner: "front", LeaseTTL: time.Minute, Limit: 1}); err == nil {
		t.Fatal("accepted an oversized response with trailing whitespace")
	}
}
