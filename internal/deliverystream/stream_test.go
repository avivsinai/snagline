package deliverystream

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/ssp"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestStreamIsBoundedFileR3DeliveryAcceleration(t *testing.T) {
	config := StreamConfig()
	if config.Name != StreamName || config.Storage != jetstream.FileStorage || config.Replicas != ProductionReplicas {
		t.Fatalf("stream config = %#v", config)
	}
	if config.Discard != jetstream.DiscardOld || config.MaxAge <= 0 || config.MaxBytes <= 0 || config.MaxMsgSize != ssp.MaxEnvelopeBytes {
		t.Fatalf("stream bounds = %#v", config)
	}
	if want := []string{SubjectPrefix + ".>"}; !sameStrings(config.Subjects, want) {
		t.Fatalf("subjects = %v, want %v", config.Subjects, want)
	}
}

func TestPublishDeliversExactRawBytesWithOutboxDerivedMessageIDAndAuthorityHeaders(t *testing.T) {
	js := newTestJetStream(t)
	ctx := testContext(t)
	createTestStream(t, ctx, js)
	raw := []byte("{\n  \"signature\": \"unchanged\"\n}\n")
	request := PublishRequest{
		OutboxID:     "outbox-42",
		Destination:  DestinationDomain,
		TenantID:     "tenant/acme",
		DomainID:     "support/sre",
		RawSSP:       raw,
		FactSequence: 17,
	}
	first, err := Publish(ctx, js, request)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if first.Duplicate {
		t.Fatalf("first publish = %#v", first)
	}
	duplicate, err := Publish(ctx, js, request)
	if err != nil {
		t.Fatalf("publish duplicate: %v", err)
	}
	if !duplicate.Duplicate {
		t.Fatalf("duplicate publish = %#v", duplicate)
	}
	subject, err := SubjectFor(request)
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	message, err := mustStream(t, ctx, js).GetLastMsgForSubject(ctx, subject)
	if err != nil {
		t.Fatalf("message lookup: %v", err)
	}
	if !bytes.Equal(message.Data, raw) {
		t.Fatalf("stored bytes = %q, want %q", message.Data, raw)
	}
	if got, want := message.Header.Get("Nats-Msg-Id"), MessageID(request.OutboxID); got != want {
		t.Fatalf("message id = %q, want %q", got, want)
	}
	if got, want := message.Header.Get(HeaderOutboxID), request.OutboxID; got != want {
		t.Fatalf("outbox header = %q, want %q", got, want)
	}
	if got := message.Header.Get(HeaderFactSequence); got != strconv.FormatUint(request.FactSequence, 10) {
		t.Fatalf("fact sequence = %q", got)
	}
	if got := message.Header.Get(HeaderDeliverySequence); got != "" {
		t.Fatalf("domain wake carried delivery sequence = %q", got)
	}
	for _, opaque := range []string{request.TenantID, request.DomainID} {
		if strings.Contains(subject, opaque) {
			t.Fatalf("subject leaks opaque identifier: %q", subject)
		}
	}
}

func TestEdgePublishCarriesGenerationMetadata(t *testing.T) {
	js := newTestJetStream(t)
	ctx := testContext(t)
	createTestStream(t, ctx, js)
	request := PublishRequest{OutboxID: "outbox-edge-1", Destination: DestinationEdge, TenantID: "tenant/acme", EdgeID: "edge/123", EdgeGeneration: 4, RawSSP: []byte("signed"), FactSequence: 5, DeliverySequence: 2}
	if _, err := Publish(ctx, js, request); err != nil {
		t.Fatalf("publish edge wake: %v", err)
	}
	subject, err := SubjectFor(request)
	if err != nil {
		t.Fatalf("edge subject: %v", err)
	}
	message, err := mustStream(t, ctx, js).GetLastMsgForSubject(ctx, subject)
	if err != nil {
		t.Fatalf("edge message lookup: %v", err)
	}
	if got, want := message.Header.Get(HeaderEdgeGeneration), strconv.FormatUint(request.EdgeGeneration, 10); got != want {
		t.Fatalf("edge generation = %q, want %q", got, want)
	}
}

func TestEdgeDestinationIncludesGenerationInLengthPrefixedToken(t *testing.T) {
	base := PublishRequest{OutboxID: "outbox-1", Destination: DestinationEdge, TenantID: "tenant/acme", EdgeID: "edge/123", EdgeGeneration: 1, RawSSP: []byte("signed"), FactSequence: 1, DeliverySequence: 1}
	first, err := SubjectFor(base)
	if err != nil {
		t.Fatalf("first subject: %v", err)
	}
	base.EdgeGeneration = 2
	second, err := SubjectFor(base)
	if err != nil {
		t.Fatalf("second subject: %v", err)
	}
	if first == second || !strings.Contains(first, EdgeToken("edge/123", 1)) || !strings.Contains(second, EdgeToken("edge/123", 2)) {
		t.Fatalf("edge subjects do not bind generation: first=%q second=%q", first, second)
	}
}

func TestPublishRejectsIncompleteOrOversizedDeliveryRequests(t *testing.T) {
	valid := PublishRequest{OutboxID: "outbox-1", Destination: DestinationEdge, TenantID: "tenant", EdgeID: "edge", EdgeGeneration: 1, RawSSP: []byte("signed"), FactSequence: 1, DeliverySequence: 1}
	for _, mutate := range []func(*PublishRequest){
		func(r *PublishRequest) { r.OutboxID = "" },
		func(r *PublishRequest) { r.TenantID = "" },
		func(r *PublishRequest) { r.Destination = "other" },
		func(r *PublishRequest) { r.EdgeGeneration = 0 },
		func(r *PublishRequest) { r.FactSequence = 0 },
		func(r *PublishRequest) { r.DeliverySequence = 0 },
		func(r *PublishRequest) { r.RawSSP = nil },
		func(r *PublishRequest) { r.RawSSP = bytes.Repeat([]byte("x"), ssp.MaxEnvelopeBytes+1) },
	} {
		request := valid
		mutate(&request)
		if _, err := SubjectFor(request); err == nil {
			t.Fatalf("invalid request was accepted: %#v", request)
		}
	}
}

func TestFactOnlyWakesRejectAnEdgeDeliverySequence(t *testing.T) {
	for _, request := range []PublishRequest{
		{OutboxID: "outbox-domain", Destination: DestinationDomain, TenantID: "tenant", DomainID: "domain", RawSSP: []byte("signed"), FactSequence: 1, DeliverySequence: 1},
	} {
		if _, err := SubjectFor(request); err == nil {
			t.Fatalf("fact-only wake accepted edge delivery sequence: %#v", request)
		}
	}
}

func TestConsumerUsesExplicitAcknowledgementsForDestination(t *testing.T) {
	js := newTestJetStream(t)
	ctx := testContext(t)
	createTestStream(t, ctx, js)
	request := ConsumerRequest{Durable: "edge_delivery", Destination: DestinationEdge, TenantID: "tenant/acme", EdgeID: "edge/123", EdgeGeneration: 4, AckWait: time.Second, MaxDeliver: 7}
	spec, err := EnsureConsumer(ctx, js, request)
	if err != nil {
		t.Fatalf("ensure consumer: %v", err)
	}
	consumer, err := js.Consumer(ctx, StreamName, spec.Durable)
	if err != nil {
		t.Fatalf("consumer lookup: %v", err)
	}
	info, err := consumer.Info(ctx)
	if err != nil {
		t.Fatalf("consumer info: %v", err)
	}
	if info.Config.AckPolicy != jetstream.AckExplicitPolicy || info.Config.FilterSubject != spec.FilterSubject || info.Config.AckWait != request.AckWait || info.Config.MaxDeliver != request.MaxDeliver {
		t.Fatalf("consumer config = %#v", info.Config)
	}
}

func newTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	server, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	if !server.ReadyForConnections(5 * time.Second) {
		server.Shutdown()
		t.Fatal("nats server did not become ready")
	}
	t.Cleanup(server.Shutdown)
	connection, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func createTestStream(t *testing.T, ctx context.Context, js jetstream.JetStream) {
	t.Helper()
	config := StreamConfig()
	config.Storage = jetstream.MemoryStorage
	config.Replicas = 1 // The embedded test server is intentionally single-node.
	if _, err := js.CreateStream(ctx, config); err != nil {
		t.Fatalf("create test stream: %v", err)
	}
}

func mustStream(t *testing.T, ctx context.Context, js jetstream.JetStream) jetstream.Stream {
	t.Helper()
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		t.Fatalf("stream lookup: %v", err)
	}
	return stream
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
