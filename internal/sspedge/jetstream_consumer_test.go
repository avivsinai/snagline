package sspedge

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/deliverystream"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNewJetStreamPullConsumerEnsuresGenerationScopedExplicitAckConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	js := newEdgeTestJetStream(t)
	config := deliverystream.StreamConfig()
	config.Storage = jetstream.MemoryStorage
	config.Replicas = 1
	if _, err := js.CreateStream(ctx, config); err != nil {
		t.Fatal(err)
	}
	id := testIdentity()
	handler, err := NewJournalConsumer(newTestDB(t), verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return nil, errors.New("unused")
	}), id, nil)
	if err != nil {
		t.Fatal(err)
	}
	pullConfig := JetStreamPullConfig{
		JetStream: js,
		Request: deliverystream.ConsumerRequest{
			Durable: "edge_generation_3", Destination: deliverystream.DestinationEdge,
			TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: uint64(id.Generation),
			AckWait: time.Second, MaxDeliver: 7,
		},
		Handler: handler, FetchWait: 100 * time.Millisecond,
	}
	adapter, err := NewJetStreamPullConsumer(ctx, pullConfig)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := js.Consumer(ctx, deliverystream.StreamName, adapter.spec.Durable)
	if err != nil {
		t.Fatal(err)
	}
	info, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.AckPolicy != jetstream.AckExplicitPolicy ||
		info.Config.FilterSubject != edgeDeliverySubject(id) ||
		adapter.spec.FilterSubject != edgeDeliverySubject(id) {
		t.Fatalf("consumer config=%+v spec=%+v", info.Config, adapter.spec)
	}
	wrongIdentity := pullConfig
	wrongIdentity.Request.EdgeGeneration++
	if got, err := NewJetStreamPullConsumer(ctx, wrongIdentity); err == nil || got != nil {
		t.Fatalf("wrong identity=(%v,%v)", got, err)
	}
	unbounded := pullConfig
	unbounded.FetchWait = maxJetStreamFetchWait + time.Nanosecond
	if got, err := NewJetStreamPullConsumer(ctx, unbounded); err == nil || got != nil {
		t.Fatalf("unbounded fetch wait=(%v,%v)", got, err)
	}
	missingHandler := pullConfig
	missingHandler.Handler = nil
	if got, err := NewJetStreamPullConsumer(ctx, missingHandler); err == nil || got != nil {
		t.Fatalf("missing handler=(%v,%v)", got, err)
	}
}

func TestJetStreamPullConsumerMapsAuthorityHeadersAndAcksAfterCommit(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	handler, err := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := validEdgeJetStreamMessage(id, 1, []byte("exact-case"))
	committedBeforeAck := false
	message.onDoubleAck = func() {
		committedBeforeAck = count(t, db, "ssp_edge_cases") == 1
	}
	adapter := &JetStreamPullConsumer{
		consumer:  oneMessageFetcher(message),
		handler:   handler,
		identity:  id,
		fetchWait: time.Second,
	}

	outcome, err := adapter.HandleNext(context.Background(), now)
	if err != nil || outcome != ProcessAccepted {
		t.Fatalf("handle=(%q,%v)", outcome, err)
	}
	if message.doubleAcks != 1 || message.naks != 0 || !committedBeforeAck {
		t.Fatalf("ack/nak=%d/%d committed-before-ack=%v", message.doubleAcks, message.naks, committedBeforeAck)
	}
	var deliverySequence int64
	var carrierStream string
	var carrierSequence uint64
	if err := db.SQL().QueryRow(`SELECT delivery_seq,carrier_stream,carrier_sequence FROM ssp_edge_deliveries`).Scan(&deliverySequence, &carrierStream, &carrierSequence); err != nil {
		t.Fatal(err)
	}
	if deliverySequence != 1 || carrierStream != deliverystream.StreamName || carrierSequence != 41 {
		t.Fatalf("stored delivery=%d/%q/%d", deliverySequence, carrierStream, carrierSequence)
	}
}

func TestJetStreamPullConsumerNaksMalformedHeaderWithoutVerification(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	verified := false
	handler, err := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		verified = true
		return nil, errors.New("must not verify malformed carrier")
	}), id, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := validEdgeJetStreamMessage(id, 1, []byte("case"))
	message.headers.Del(deliverystream.HeaderDeliverySequence)
	adapter := &JetStreamPullConsumer{
		consumer: oneMessageFetcher(message), handler: handler, identity: id, fetchWait: time.Second,
	}
	outcome, err := adapter.HandleNext(context.Background(), time.Now().UTC())
	if err != nil || outcome != ProcessRetrying {
		t.Fatalf("malformed handle=(%q,%v)", outcome, err)
	}
	if message.doubleAcks != 0 || message.naks != 1 || verified {
		t.Fatalf("ack/nak=%d/%d verified=%v", message.doubleAcks, message.naks, verified)
	}
}

func TestNewJetStreamPullConsumerRejectsNilDependencies(t *testing.T) {
	if got, err := NewJetStreamPullConsumer(context.Background(), JetStreamPullConfig{}); err == nil || got != nil {
		t.Fatalf("nil dependencies=(%v,%v)", got, err)
	}
}

func TestJetStreamPullConsumerExposesBoundedAuthorityReconciliation(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	reconciler := &fakeReconciler{batch: ReconcileBatch{
		Deliveries:      []JournalDelivery{testDelivery(id, 1, "case"), testDelivery(id, 2, "advice")},
		HighWatermark:   2,
		CompleteThrough: 2,
	}}
	reconciler.batch.Deliveries[0].Subject = edgeDeliverySubject(id)
	reconciler.batch.Deliveries[1].Subject = edgeDeliverySubject(id)
	handler, err := NewJournalConsumer(db, verifyFunc(func(_ context.Context, delivery JournalDelivery) (*VerifiedProjection, error) {
		if delivery.DeliverySeq == 1 {
			return caseProjection(now, id, "domain/a.*", "case"), nil
		}
		return adviceProjection(now, id, commitment("a")), nil
	}), id, reconciler)
	if err != nil {
		t.Fatal(err)
	}
	gap := fakeCarrier(id, 2, "gap", edgeDeliverySubject(id))
	if outcome, err := handler.Process(context.Background(), gap, now); err != nil || outcome != ProcessReconciliationRequired {
		t.Fatalf("gap = (%q,%v)", outcome, err)
	}
	adapter := &JetStreamPullConsumer{consumer: &fakePullFetcher{}, handler: handler, identity: id}
	if !adapter.Halted() {
		t.Fatal("adapter did not expose persisted halt")
	}
	result, err := adapter.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Resumed || adapter.Halted() || result.CompleteThrough != 2 {
		t.Fatalf("reconcile = %+v halted=%v", result, adapter.Halted())
	}
}

func newEdgeTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		JetStream: true, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("NATS server did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	connection, err := nats.Connect(srv.ClientURL())
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

type fakePullFetcher struct {
	batch jetstream.MessageBatch
	err   error
}

func (f *fakePullFetcher) Fetch(int, ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	return f.batch, f.err
}

type fakeMessageBatch struct {
	messages <-chan jetstream.Msg
	err      error
}

func (b *fakeMessageBatch) Messages() <-chan jetstream.Msg { return b.messages }
func (b *fakeMessageBatch) Error() error                   { return b.err }

func oneMessageFetcher(message jetstream.Msg) *fakePullFetcher {
	messages := make(chan jetstream.Msg, 1)
	messages <- message
	close(messages)
	return &fakePullFetcher{batch: &fakeMessageBatch{messages: messages}}
}

type fakeEdgeJetStreamMessage struct {
	metadata    *jetstream.MsgMetadata
	metadataErr error
	headers     nats.Header
	subject     string
	data        []byte
	doubleAcks  int
	naks        int
	onDoubleAck func()
}

func validEdgeJetStreamMessage(id EdgeIdentity, sequence int64, raw []byte) *fakeEdgeJetStreamMessage {
	headers := make(nats.Header)
	headers.Set(deliverystream.HeaderOutboxID, "outbox-1")
	headers.Set(deliverystream.HeaderFactSequence, "10")
	headers.Set(deliverystream.HeaderDeliverySequence, strconv.FormatInt(sequence, 10))
	headers.Set(deliverystream.HeaderEdgeGeneration, strconv.FormatInt(id.Generation, 10))
	return &fakeEdgeJetStreamMessage{
		metadata: &jetstream.MsgMetadata{
			Sequence: jetstream.SequencePair{Stream: 41, Consumer: 1},
			Stream:   deliverystream.StreamName,
		},
		headers: headers, subject: edgeDeliverySubject(id), data: append([]byte(nil), raw...),
	}
}

func (m *fakeEdgeJetStreamMessage) Metadata() (*jetstream.MsgMetadata, error) {
	return m.metadata, m.metadataErr
}
func (m *fakeEdgeJetStreamMessage) Data() []byte         { return m.data }
func (m *fakeEdgeJetStreamMessage) Headers() nats.Header { return m.headers }
func (m *fakeEdgeJetStreamMessage) Subject() string      { return m.subject }
func (m *fakeEdgeJetStreamMessage) Reply() string        { return "" }
func (m *fakeEdgeJetStreamMessage) Ack() error           { return errors.New("unexpected Ack") }
func (m *fakeEdgeJetStreamMessage) DoubleAck(context.Context) error {
	m.doubleAcks++
	if m.onDoubleAck != nil {
		m.onDoubleAck()
	}
	return nil
}
func (m *fakeEdgeJetStreamMessage) Nak() error {
	m.naks++
	return nil
}
func (m *fakeEdgeJetStreamMessage) NakWithDelay(time.Duration) error {
	return errors.New("unexpected NakWithDelay")
}
func (m *fakeEdgeJetStreamMessage) InProgress() error { return errors.New("unexpected InProgress") }
func (m *fakeEdgeJetStreamMessage) Term() error       { return errors.New("unexpected Term") }
func (m *fakeEdgeJetStreamMessage) TermWithReason(string) error {
	return errors.New("unexpected TermWithReason")
}
