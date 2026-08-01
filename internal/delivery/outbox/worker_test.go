package outbox

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/deliverystream"
)

var (
	errPublish    = errors.New("broker unavailable")
	errMark       = errors.New("mark failed after ACK")
	errStaleLease = errors.New("stale lease")
)

func TestWorkerCrashWindowRedeliversSameOutboxMessage(t *testing.T) {
	item := validEdgeItem()
	source := &fakeSource{
		batches:  [][]Item{{item}, {withLease(item, "lease-2")}},
		markErrs: []error{errMark, nil},
	}
	publisher := &fakePublisher{}
	worker := testWorker(source, publisher)

	if err := worker.RunOnce(context.Background()); !errors.Is(err, errMark) {
		t.Fatalf("first run error = %v, want %v", err, errMark)
	}
	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(publisher.requests) != 2 {
		t.Fatalf("publish calls = %d, want 2", len(publisher.requests))
	}
	first, second := publisher.requests[0], publisher.requests[1]
	if first.OutboxID != second.OutboxID || first.OutboxID != item.ID ||
		!bytes.Equal(first.RawSSP, second.RawSSP) {
		t.Fatalf("duplicate publish changed identity or bytes: first=%#v second=%#v", first, second)
	}
	if len(source.marks) != 2 || source.marks[0].leaseToken != "lease-1" ||
		source.marks[1].leaseToken != "lease-2" || len(source.releases) != 0 {
		t.Fatalf("source calls = marks:%#v releases:%#v", source.marks, source.releases)
	}
}

func TestWorkerPublishFailureReleasesWithoutMarking(t *testing.T) {
	item := validEdgeItem()
	source := &fakeSource{batches: [][]Item{{item}}}
	publisher := &fakePublisher{errs: []error{errPublish}}
	worker := testWorker(source, publisher)

	err := worker.RunOnce(context.Background())
	if !errors.Is(err, errPublish) {
		t.Fatalf("run error = %v, want %v", err, errPublish)
	}
	if len(source.marks) != 0 || len(source.releases) != 1 {
		t.Fatalf("source calls = marks:%#v releases:%#v", source.marks, source.releases)
	}
	release := source.releases[0]
	if release.itemID != item.ID || release.leaseToken != item.LeaseToken ||
		!release.retryAt.Equal(testNow.Add(testRetryDelay)) ||
		release.reason != ReasonPublishFailed {
		t.Fatalf("release = %#v", release)
	}
	if strings.Contains(release.reason, string(item.Raw)) ||
		strings.Contains(release.reason, errPublish.Error()) {
		t.Fatalf("release reason was not redacted: %q", release.reason)
	}
}

func TestWorkerStaleLeaseMarkFailureIsNotReleased(t *testing.T) {
	item := validEdgeItem()
	source := &fakeSource{
		batches:  [][]Item{{item}},
		markErrs: []error{errStaleLease},
	}
	publisher := &fakePublisher{}
	worker := testWorker(source, publisher)

	err := worker.RunOnce(context.Background())
	if !errors.Is(err, errStaleLease) {
		t.Fatalf("run error = %v, want %v", err, errStaleLease)
	}
	if len(publisher.requests) != 1 || len(source.marks) != 1 ||
		source.marks[0].leaseToken != item.LeaseToken || len(source.releases) != 0 {
		t.Fatalf("calls = publish:%d marks:%#v releases:%#v", len(publisher.requests), source.marks, source.releases)
	}
}

func TestWorkerMalformedItemIsPoisonReleasedWithoutPayloadLeak(t *testing.T) {
	item := validEdgeItem()
	item.EdgeID = ""
	item.Raw = []byte("signed-secret-payload")
	source := &fakeSource{batches: [][]Item{{item}}}
	publisher := &fakePublisher{}
	worker := testWorker(source, publisher)

	if err := worker.RunOnce(context.Background()); err == nil {
		t.Fatal("malformed item succeeded")
	}
	if len(publisher.requests) != 0 || len(source.marks) != 0 || len(source.releases) != 1 {
		t.Fatalf("calls = publish:%d marks:%#v releases:%#v", len(publisher.requests), source.marks, source.releases)
	}
	release := source.releases[0]
	if release.reason != ReasonMalformedItem || strings.Contains(release.reason, string(item.Raw)) {
		t.Fatalf("malformed release reason = %q", release.reason)
	}
}

func TestWorkerMapsDeliveryDestinationsAndDoesNotMutatePayload(t *testing.T) {
	edge := validEdgeItem()
	domain := Item{
		ID: "outbox-domain", LeaseToken: "lease-domain", TenantID: "tenant-a",
		EventKind: EventCase, EntityID: "case-2",
		DestinationKind: DestinationDomainDispatch, DestinationKey: "support/sre",
		Raw: []byte("{\n \"exact\":\"domain\" \n}"), AuthorityRevision: 42,
		DomainID: "support/sre",
	}
	originals := [][]byte{
		append([]byte(nil), edge.Raw...),
		append([]byte(nil), domain.Raw...),
	}
	source := &fakeSource{batches: [][]Item{{edge, domain}}}
	publisher := &fakePublisher{mutateAfterCapture: true}
	worker := testWorker(source, publisher)

	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(publisher.requests) != 2 || len(source.marks) != 2 {
		t.Fatalf("calls = publish:%d marks:%d", len(publisher.requests), len(source.marks))
	}
	edgeRequest, domainRequest := publisher.requests[0], publisher.requests[1]
	if edgeRequest.Destination != deliverystream.DestinationEdge ||
		edgeRequest.EdgeID != edge.EdgeID ||
		edgeRequest.EdgeGeneration != uint64(edge.EdgeGeneration) ||
		edgeRequest.DeliverySequence != uint64(edge.DeliverySequence) {
		t.Fatalf("edge request = %#v", edgeRequest)
	}
	if domainRequest.Destination != deliverystream.DestinationDomain ||
		domainRequest.DomainID != domain.DomainID ||
		domainRequest.DeliverySequence != 0 {
		t.Fatalf("domain request = %#v", domainRequest)
	}
	items := []Item{edge, domain}
	for index := range items {
		if !bytes.Equal(publisher.requests[index].RawSSP, originals[index]) {
			t.Fatalf("published payload %d = %q, want %q", index, publisher.requests[index].RawSSP, originals[index])
		}
		if !bytes.Equal(items[index].Raw, originals[index]) {
			t.Fatalf("source payload %d was mutated: %q", index, items[index].Raw)
		}
		if publisher.requests[index].FactSequence != uint64(items[index].AuthorityRevision) {
			t.Fatalf("fact sequence %d = %d, want %d", index, publisher.requests[index].FactSequence, items[index].AuthorityRevision)
		}
	}
}

func TestWorkerValidatesBoundsBeforeClaim(t *testing.T) {
	valid := testWorker(&fakeSource{}, &fakePublisher{})
	tests := []struct {
		name   string
		mutate func(*Worker)
	}{
		{"worker ID", func(worker *Worker) { worker.WorkerID = "" }},
		{"zero limit", func(worker *Worker) { worker.Limit = 0 }},
		{"excessive limit", func(worker *Worker) { worker.Limit = MaxBatchSize + 1 }},
		{"zero lease", func(worker *Worker) { worker.Lease = 0 }},
		{"excessive lease", func(worker *Worker) { worker.Lease = MaxLease + time.Nanosecond }},
		{"zero retry delay", func(worker *Worker) { worker.RetryDelay = 0 }},
		{"excessive retry delay", func(worker *Worker) { worker.RetryDelay = MaxRetryDelay + time.Nanosecond }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			worker := valid
			test.mutate(&worker)
			source := worker.Source.(*fakeSource)
			before := source.claims
			if err := worker.RunOnce(context.Background()); err == nil {
				t.Fatal("invalid worker succeeded")
			}
			if source.claims != before {
				t.Fatal("invalid worker claimed items")
			}
		})
	}
}

func TestWorkerRejectsSourceBatchBeyondClaimLimit(t *testing.T) {
	item := validEdgeItem()
	source := &fakeSource{batches: [][]Item{{item, withLease(item, "lease-2")}}}
	publisher := &fakePublisher{}
	worker := testWorker(source, publisher)
	worker.Limit = 1

	if err := worker.RunOnce(context.Background()); err == nil {
		t.Fatal("oversized claim succeeded")
	}
	if len(publisher.requests) != 0 || len(source.marks) != 0 || len(source.releases) != 0 {
		t.Fatal("oversized claim was processed")
	}
}

func TestWorkerPreservesCancellationAfterClaim(t *testing.T) {
	item := validEdgeItem()
	ctx, cancel := context.WithCancel(context.Background())
	source := &fakeSource{
		batches: [][]Item{{item}},
		onClaim: cancel,
	}
	publisher := &fakePublisher{}
	worker := testWorker(source, publisher)

	if err := worker.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v, want context canceled", err)
	}
	if len(publisher.requests) != 0 || len(source.marks) != 0 || len(source.releases) != 0 {
		t.Fatal("canceled claim was processed")
	}
}

func TestJetStreamPublisherFailsClosedWithoutClient(t *testing.T) {
	if err := (JetStreamPublisher{}).Publish(context.Background(), PublishRequest{}); err == nil {
		t.Fatal("nil JetStream publisher succeeded")
	}
}

var (
	testNow        = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	testRetryDelay = 10 * time.Second
)

func testWorker(source Source, publisher Publisher) Worker {
	return Worker{
		Source: source, Publisher: publisher, WorkerID: "worker-a",
		Limit: 10, Lease: time.Minute, RetryDelay: testRetryDelay,
		Now: func() time.Time { return testNow },
	}
}

func validEdgeItem() Item {
	return Item{
		ID: "outbox-edge", LeaseToken: "lease-1", TenantID: "tenant-a",
		EventKind: EventAdvice, EntityID: "case-1",
		DestinationKind: DestinationEdgeDelivery, DestinationKey: "edge/1@4",
		Raw: []byte("{\n \"exact\":\"edge\" \n}"), AuthorityRevision: 41,
		EdgeID: "edge/1", EdgeGeneration: 4, DeliverySequence: 9,
	}
}

func withLease(item Item, leaseToken string) Item {
	item.LeaseToken = leaseToken
	return item
}

type sourceCall struct {
	itemID     string
	leaseToken string
}

type releaseCall struct {
	sourceCall
	retryAt time.Time
	reason  string
}

type fakeSource struct {
	batches  [][]Item
	markErrs []error
	onClaim  func()
	claims   int
	marks    []sourceCall
	releases []releaseCall
}

func (source *fakeSource) Claim(_ context.Context, _ string, _ int, _ time.Duration) ([]Item, error) {
	source.claims++
	if source.onClaim != nil {
		source.onClaim()
	}
	if len(source.batches) == 0 {
		return nil, nil
	}
	items := source.batches[0]
	source.batches = source.batches[1:]
	return items, nil
}

func (source *fakeSource) MarkPublished(_ context.Context, itemID, leaseToken string) error {
	source.marks = append(source.marks, sourceCall{itemID: itemID, leaseToken: leaseToken})
	if len(source.markErrs) == 0 {
		return nil
	}
	err := source.markErrs[0]
	source.markErrs = source.markErrs[1:]
	return err
}

func (source *fakeSource) Release(_ context.Context, itemID, leaseToken string, retryAt time.Time, reason string) error {
	source.releases = append(source.releases, releaseCall{
		sourceCall: sourceCall{itemID: itemID, leaseToken: leaseToken},
		retryAt:    retryAt, reason: reason,
	})
	return nil
}

type fakePublisher struct {
	requests           []PublishRequest
	errs               []error
	mutateAfterCapture bool
}

func (publisher *fakePublisher) Publish(_ context.Context, request PublishRequest) error {
	captured := request
	captured.RawSSP = append([]byte(nil), request.RawSSP...)
	publisher.requests = append(publisher.requests, captured)
	if publisher.mutateAfterCapture && len(request.RawSSP) > 0 {
		request.RawSSP[0] ^= 0xff
	}
	if len(publisher.errs) == 0 {
		return nil
	}
	err := publisher.errs[0]
	publisher.errs = publisher.errs[1:]
	return err
}
