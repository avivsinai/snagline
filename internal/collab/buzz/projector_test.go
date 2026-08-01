package buzz

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/ssp"
)

var projectorNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func TestProjectorPreparesOnceAndRetriesExactPersistedBuzzBytes(t *testing.T) {
	caseRecord := testCaseRecord(1, "case-1", "case-envelope-1", "support/sre")
	source := &fakeFactSource{records: []CommittedFact{caseRecord}}
	verifier := fakeVerifier{envelopes: map[string]ssp.Envelope{string(caseRecord.Raw): testCaseEnvelope("case-1", "case-envelope-1", "support/sre")}}
	store := NewMemoryStore()
	signer := &fakeSigner{}
	relay := &fakeRelay{failures: 1}
	projector, err := NewProjector(ProjectorConfig{
		Source: source, Verifier: verifier, Channels: fakeChannels{"support/sre": "11111111-1111-1111-1111-111111111111"}, Store: store, Signer: signer, Relay: relay,
		Clock: func() time.Time { return projectorNow },
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := projector.Project(context.Background(), 10); err == nil {
		t.Fatal("first publish should fail")
	}
	state := store.State()
	prepared := state.Records[caseRecord.Sequence]
	if prepared.Status != StatusRetry || len(prepared.Wire) == 0 || signer.calls != 1 {
		t.Fatalf("retry state = %#v signer calls = %d", prepared, signer.calls)
	}
	assertRedactedCard(t, prepared.Wire, "case-raw", "signature", "context_manifest", "registry_hash", "edge-key")
	persisted := append([]byte(nil), prepared.Wire...)

	// A new projector instance proves no process-local queue or cursor is
	// needed to resume the exact prepared artifact after removal/restart.
	projector, err = NewProjector(ProjectorConfig{
		Source: source, Verifier: verifier, Channels: fakeChannels{"support/sre": "11111111-1111-1111-1111-111111111111"}, Store: store, Signer: signer, Relay: relay,
		Clock: func() time.Time { return projectorNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Project(context.Background(), 10); err != nil {
		t.Fatalf("retry project: %v", err)
	}
	if signer.calls != 1 || len(relay.published) != 1 || !bytes.Equal(relay.published[0], persisted) {
		t.Fatalf("retry did not publish persisted bytes: signer=%d wires=%q", signer.calls, relay.published)
	}
	if got := store.State(); got.Checkpoint != caseRecord.Sequence || got.Records[caseRecord.Sequence].Status != StatusPublished {
		t.Fatalf("final state = %#v", got)
	}
}

func TestProjectorPersistsSupersedingEventOnlyAfterExpiredAbsentProof(t *testing.T) {
	record := testCaseRecord(1, "case-1", "case-envelope-1", "support/sre")
	source := &fakeFactSource{records: []CommittedFact{record}}
	verifier := fakeVerifier{envelopes: map[string]ssp.Envelope{string(record.Raw): testCaseEnvelope("case-1", "case-envelope-1", "support/sre")}}
	store := NewMemoryStore()
	signer := &fakeSigner{}
	relay := &fakeRelay{results: []error{errors.New("Buzz unavailable"), ErrPreparedExpiredAbsent, nil}}
	now := projectorNow
	projector, err := NewProjector(ProjectorConfig{
		Source: source, Verifier: verifier,
		Channels: fakeChannels{"support/sre": "11111111-1111-1111-1111-111111111111"},
		Store:    store, Signer: signer, Relay: relay, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Project(context.Background(), 1); err == nil {
		t.Fatal("initial unavailable relay unexpectedly succeeded")
	}
	before := store.State().Records[record.Sequence]
	if len(before.Wire) == 0 || signer.calls != 1 {
		t.Fatalf("initial evidence = %#v signer calls = %d", before, signer.calls)
	}
	now = now.Add(15 * time.Minute)
	if _, err := projector.Project(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	after := store.State()
	replacement := after.Records[record.Sequence]
	if signer.calls != 2 || replacement.EventID == before.EventID ||
		len(replacement.Superseded) != 1 ||
		!bytes.Equal(replacement.Superseded[0].Wire, before.Wire) ||
		replacement.Superseded[0].Reason != "expired_absent" ||
		after.CaseRoots["case-1"] != replacement.EventID ||
		replacement.Status != StatusPublished || after.Checkpoint != record.Sequence {
		t.Fatalf("superseding state = %#v signer calls = %d", after, signer.calls)
	}
	if len(relay.published) != 1 || !bytes.Equal(relay.published[0], replacement.Wire) {
		t.Fatalf("published replacements = %q", relay.published)
	}
}

func TestSQLiteStoreReopensEncryptedPreparedBytesForRetry(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "projector.sqlite")
	key := bytes.Repeat([]byte{7}, 32)
	store, err := OpenProjectionStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	assertCrashSafeSQLitePragmas(t, store)
	state := State{Checkpoint: 3, HighWatermark: 4, CaseRoots: map[string]string{"case-1": "root-1"}, Records: map[uint64]Delivery{
		4: {
			Record: CommittedFact{Sequence: 4, Raw: []byte("committed SSP raw")},
			Wire:   []byte("exact signed Nostr bytes"), Status: StatusRetry, Attempts: 2,
			Superseded: []SupersededProjection{{EventID: "old", Wire: []byte("old signed Nostr bytes"), Reason: "expired_absent"}},
		},
	}}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("exact signed Nostr bytes")) || bytes.Contains(stored, []byte("committed SSP raw")) {
		t.Fatal("SQLite file stores prepared or committed bytes in plaintext")
	}
	reopened, err := OpenProjectionStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Records[4].Wire, state.Records[4].Wire) ||
		!bytes.Equal(loaded.Records[4].Superseded[0].Wire, state.Records[4].Superseded[0].Wire) ||
		loaded.Checkpoint != state.Checkpoint || loaded.CaseRoots["case-1"] != "root-1" || loaded.Records[4].Status != StatusRetry {
		t.Fatalf("reopened state = %#v", loaded)
	}

	symlink := filepath.Join(filepath.Dir(path), "link.sqlite")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenProjectionStore(symlink, key); err == nil {
		t.Fatal("descriptor-safe store accepted a symlink database path")
	}

	nonPrivate := t.TempDir()
	if err := os.Chmod(nonPrivate, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenProjectionStore(filepath.Join(nonPrivate, "projector.sqlite"), key); err == nil {
		t.Fatal("projection store accepted a non-private state directory")
	}
}

func TestSQLiteStoreRetainsCommittedExactWireAfterProcessKill(t *testing.T) {
	const helperEnv = "SNAGLINE_BUZZ_STORE_CRASH_HELPER"
	if os.Getenv(helperEnv) == "1" {
		path := os.Getenv("SNAGLINE_BUZZ_STORE_PATH")
		store, err := OpenProjectionStore(path, bytes.Repeat([]byte{7}, 32))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		state := sqliteCrashState()
		if err := store.Save(context.Background(), state); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
		fmt.Fprintln(os.Stdout, "committed")
		select {}
	}

	path := filepath.Join(privateTempDir(t), "projector.sqlite")
	command := exec.Command(os.Args[0], "-test.run=^TestSQLiteStoreRetainsCommittedExactWireAfterProcessKill$")
	command.Env = append(os.Environ(), helperEnv+"=1", "SNAGLINE_BUZZ_STORE_PATH="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "committed\n" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("crash helper readiness = %q, %v", line, err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("crash helper unexpectedly exited cleanly")
	}

	reopened, err := OpenProjectionStore(path, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := sqliteCrashState()
	if loaded.Checkpoint != want.Checkpoint ||
		loaded.CaseRoots["case-crash"] != want.CaseRoots["case-crash"] ||
		!bytes.Equal(loaded.Records[9].Wire, want.Records[9].Wire) ||
		!bytes.Equal(loaded.Records[9].Superseded[0].Wire, want.Records[9].Superseded[0].Wire) {
		t.Fatalf("post-kill state = %#v", loaded)
	}
}

func TestSQLiteStoreFailedAtomicUpdatePreservesPreviousState(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "projector.sqlite")
	store, err := OpenProjectionStore(path, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	initial := State{Checkpoint: 1, Records: map[uint64]Delivery{
		2: {Record: CommittedFact{Sequence: 2}, Wire: []byte("initial exact wire"), Status: StatusPrepared},
	}}
	if err := store.Save(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER inject_state_failure BEFORE UPDATE ON buzz_projector_state BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	replacement := State{Checkpoint: 2, Records: map[uint64]Delivery{
		3: {Record: CommittedFact{Sequence: 3}, Wire: []byte("replacement exact wire"), Status: StatusPrepared},
	}}
	if err := store.Save(context.Background(), replacement); err == nil {
		t.Fatal("injected update failure unexpectedly committed")
	}
	if _, err := store.db.Exec(`DROP TRIGGER inject_state_failure`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenProjectionStore(path, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Checkpoint != initial.Checkpoint ||
		!bytes.Equal(loaded.Records[2].Wire, initial.Records[2].Wire) ||
		len(loaded.Records[3].Wire) != 0 {
		t.Fatalf("failed atomic replacement changed state = %#v", loaded)
	}
}

func assertCrashSafeSQLitePragmas(t *testing.T, store *ProjectionStore) {
	t.Helper()
	var journal string
	var synchronous, fullfsync, checkpointFullfsync int
	if err := store.db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`PRAGMA fullfsync`).Scan(&fullfsync); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`PRAGMA checkpoint_fullfsync`).Scan(&checkpointFullfsync); err != nil {
		t.Fatal(err)
	}
	if journal != "wal" || synchronous != 2 || fullfsync != 1 || checkpointFullfsync != 1 {
		t.Fatalf("unsafe SQLite pragmas journal=%q synchronous=%d fullfsync=%d checkpoint_fullfsync=%d",
			journal, synchronous, fullfsync, checkpointFullfsync)
	}
}

func sqliteCrashState() State {
	return State{
		Checkpoint: 9, HighWatermark: 9,
		CaseRoots: map[string]string{"case-crash": "root-crash"},
		Records: map[uint64]Delivery{9: {
			Record:  CommittedFact{Sequence: 9, Raw: []byte("committed SSP")},
			EventID: "event-new", RootEventID: "root-crash",
			Wire: []byte("new exact signed event"), Status: StatusPrepared,
			Superseded: []SupersededProjection{{
				EventID: "event-old", Wire: []byte("old exact signed event"),
				Reason: "expired_absent",
			}},
		}},
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAdviceUsesPersistedCaseRootAndBuzzFailureDoesNotChangeJournal(t *testing.T) {
	caseRecord := testCaseRecord(1, "case-1", "case-envelope-1", "support/sre")
	adviceRecord := CommittedFact{Sequence: 2, EnvelopeID: "advice-envelope-1", Commitment: "sha256:" + repeat("b", 64), Raw: []byte("advice-raw")}
	source := &fakeFactSource{records: []CommittedFact{caseRecord, adviceRecord}}
	verifier := fakeVerifier{envelopes: map[string]ssp.Envelope{
		string(caseRecord.Raw):   testCaseEnvelope("case-1", "case-envelope-1", "support/sre"),
		string(adviceRecord.Raw): testAdviceEnvelope("case-1", "advice-envelope-1"),
	}}
	store := NewMemoryStore()
	relay := &fakeRelay{failures: 1}
	projector, err := NewProjector(ProjectorConfig{
		Source: source, Verifier: verifier, Channels: fakeChannels{"support/sre": "11111111-1111-1111-1111-111111111111"}, Store: store, Signer: &fakeSigner{}, Relay: relay,
		Clock: func() time.Time { return projectorNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = projector.Project(context.Background(), 10)
	if !bytes.Equal(source.records[0].Raw, []byte("case-raw")) || !bytes.Equal(source.records[1].Raw, []byte("advice-raw")) {
		t.Fatal("Buzz outcome changed committed SSP authority bytes")
	}

	// The root is persisted before any Buzz publish. Let a healthy relay drain
	// the case then advice and prove the reply points at that root event ID.
	relay.failures = 0
	if _, err := projector.Project(context.Background(), 10); err != nil {
		t.Fatalf("case retry: %v", err)
	}
	if _, err := projector.Project(context.Background(), 10); err != nil {
		t.Fatalf("advice project: %v", err)
	}
	state := store.State()
	root := state.CaseRoots["case-1"]
	advice := state.Records[adviceRecord.Sequence]
	var event nostrEvent
	if err := json.Unmarshal(advice.Wire, &event); err != nil {
		t.Fatal(err)
	}
	if root == "" || !hasReplyRoot(event.Tags, root) {
		t.Fatalf("advice root mapping = %q event=%#v", root, event)
	}
}

func TestProjectorPoisonAndLagRemainInPersistedState(t *testing.T) {
	record := testCaseRecord(1, "case-1", "case-envelope-1", "support/sre")
	store := NewMemoryStore()
	projector, err := NewProjector(ProjectorConfig{
		Source: &fakeFactSource{records: []CommittedFact{record}}, Verifier: fakeVerifier{envelopes: map[string]ssp.Envelope{string(record.Raw): testCaseEnvelope("case-1", "case-envelope-1", "support/sre")}},
		Channels: fakeChannels{"support/sre": "11111111-1111-1111-1111-111111111111"}, Store: store, Signer: &fakeSigner{}, Relay: &fakeRelay{failures: 2}, MaxAttempts: 1,
		Clock: func() time.Time { return projectorNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Project(context.Background(), 10); err == nil {
		t.Fatal("expected Buzz failure")
	}
	state := store.State()
	if state.Records[record.Sequence].Status != StatusPoison || state.Lag.Pending != 0 ||
		state.Lag.Poisoned != 1 || state.Checkpoint != 0 {
		t.Fatalf("poison/lag state = %#v", state)
	}
}

func TestProjectorParksPoisonAndContinuesWithIndependentFact(t *testing.T) {
	first := testCaseRecord(1, "case-1", "case-envelope-1", "support/sre")
	first.Raw = []byte("case-raw-1")
	second := testCaseRecord(2, "case-2", "case-envelope-2", "support/sre")
	second.Raw = []byte("case-raw-2")
	store := NewMemoryStore()
	relay := &fakeRelay{failures: 1}
	projector, err := NewProjector(ProjectorConfig{
		Source: &fakeFactSource{records: []CommittedFact{first, second}},
		Verifier: fakeVerifier{envelopes: map[string]ssp.Envelope{
			string(first.Raw):  testCaseEnvelope("case-1", "case-envelope-1", "support/sre"),
			string(second.Raw): testCaseEnvelope("case-2", "case-envelope-2", "support/sre"),
		}},
		Channels: fakeChannels{"support/sre": "11111111-1111-1111-1111-111111111111"},
		Store:    store, Signer: &fakeSigner{}, Relay: relay, MaxAttempts: 1,
		Clock: func() time.Time { return projectorNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Project(context.Background(), 10); err == nil {
		t.Fatal("first permanent failure unexpectedly succeeded")
	}
	result, err := projector.Project(context.Background(), 10)
	if err != nil {
		t.Fatalf("resume past parked record: %v", err)
	}
	state := store.State()
	if result.Published != 1 || state.Checkpoint != second.Sequence ||
		state.Records[first.Sequence].Status != StatusPoison ||
		state.Records[second.Sequence].Status != StatusPublished ||
		state.Lag.Pending != 0 || state.Lag.Poisoned != 1 {
		t.Fatalf("parked progress result=%#v state=%#v", result, state)
	}
}

func TestProjectorRejectsNonCanonicalChannelBeforeSigningOrPersistence(t *testing.T) {
	for _, channel := range []string{
		"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
		"{11111111-1111-1111-1111-111111111111}",
	} {
		t.Run(channel, func(t *testing.T) {
			record := testCaseRecord(1, "case-1", "case-envelope-1", "support/sre")
			store := NewMemoryStore()
			signer := &fakeSigner{}
			projector, err := NewProjector(ProjectorConfig{
				Source: &fakeFactSource{records: []CommittedFact{record}},
				Verifier: fakeVerifier{envelopes: map[string]ssp.Envelope{
					string(record.Raw): testCaseEnvelope("case-1", "case-envelope-1", "support/sre"),
				}},
				Channels: fakeChannels{"support/sre": channel},
				Store:    store, Signer: signer, Relay: &fakeRelay{},
				Clock: func() time.Time { return projectorNow },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := projector.Project(context.Background(), 1); err == nil {
				t.Fatal("non-canonical channel unexpectedly projected")
			}
			state := store.State()
			if signer.calls != 0 || len(state.Records[record.Sequence].Wire) != 0 {
				t.Fatalf("non-canonical channel crossed signing barrier: signer=%d state=%#v", signer.calls, state)
			}
		})
	}
}

func TestProjectorCanRebuildAnAuthorityVerifiedFactAfterEnvelopeExpiry(t *testing.T) {
	record := testCaseRecord(1, "case-1", "case-envelope-1", "support/sre")
	envelope := testCaseEnvelope("case-1", "case-envelope-1", "support/sre")
	envelope.ExpiresAt = "2029-12-31T23:30:00Z"
	relay := &fakeRelay{}
	projector, err := NewProjector(ProjectorConfig{
		Source:   &fakeFactSource{records: []CommittedFact{record}},
		Verifier: fakeVerifier{envelopes: map[string]ssp.Envelope{string(record.Raw): envelope}},
		Channels: fakeChannels{"support/sre": "11111111-1111-1111-1111-111111111111"},
		Store:    NewMemoryStore(), Signer: &fakeSigner{}, Relay: relay,
		Clock: func() time.Time { return projectorNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Project(context.Background(), 1); err != nil {
		t.Fatalf("historical rebuild failed: %v", err)
	}
	if len(relay.published) != 1 {
		t.Fatalf("published = %d, want one historical committed fact", len(relay.published))
	}
}

func TestNostrDigestMatchesStockSerializationForHTMLAndLineSeparators(t *testing.T) {
	event := nostrEvent{
		PubKey: "pub", CreatedAt: 7, Kind: stockBuzzMessageKind,
		Tags: [][]string{}, Content: "<>&\u2028\u2029",
	}
	got, err := nostrDigest(event)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("[0,\"pub\",7,9,[],\"<>&\u2028\u2029\"]"))
	if got != want {
		t.Fatalf("digest = %x, want stock serialization %x", got, want)
	}
}

type fakeFactSource struct{ records []CommittedFact }

func (s *fakeFactSource) ReadAfter(_ context.Context, after uint64, limit int) ([]CommittedFact, error) {
	var records []CommittedFact
	for _, record := range s.records {
		if record.Sequence > after && len(records) < limit {
			record.Raw = append([]byte(nil), record.Raw...)
			records = append(records, record)
		}
	}
	return records, nil
}

type fakeVerifier struct{ envelopes map[string]ssp.Envelope }

func (v fakeVerifier) VerifyCommitted(_ context.Context, raw []byte) (ssp.Envelope, error) {
	envelope, ok := v.envelopes[string(raw)]
	if !ok {
		return ssp.Envelope{}, errors.New("unrecognized committed SSP bytes")
	}
	return envelope, nil
}

type fakeChannels map[string]string

func (c fakeChannels) ChannelForDomain(_ context.Context, domain string) (string, error) {
	return c[domain], nil
}

type fakeSigner struct{ calls int }

func (s *fakeSigner) PublicKey() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}
func (s *fakeSigner) SignDigest(_ context.Context, _ [32]byte) (string, error) {
	s.calls++
	return repeat("0", 128), nil
}

type fakeRelay struct {
	failures  int
	published [][]byte
	results   []error
}

func (r *fakeRelay) Publish(_ context.Context, wire []byte) error {
	if len(r.results) > 0 {
		result := r.results[0]
		r.results = r.results[1:]
		if result != nil {
			return result
		}
		r.published = append(r.published, append([]byte(nil), wire...))
		return nil
	}
	if r.failures > 0 {
		r.failures--
		return errors.New("Buzz unavailable")
	}
	r.published = append(r.published, append([]byte(nil), wire...))
	return nil
}

func testCaseRecord(sequence uint64, caseID, envelopeID, domain string) CommittedFact {
	return CommittedFact{Sequence: sequence, EnvelopeID: envelopeID, Commitment: "sha256:" + repeat("a", 64), Raw: []byte("case-raw")}
}

func testCaseEnvelope(caseID, envelopeID, domain string) ssp.Envelope {
	return ssp.Envelope{
		Schema: ssp.FamilyCase, ID: envelopeID, CaseID: caseID,
		EmittedAt: "2029-12-31T23:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z",
		RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: "sha256:" + repeat("d", 64),
		AuthorKeyID: "edge-key", SignatureAlg: "ed25519",
		Body: json.RawMessage(`{"domain":"` + domain + `","issuer_edge_id":"edge/123","issuer_edge_generation":1,"summary":"help","context_manifest":"sha256:` + repeat("c", 64) + `"}`),
	}
}

func testAdviceEnvelope(caseID, envelopeID string) ssp.Envelope {
	return ssp.Envelope{
		Schema: ssp.FamilyAdvice, ID: envelopeID, CaseID: caseID,
		EmittedAt: "2029-12-31T23:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z",
		RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: "sha256:" + repeat("d", 64),
		AuthorKeyID: "advice-key", SignatureAlg: "ed25519",
		Body: json.RawMessage(`{"case_commitment":"sha256:` + repeat("a", 64) + `","text":"try this"}`),
	}
}

func hasReplyRoot(tags [][]string, root string) bool {
	for _, tag := range tags {
		if len(tag) == 4 && tag[0] == "e" && tag[1] == root && tag[3] == "reply" {
			return true
		}
	}
	return false
}

func repeat(value string, n int) string {
	return string(bytes.Repeat([]byte(value), n))
}

func assertRedactedCard(t *testing.T, wire []byte, forbidden ...string) {
	t.Helper()
	var event nostrEvent
	if err := json.Unmarshal(wire, &event); err != nil {
		t.Fatal(err)
	}
	for _, value := range forbidden {
		if strings.Contains(event.Content, value) {
			t.Fatalf("card leaked %q: %s", value, event.Content)
		}
	}
	var card map[string]string
	if err := json.Unmarshal([]byte(event.Content), &card); err != nil {
		t.Fatalf("card is not JSON: %v", err)
	}
	if card["family"] != ssp.FamilyCase || card["summary"] != "help" || card["case_id"] != "case-1" {
		t.Fatalf("redacted card = %#v", card)
	}
}
