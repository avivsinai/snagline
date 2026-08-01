package buzz

import (
	"context"
	"testing"

	"github.com/avivsinai/snagline/internal/authority"
)

func TestAuthoritySourceReadsExactCommittedFactsAfterCheckpoint(t *testing.T) {
	store := &fakeProjectionAuthority{page: authority.ProjectionFactPage{
		HighWatermark: 9,
		Facts: []authority.ProjectionFact{{
			AuthorityRevision: 9, Kind: "case", CaseID: "case-1",
			EnvelopeID: "envelope-1", Commitment: "sha256:" + repeat("a", 64),
			Raw: []byte("{exact signed SSP}"),
		}},
	}}
	source := AuthoritySource{Store: store, TenantID: "tenant-a"}
	facts, err := source.ReadAfter(context.Background(), 7, 20)
	if err != nil {
		t.Fatal(err)
	}
	if store.query.TenantID != "tenant-a" || store.query.AfterAuthoritySequence != 7 ||
		store.query.Limit != 20 || len(facts) != 1 || facts[0].Sequence != 9 ||
		string(facts[0].Raw) != "{exact signed SSP}" {
		t.Fatalf("query=%#v facts=%#v", store.query, facts)
	}
	store.page.Facts[0].Raw[0] = 'X'
	if string(facts[0].Raw) != "{exact signed SSP}" {
		t.Fatal("authority source aliased store-owned raw bytes")
	}
}

func TestAuthoritySourceRejectsNonAdvancingAuthorityFact(t *testing.T) {
	source := AuthoritySource{
		TenantID: "tenant-a",
		Store: &fakeProjectionAuthority{page: authority.ProjectionFactPage{
			Facts: []authority.ProjectionFact{{AuthorityRevision: 7}},
		}},
	}
	if _, err := source.ReadAfter(context.Background(), 7, 1); err == nil {
		t.Fatal("accepted a non-advancing authority fact")
	}
}

type fakeProjectionAuthority struct {
	query authority.ProjectionFactQuery
	page  authority.ProjectionFactPage
	err   error
}

func (f *fakeProjectionAuthority) ListProjectionFacts(_ context.Context, query authority.ProjectionFactQuery) (authority.ProjectionFactPage, error) {
	f.query = query
	return f.page, f.err
}
