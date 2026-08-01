package buzz

import (
	"context"
	"errors"
	"math"
	"strings"

	"github.com/avivsinai/snagline/internal/authority"
)

// ProjectionAuthority is the read-only database boundary needed by the Buzz
// projector. It cannot acknowledge, mutate, or delete semantic facts.
type ProjectionAuthority interface {
	ListProjectionFacts(context.Context, authority.ProjectionFactQuery) (authority.ProjectionFactPage, error)
}

// AuthoritySource rebuilds the disposable Buzz projection directly from
// PostgreSQL. JetStream may wake the worker, but never supplies its checkpoint.
type AuthoritySource struct {
	Store    ProjectionAuthority
	TenantID string
}

var _ FactSource = AuthoritySource{}

func (s AuthoritySource) ReadAfter(ctx context.Context, after uint64, limit int) ([]CommittedFact, error) {
	if s.Store == nil || strings.TrimSpace(s.TenantID) == "" {
		return nil, errors.New("collab buzz: projection authority and tenant are required")
	}
	if after > math.MaxInt64 {
		return nil, errors.New("collab buzz: authority checkpoint exceeds supported range")
	}
	page, err := s.Store.ListProjectionFacts(ctx, authority.ProjectionFactQuery{
		TenantID: s.TenantID, AfterAuthoritySequence: int64(after), Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	facts := make([]CommittedFact, len(page.Facts))
	for i, fact := range page.Facts {
		if fact.AuthorityRevision <= int64(after) || fact.AuthorityRevision <= 0 {
			return nil, errors.New("collab buzz: authority returned a non-advancing fact")
		}
		facts[i] = CommittedFact{
			Sequence: uint64(fact.AuthorityRevision), EnvelopeID: fact.EnvelopeID,
			Commitment: fact.Commitment, Raw: append([]byte(nil), fact.Raw...),
		}
	}
	return facts, nil
}
