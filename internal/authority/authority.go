// Package authority defines the transactional authority boundary for SSP.
//
// PostgreSQL is the semantic source of truth. Delivery systems consume the
// outbox after a commit; they neither decide admission nor issue receipts.
package authority

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidRequest           = errors.New("authority: invalid request")
	ErrConflictingCase          = errors.New("authority: conflicting case identity")
	ErrCaseNotFound             = errors.New("authority: committed case not found")
	ErrCaseBinding              = errors.New("authority: advice does not bind the committed case")
	ErrFinalAdviceAlreadySet    = errors.New("authority: final advice already committed")
	ErrConflictingRegistry      = errors.New("authority: conflicting registry revision")
	ErrRegistryRevisionSequence = errors.New("authority: registry revision is not next")
	ErrRegistryEquivocation     = errors.New("authority: registry predecessor conflicts with the committed head")
	ErrRegistryRollback         = errors.New("authority: registry revision rolls back the committed head")
	ErrRegistryHalted           = errors.New("authority: registry head is halted")
	ErrRegistryBinding          = errors.New("authority: case does not bind the current registry head")
	ErrEdgeGenerationRollback   = errors.New("authority: edge generation does not advance after removal or rollback")
	ErrEdgeNotActive            = errors.New("authority: edge identity is not active in the current registry")
	ErrRegistryNotFound         = errors.New("authority: registry not found")
	ErrRegistryHeadNotFound     = errors.New("authority: registry head not found")
)

// Store is the global transaction boundary. Callers provide only facts that
// were already SSP-verified. In particular, CommitAdviceRequest deliberately
// has no route or target fields: the store derives them from its committed
// case row while holding the transaction lock.
type Store interface {
	CommitCase(context.Context, CommitCaseRequest) (CommitReceipt, error)
	CommitAdvice(context.Context, CommitAdviceRequest) (CommitReceipt, error)
	CommitRegistry(context.Context, CommitRegistryRequest) (CommitReceipt, error)
	ListEdgeDeliveries(context.Context, EdgeDeliveryQuery) (EdgeDeliveryPage, error)
	ListProjectionFacts(context.Context, ProjectionFactQuery) (ProjectionFactPage, error)
	ResolveCase(context.Context, string, string, string) (CaseRecord, error)
	ResolveRegistry(context.Context, string, int64, string) (RegistryRecord, error)
	CurrentRegistryHead(context.Context, string) (RegistryHead, error)
}

// CommitReceipt is returned only after the durable database transaction has
// committed. Revision identifies the immutable authority commit, not a
// transport acknowledgement.
type CommitReceipt struct {
	AuthorityID string
	Revision    int64
	EnvelopeID  string
	Commitment  string
}

// CommitCaseRequest is an already-verified case fact. Raw is the original
// received SSP byte sequence and must never be reserialized by the store.
type CommitCaseRequest struct {
	TenantID                 string
	CaseID                   string
	EnvelopeID               string
	Commitment               string
	Raw                      []byte
	Domain                   string
	IssuerEdgeID             string
	IssuerEdgeGeneration     int64
	RoutingEpoch             int64
	RegistryRevision         int64
	RegistryHash             string
	ExpiresAt                time.Time
	AuthenticatedPrincipalID string
	AuthenticatedEdgeID      string
	Decision                 string
}

func (r CommitCaseRequest) Validate() error {
	if !validText(r.TenantID) || !validText(r.CaseID) || !validText(r.EnvelopeID) ||
		!validCommitment(r.Commitment) || len(r.Raw) == 0 || !validText(r.Domain) ||
		!validText(r.IssuerEdgeID) || r.IssuerEdgeGeneration <= 0 || r.RoutingEpoch < 0 ||
		r.RegistryRevision < 0 || !validCommitment(r.RegistryHash) || r.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: complete case identity, raw SSP bytes, and positive edge generation are required", ErrInvalidRequest)
	}
	return nil
}

func (r CommitCaseRequest) clone() CommitCaseRequest {
	r.Raw = append([]byte(nil), r.Raw...)
	return r
}

// CommitAdviceRequest contains no target-edge coordinate. The target edge,
// generation, and delivery sequence are selected from the committed case.
type CommitAdviceRequest struct {
	TenantID                 string
	CaseID                   string
	EnvelopeID               string
	CaseCommitment           string
	Commitment               string
	Raw                      []byte
	RoutingEpoch             int64
	RegistryRevision         int64
	RegistryHash             string
	AuthenticatedPrincipalID string
	AuthenticatedEdgeID      string
	Decision                 string
}

func (r CommitAdviceRequest) Validate() error {
	if !validText(r.TenantID) || !validText(r.CaseID) || !validText(r.EnvelopeID) ||
		!validCommitment(r.CaseCommitment) || !validCommitment(r.Commitment) || len(r.Raw) == 0 ||
		r.RoutingEpoch < 0 || r.RegistryRevision < 0 || !validCommitment(r.RegistryHash) {
		return fmt.Errorf("%w: complete advice and committed-case identity plus raw SSP bytes are required", ErrInvalidRequest)
	}
	return nil
}

func (r CommitAdviceRequest) clone() CommitAdviceRequest {
	r.Raw = append([]byte(nil), r.Raw...)
	return r
}

// RegistryEdge is the complete signed identity of one edge installation.
type RegistryEdge struct {
	PrincipalID string
	Generation  int64
}

// CommitRegistryRequest records verified registry evidence at the next
// positive tenant-local revision.
type CommitRegistryRequest struct {
	TenantID                 string
	Revision                 int64
	EnvelopeID               string
	Commitment               string
	Raw                      []byte
	RoutingEpoch             int64
	PreviousCommitment       string
	Edges                    map[string]RegistryEdge
	AuthenticatedPrincipalID string
	AuthenticatedEdgeID      string
	Decision                 string
}

func (r CommitRegistryRequest) Validate() error {
	if !validText(r.TenantID) || r.Revision <= 0 || !validText(r.EnvelopeID) ||
		!validCommitment(r.Commitment) || len(r.Raw) == 0 || r.RoutingEpoch < 0 ||
		(r.PreviousCommitment != "" && !validCommitment(r.PreviousCommitment)) ||
		r.Edges == nil {
		return fmt.Errorf("%w: complete registry identity, non-negative revision, and raw SSP bytes are required", ErrInvalidRequest)
	}
	for edgeID, edge := range r.Edges {
		if !validText(edgeID) || !validText(edge.PrincipalID) || edge.Generation <= 0 {
			return fmt.Errorf("%w: edge IDs, principals, and generations must be non-empty and positive", ErrInvalidRequest)
		}
	}
	return nil
}

// EdgeDeliveryQuery reads the immutable per-edge delivery log after the
// caller's acknowledged sequence. Limit is intentionally bounded to avoid a
// replica turning recovery into an unbounded database read.
type EdgeDeliveryQuery struct {
	TenantID       string
	EdgeID         string
	PrincipalID    string
	EdgeGeneration int64
	AfterSequence  int64
	Limit          int
}

func (q EdgeDeliveryQuery) Validate() error {
	if !validText(q.TenantID) || !validText(q.EdgeID) || !validText(q.PrincipalID) || q.EdgeGeneration <= 0 ||
		q.AfterSequence < 0 || q.Limit <= 0 || q.Limit > 1000 {
		return fmt.Errorf("%w: tenant, positive edge generation, non-negative cursor, and 1..1000 limit are required", ErrInvalidRequest)
	}
	return nil
}

type EdgeDelivery struct {
	Sequence          int64
	Kind              string
	CaseID            string
	EnvelopeID        string
	Commitment        string
	Raw               []byte
	AuthorityRevision int64
}

type EdgeDeliveryPage struct {
	Deliveries      []EdgeDelivery
	HighWatermark   int64
	CompleteThrough int64
}

// ProjectionFactQuery is the durable, database-backed source for rebuilding
// stock-Buzz facts. It deliberately does not read delivery state or JetStream.
type ProjectionFactQuery struct {
	TenantID               string
	AfterAuthoritySequence int64
	Limit                  int
}

func (q ProjectionFactQuery) Validate() error {
	if !validText(q.TenantID) || q.AfterAuthoritySequence < 0 || q.Limit <= 0 || q.Limit > 1000 {
		return fmt.Errorf("%w: tenant, non-negative authority cursor, and 1..1000 limit are required", ErrInvalidRequest)
	}
	return nil
}

type ProjectionFact struct {
	AuthorityRevision int64
	Kind              string
	CaseID            string
	EnvelopeID        string
	Commitment        string
	Raw               []byte
}

type ProjectionFactPage struct {
	Facts         []ProjectionFact
	HighWatermark int64
}

// CaseRecord is the indexed immutable case source used by advice admission.
// Raw remains the exact signed wire and must be independently verified by the
// control service before any authorization decision.
type CaseRecord struct {
	TenantID             string
	CaseID               string
	EnvelopeID           string
	Commitment           string
	Raw                  []byte
	Domain               string
	IssuerEdgeID         string
	IssuerEdgeGeneration int64
	RoutingEpoch         int64
	RegistryRevision     int64
	RegistryHash         string
	ExpiresAt            time.Time
	AuthorityRevision    int64
}

// RegistryRecord is an exact committed registry artifact for stateless
// replicas. Raw is copied by implementations before it crosses the boundary.
type RegistryRecord struct {
	TenantID           string
	Revision           int64
	EnvelopeID         string
	Commitment         string
	Raw                []byte
	RoutingEpoch       int64
	PreviousCommitment string
	AuthorityRevision  int64
}

type RegistryHead struct {
	TenantID     string
	Revision     int64
	Commitment   string
	RoutingEpoch int64
	Halted       bool
	HaltReason   string
}

func (r CommitRegistryRequest) clone() CommitRegistryRequest {
	r.Raw = append([]byte(nil), r.Raw...)
	r.Edges = cloneRegistryEdges(r.Edges)
	return r
}

func cloneRegistryEdges(source map[string]RegistryEdge) map[string]RegistryEdge {
	if source == nil {
		return nil
	}
	clone := make(map[string]RegistryEdge, len(source))
	for edgeID, edge := range source {
		clone[edgeID] = edge
	}
	return clone
}

func validText(value string) bool { return strings.TrimSpace(value) != "" }

func validCommitment(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, char := range value[len(prefix):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
