package registry

import (
	"errors"
	"fmt"
	"time"
)

// EpochVerdict is the result of fencing an envelope against a domain's current
// routing epoch.
type EpochVerdict string

const (
	// EpochCurrent means the envelope was authored under the routing epoch this
	// domain is currently on. Only these may be machine-accepted.
	EpochCurrent EpochVerdict = "current"
	// EpochHistorical means the envelope predates a dispatcher change. It stays
	// readable as history and must never be machine-accepted for a live case:
	// that is the whole point of bumping the epoch when a dispatcher rotates.
	EpochHistorical EpochVerdict = "historical"
	// EpochFuture means the envelope names a newer epoch than this edge knows
	// about, so our registry is stale. It fails closed rather than being
	// treated as current, because we cannot evaluate authority under an epoch we
	// have not seen.
	EpochFuture EpochVerdict = "future"
)

// ErrUnknownDomain reports that a domain is absent from the snapshot.
var ErrUnknownDomain = errors.New("registry: unknown domain")

// EvaluateEpoch fences an envelope's routing epoch against a domain route.
func (r Registry) EvaluateEpoch(domain string, envelopeRoutingEpoch int64) (EpochVerdict, error) {
	route, ok := r.domains[domain]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownDomain, domain)
	}
	switch {
	case envelopeRoutingEpoch == route.RoutingEpoch:
		return EpochCurrent, nil
	case envelopeRoutingEpoch < route.RoutingEpoch:
		return EpochHistorical, nil
	default:
		return EpochFuture, nil
	}
}

// MachineAcceptableEpoch reports whether an envelope's routing epoch permits
// machine acceptance for a live case. Anything other than the current epoch is
// refused, including a future one.
func (r Registry) MachineAcceptableEpoch(domain string, envelopeRoutingEpoch int64) bool {
	verdict, err := r.EvaluateEpoch(domain, envelopeRoutingEpoch)
	return err == nil && verdict == EpochCurrent
}

// CheckBinding verifies that an envelope's registry commitment names exactly
// this snapshot.
//
// The revision-match-hash-mismatch case is the one that matters: an envelope
// naming our revision with a different commitment was authored against a
// different snapshot at that revision, which is precisely the equivocation the
// store refuses to accept. It fails closed rather than being treated as a
// version skew.
func (r Registry) CheckBinding(revision int64, commitment string) error {
	if revision != r.revision {
		return fmt.Errorf("registry: envelope binds revision %d, snapshot is %d", revision, r.revision)
	}
	if commitment != r.commitment {
		return fmt.Errorf("registry: envelope binds a different snapshot at revision %d", revision)
	}
	return nil
}

// Expired reports whether the snapshot's own validity window has passed.
//
// An expired snapshot is not automatically useless: display of existing advice
// continues on last-known authority, while anything that causes an effect must
// fail closed. Callers make that distinction; this only reports the fact.
func (r Registry) Expired(at time.Time) bool {
	return !r.expiresAt.IsZero() && !at.Before(r.expiresAt)
}
