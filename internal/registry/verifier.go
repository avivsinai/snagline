package registry

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/ssp"
)

var ErrUnverified = errors.New("registry: candidate was not verified")

// Trust is the deployment-pinned root used only to authenticate registry
// artifacts. PostgreSQL, not this in-process verifier, owns accepted history.
type Trust struct {
	authorKeyID string
	publicKey   ed25519.PublicKey
}

func NewTrust(authorKeyID string, publicKey ed25519.PublicKey) (Trust, error) {
	if authorKeyID == "" {
		return Trust{}, errors.New("registry: trust author key id is required")
	}
	verifying, err := identity.NewEd25519VerifyingKey(publicKey)
	if err != nil {
		return Trust{}, fmt.Errorf("registry: trust public key: %w", err)
	}
	cloned, err := verifying.PublicKey()
	if err != nil {
		return Trust{}, fmt.Errorf("registry: trust public key: %w", err)
	}
	return Trust{authorKeyID: authorKeyID, publicKey: cloned}, nil
}

// Verified is immutable evidence produced by one root-verification operation.
// It carries no acceptance or delivery position; those are authority concerns.
type Verified struct {
	owner      *Verifier
	raw        []byte
	snapshot   Registry
	commitment string
}

func (v Verified) Commitment() (string, error) {
	if v.owner == nil || v.commitment == "" {
		return "", ErrUnverified
	}
	return v.commitment, nil
}

func (v Verified) Revision() (int64, error) {
	if v.owner == nil {
		return 0, ErrUnverified
	}
	return v.snapshot.Revision(), nil
}

// Snapshot returns a defensive copy of the independently verified registry.
func (v Verified) Snapshot() (Registry, error) {
	if v.owner == nil {
		return Registry{}, ErrUnverified
	}
	return cloneRegistry(v.snapshot), nil
}

// Verifier authenticates and decodes registry bytes against a pinned root.
// It deliberately has no apply, current, history, or broker-position API.
type Verifier struct {
	trust Trust
	clock func() time.Time
}

func NewVerifier(trust Trust, clock func() time.Time) (*Verifier, error) {
	if trust.authorKeyID == "" || len(trust.publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("registry: configured trust root is required")
	}
	if clock == nil {
		clock = time.Now
	}
	trust.publicKey = append(ed25519.PublicKey(nil), trust.publicKey...)
	return &Verifier{trust: trust, clock: clock}, nil
}

func (v *Verifier) Verify(raw []byte) (Verified, error) {
	if v == nil {
		return Verified{}, errors.New("registry: nil verifier")
	}
	now := v.clock().UTC()
	verifying, err := identity.NewEd25519VerifyingKey(v.trust.publicKey)
	if err != nil {
		return Verified{}, err
	}
	proof, err := ssp.VerifyRegistry(raw, v.trust.authorKeyID, verifying, now)
	if err != nil {
		return Verified{}, err
	}
	envelope, err := proof.Envelope()
	if err != nil {
		return Verified{}, err
	}
	commitment, err := proof.Commitment()
	if err != nil {
		return Verified{}, err
	}
	snapshot, err := decodeRegistry(envelope, commitment)
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		owner: v, raw: append([]byte(nil), raw...),
		snapshot: snapshot, commitment: commitment,
	}, nil
}

func cloneRegistry(in Registry) Registry {
	out := Registry{
		revision: in.revision, routingEpoch: in.routingEpoch,
		previousCommitment: in.previousCommitment,
		commitment:         in.commitment,
		authorKeyID:        in.authorKeyID,
		expiresAt:          in.expiresAt,
		domainsList:        cloneDomainRoutes(in.domainsList),
		principalsList:     clonePrincipalRecords(in.principalsList),
		edgesList:          append([]EdgeRecord(nil), in.edgesList...),
		keysList:           cloneKeyRecords(in.keysList),
	}
	out.index()
	return out
}
