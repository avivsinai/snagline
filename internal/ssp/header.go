package ssp

// EnvelopeHeader is untrusted routing metadata decoded from a structurally
// strict SSP envelope. It is never authority: callers must validate the
// envelope and verify its signature before using any of these values for an
// authorization, integrity, or effect decision.
//
// It intentionally contains only plain value fields. In particular, it does
// not expose the envelope body or signature.
type EnvelopeHeader struct {
	Schema           string
	ID               string
	CaseID           string
	EmittedAt        string
	ExpiresAt        string
	RoutingEpoch     int64
	RegistryRevision int64
	RegistryHash     string
	AuthorKeyID      string
}

// ReadHeader strictly decodes untrusted SSP routing metadata without treating
// it as an authenticated envelope. It rejects malformed input and violations
// of the SSP envelope member rules, but deliberately does not validate body or
// timestamp semantics, calculate a commitment, or verify a signature.
func ReadHeader(raw []byte) (EnvelopeHeader, error) {
	envelope, err := decodeStrictEnvelope(raw)
	if err != nil {
		return EnvelopeHeader{}, err
	}

	return EnvelopeHeader{
		Schema:           envelope.Schema,
		ID:               envelope.ID,
		CaseID:           envelope.CaseID,
		EmittedAt:        envelope.EmittedAt,
		ExpiresAt:        envelope.ExpiresAt,
		RoutingEpoch:     envelope.RoutingEpoch,
		RegistryRevision: envelope.RegistryRevision,
		RegistryHash:     envelope.RegistryHash,
		AuthorKeyID:      envelope.AuthorKeyID,
	}, nil
}
