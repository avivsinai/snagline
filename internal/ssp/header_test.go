package ssp

import (
	"errors"
	"strings"
	"testing"

	"github.com/avivsinai/snagline/internal/identity"
)

func TestReadHeaderReturnsOnlyStrictlyDecodedRoutingMetadata(t *testing.T) {
	raw := []byte("{" + strings.Join(append(strictCaseMembers(strictCaseBody(), ""), `"signature":"placeholder"`), ",") + "}")

	header, err := ReadHeader(raw)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if got, want := header, (EnvelopeHeader{
		Schema:           FamilyCase,
		ID:               "case-envelope-1",
		CaseID:           "case-1",
		EmittedAt:        "2030-01-01T00:00:00Z",
		ExpiresAt:        "2030-01-01T01:00:00Z",
		RoutingEpoch:     7,
		RegistryRevision: 12,
		RegistryHash:     "sha256:" + strings.Repeat("a", 64),
		AuthorKeyID:      "key-1",
	}); got != want {
		t.Fatalf("ReadHeader() = %#v, want %#v", got, want)
	}
}

func TestReadHeaderRejectsNonStrictEnvelopeWires(t *testing.T) {
	validMembers := append(strictCaseMembers(strictCaseBody(), ""), `"signature":"placeholder"`)
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{
			name: "malformed JSON",
			raw:  []byte(`{"schema":"ssp.case.v1"`),
		},
		{
			name: "duplicate member",
			raw:  []byte("{" + strings.Join(append(validMembers, `"id":"other"`), ",") + "}"),
			want: ErrDuplicateKey,
		},
		{
			name: "unknown member",
			raw:  []byte("{" + strings.Join(append(validMembers, `"unexpected":true`), ",") + "}"),
			want: ErrUnknownField,
		},
		{
			name: "missing common required member",
			raw:  []byte("{" + strings.Join(withoutMember(validMembers, `"signature":"placeholder"`), ",") + "}"),
		},
		{
			name: "missing case family member",
			raw:  []byte("{" + strings.Join(withoutMember(validMembers, `"registry_hash":"sha256:`+strings.Repeat("a", 64)+`"`), ",") + "}"),
		},
		{
			name: "registry rejects case family members",
			raw: []byte("{" + strings.Join(replaceMember(validMembers,
				`"schema":"ssp.case.v1"`, `"schema":"ssp.registry.v1"`), ",") + "}"),
		},
		{
			name: "unsupported family",
			raw:  []byte(`{"schema":"ssp.future.v1"}`),
			want: ErrUnknownFamily,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ReadHeader(test.raw); err == nil {
				t.Fatal("ReadHeader accepted a non-strict envelope")
			} else if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("ReadHeader error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReadHeaderCanPeekStructurallyStrictButUnauthoritativeEnvelope(t *testing.T) {
	_, _, verifying := strictTestKeys(t)
	base := append(strictCaseMembers(strictCaseBody(), ""), `"signature":"not-a-signature"`)

	tests := []struct {
		name    string
		members []string
		verify  bool
	}{
		{
			name:    "invalid body",
			members: replaceMember(base, `"body":`+strictCaseBody(), `"body":{}`),
		},
		{
			name:    "invalid timestamps",
			members: replaceMember(base, `"emitted_at":"2030-01-01T00:00:00Z"`, `"emitted_at":"not-a-timestamp"`),
		},
		{
			name:    "invalid signature",
			members: base,
			verify:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte("{" + strings.Join(test.members, ",") + "}")
			header, err := ReadHeader(raw)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			if header.ID != "case-envelope-1" || header.CaseID != "case-1" {
				t.Fatalf("ReadHeader() = %#v, want case routing metadata", header)
			}

			if test.verify {
				if _, err := Verify(raw, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, strictTestNow()); err == nil {
					t.Fatal("Verify accepted an invalid signature")
				}
				return
			}
			if _, err := decodeAndValidate(raw, strictTestNow()); err == nil {
				t.Fatal("decodeAndValidate accepted invalid envelope content")
			}
		})
	}
}
