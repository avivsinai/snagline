// snagline-dispatcher performs one inert SSP advice finalization. It has no
// provider adapter, no Buzz integration, and no generic signing command.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/securefile"
)

const maxDescriptorBytes = 4096

type dispatcherAPI interface {
	FinalizeAdvice(context.Context, edge.FinalizeAdviceRequest) (edge.AdviceSubmission, error)
}
type keyDescriptor struct {
	KeyPath string `json:"key_path"`
}
type commandResult struct {
	OK                bool   `json:"ok"`
	Code              string `json:"code"`
	AdviceID          string `json:"advice_id,omitempty"`
	AuthorityRevision int64  `json:"authority_revision,omitempty"`
}

func main() {
	config, err := parseDispatcherRuntimeConfig(os.Args[1:], os.Stdin)
	if err != nil {
		os.Exit(writeResult(os.Stdout, commandResult{OK: false, Code: "invalid_arguments"}))
	}
	os.Exit(runDispatcher(context.Background(), config, os.Stdout))
}

// run is intentionally one-shot. The injected factory owns descriptor-to-key
// resolution and local Unix-socket gateway construction; this command never
// accepts a raw key, prints key material, or offers a generic sign operation.
func run(args []string, factory func(keyDescriptor) (dispatcherAPI, error), stdout io.Writer) int {
	flags := flag.NewFlagSet("snagline-dispatcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	descriptorPath := flags.String("key-descriptor", "", "absolute private key descriptor")
	caseID := flags.String("case-id", "", "case ID")
	caseCommitment := flags.String("case-commitment", "", "exact committed case commitment")
	text := flags.String("text", "", "inert advice text")
	publicSummary := flags.String("public-summary", "", "explicit public advice summary")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*descriptorPath) || *caseID == "" || *caseCommitment == "" || *text == "" || *publicSummary == "" {
		return writeResult(stdout, commandResult{OK: false, Code: "invalid_arguments"})
	}
	descriptor, err := readKeyDescriptor(*descriptorPath)
	if err != nil {
		return writeResult(stdout, commandResult{OK: false, Code: "invalid_key_descriptor"})
	}
	service, err := factory(descriptor)
	if err != nil || service == nil {
		return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
	}
	result, err := service.FinalizeAdvice(context.Background(), edge.FinalizeAdviceRequest{CaseID: *caseID, CaseCommitment: *caseCommitment, Text: *text, PublicSummary: *publicSummary})
	if err != nil || !result.AcceptedRemote {
		return writeResult(stdout, commandResult{OK: false, Code: "advice_not_accepted"})
	}
	return writeResult(stdout, commandResult{OK: true, Code: "accepted_remote", AdviceID: result.EnvelopeID, AuthorityRevision: result.Receipt.Revision})
}

// readKeyDescriptor validates the descriptor through the opened file descriptor
// so path swaps/symlinks cannot redirect the factory to attacker-controlled
// key material. The descriptor contains only an absolute key pathname.
func readKeyDescriptor(path string) (keyDescriptor, error) {
	if !filepath.IsAbs(path) {
		return keyDescriptor{}, errors.New("descriptor must be absolute")
	}
	raw, err := securefile.ReadPrivateBounded(path, maxDescriptorBytes)
	if err != nil || len(raw) == 0 || len(raw) > maxDescriptorBytes {
		return keyDescriptor{}, errors.New("descriptor rejected")
	}
	var descriptor keyDescriptor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil || descriptor.KeyPath == "" || !filepath.IsAbs(descriptor.KeyPath) {
		return keyDescriptor{}, errors.New("descriptor rejected")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return keyDescriptor{}, errors.New("descriptor rejected")
	}
	return descriptor, nil
}

func writeResult(w io.Writer, result commandResult) int {
	if err := json.NewEncoder(w).Encode(result); err != nil {
		return 1
	}
	if !result.OK {
		return 1
	}
	return 0
}
