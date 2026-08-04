// snagline-case is the one-shot trusted adapter between one agent session and
// one deployment-bound Snagline case. The agent cannot select an edge socket,
// case ID, domain, context commitment, or registry generation.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/avivsinai/snagline/internal/edgeclient"
	"github.com/avivsinai/snagline/internal/securefile"
)

const (
	operationTimeout      = 15 * time.Second
	sessionBindingPath    = "/run/snagline-case/session.json"
	maxSessionBindingSize = 8 << 10
	maxOpenInputSize      = 32 << 10
)

var exactSHA256 = regexp.MustCompile(`\Asha256:[0-9a-f]{64}\z`)

type caseConfig struct{ Mode string }

type sessionBinding struct {
	Socket          string                         `json:"socket"`
	CaseID          string                         `json:"case_id"`
	Domain          string                         `json:"domain"`
	ContextManifest string                         `json:"context_manifest"`
	Registry        edgeclient.RegistryCoordinates `json:"registry"`
}

type openInput struct {
	Summary       string `json:"summary"`
	PublicSummary string `json:"public_summary"`
}

type commandResult struct {
	OK                bool         `json:"ok"`
	Code              string       `json:"code"`
	CaseID            string       `json:"case_id"`
	EnvelopeID        string       `json:"envelope_id,omitempty"`
	Commitment        string       `json:"commitment,omitempty"`
	AuthorityID       string       `json:"authority_id,omitempty"`
	AuthorityRevision int64        `json:"authority_revision,omitempty"`
	Committed         bool         `json:"committed,omitempty"`
	ExpiresAt         time.Time    `json:"expires_at,omitempty"`
	Advice            []safeAdvice `json:"advice,omitempty"`
}

type safeAdvice struct {
	AdviceID   string    `json:"advice_id"`
	ReceivedAt time.Time `json:"received_at"`
}

func main() {
	config, err := parseCaseConfig(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	if err := runCase(context.Background(), config, sessionBindingPath, os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}

func parseCaseConfig(args []string) (caseConfig, error) {
	if len(args) != 1 {
		return caseConfig{}, errors.New("snagline-case: exactly one mode is required")
	}
	switch args[0] {
	case "open", "retry", "get", "advice":
		return caseConfig{Mode: args[0]}, nil
	default:
		return caseConfig{}, errors.New("snagline-case: mode must be open, retry, get, or advice")
	}
}

func readSessionBinding(path string) (sessionBinding, error) {
	raw, err := securefile.ReadPrivateBounded(path, maxSessionBindingSize)
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
		return sessionBinding{}, errors.New("snagline-case: session binding rejected")
	}
	var binding sessionBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!filepath.IsAbs(binding.Socket) || filepath.Clean(binding.Socket) != binding.Socket ||
		!validRunes(binding.CaseID, 512) || !validRunes(binding.Domain, 512) ||
		!exactSHA256.MatchString(binding.ContextManifest) || !exactSHA256.MatchString(binding.Registry.Hash) ||
		binding.Registry.RoutingEpoch < 0 || binding.Registry.Revision < 0 {
		return sessionBinding{}, errors.New("snagline-case: session binding rejected")
	}
	return binding, nil
}

func readOpenInput(r io.Reader) (openInput, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxOpenInputSize+1))
	if err != nil || len(raw) == 0 || len(raw) > maxOpenInputSize || !utf8.Valid(raw) {
		return openInput{}, errors.New("snagline-case: open input rejected")
	}
	var input openInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!validRunes(input.Summary, 4096) || !validRunes(input.PublicSummary, 1024) {
		return openInput{}, errors.New("snagline-case: open input rejected")
	}
	return input, nil
}

func runCase(ctx context.Context, config caseConfig, bindingPath string, stdin io.Reader, stdout io.Writer) error {
	binding, err := readSessionBinding(bindingPath)
	if err != nil {
		return err
	}
	var input openInput
	if config.Mode == "open" {
		input, err = readOpenInput(stdin)
		if err != nil {
			return err
		}
	}
	client, err := edgeclient.New(edgeclient.Config{Socket: binding.Socket})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	switch config.Mode {
	case "open":
		submission, err := client.OpenCase(ctx, edgeclient.OpenCaseRequest{CaseID: binding.CaseID, Domain: binding.Domain, Summary: input.Summary, PublicSummary: input.PublicSummary, ContextManifest: binding.ContextManifest, Registry: binding.Registry})
		if err != nil {
			return err
		}
		return writeJSON(stdout, acceptedResult(submission))
	case "retry":
		submission, err := client.RetryCase(ctx, binding.CaseID)
		if err != nil {
			return err
		}
		return writeJSON(stdout, acceptedResult(submission))
	case "get":
		record, err := client.GetCase(ctx, binding.CaseID)
		if err != nil {
			return err
		}
		return writeJSON(stdout, commandResult{OK: true, Code: "case_status", CaseID: record.CaseID, EnvelopeID: record.EnvelopeID, Commitment: record.Commitment, Committed: record.Committed, ExpiresAt: record.ExpiresAt})
	case "advice":
		views, err := client.ListAdvice(ctx, binding.CaseID)
		if err != nil {
			return err
		}
		result := commandResult{OK: true, Code: "advice_status", CaseID: binding.CaseID, Advice: make([]safeAdvice, 0, len(views))}
		for _, view := range views {
			result.Advice = append(result.Advice, safeAdvice{AdviceID: view.AdviceID, ReceivedAt: view.ReceivedAt})
		}
		return writeJSON(stdout, result)
	default:
		return errors.New("snagline-case: unreachable mode")
	}
}

func acceptedResult(submission edgeclient.CaseSubmission) commandResult {
	return commandResult{OK: true, Code: "accepted_remote", CaseID: submission.CaseID, EnvelopeID: submission.EnvelopeID, Commitment: submission.Commitment, AuthorityID: submission.Receipt.AuthorityID, AuthorityRevision: submission.Receipt.Revision}
}

func validRunes(value string, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= max
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
