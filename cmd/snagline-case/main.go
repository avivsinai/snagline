// snagline-case is the one-shot trusted adapter for opening and reading a
// Snagline case over the edge's private local API. It runs under the edge
// service UID, validates its input, and speaks only to the local Unix socket
// through the bounded edgeclient. It has no SQLite, SSP, PostgreSQL, NATS, or
// Buzz access, and it performs no provider action: advice it prints is inert
// text.
//
// It exists because nothing else opens a case. An agent must not be given the
// edge UID; instead it invokes this bounded command and consumes the JSON the
// command prints. Registry coordinates cannot be discovered locally and are
// supplied by the caller from trusted deployment configuration.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/avivsinai/snagline/internal/edgeclient"
)

const operationTimeout = 15 * time.Second

type caseConfig struct {
	Mode   string
	Socket string
	CaseID string
	// open-only inputs
	Domain, Summary, PublicSummary, ContextManifest, RegistryHash string
	RoutingEpoch, Revision                                        int64
}

func main() {
	config, err := parseCaseConfig(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	if err := runCase(context.Background(), config, os.Stdout); err != nil {
		os.Exit(1)
	}
}

func parseCaseConfig(args []string) (caseConfig, error) {
	if len(args) == 0 {
		return caseConfig{}, errors.New("snagline-case: a mode is required")
	}
	mode := args[0]
	flags := flag.NewFlagSet("snagline-case", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", "", "absolute edge Unix socket path")
	caseID := flags.String("case-id", "", "bounded opaque case identifier")
	domain := flags.String("domain", "", "bounded opaque case domain (open)")
	summary := flags.String("summary", "", "confidential case summary, 1..4096 code points (open)")
	publicSummary := flags.String("public-summary", "", "Buzz-projected summary, 1..1024 code points (open)")
	contextManifest := flags.String("context-manifest", "", "sha256 context-manifest commitment (open)")
	registryHash := flags.String("registry-hash", "", "sha256 registry commitment from deployment config (open)")
	routingEpoch := flags.Int64("routing-epoch", -1, "registry routing epoch from deployment config (open)")
	revision := flags.Int64("revision", -1, "registry revision from deployment config (open)")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return caseConfig{}, errors.New("snagline-case: invalid flags")
	}
	config := caseConfig{
		Mode: mode, Socket: *socket, CaseID: *caseID,
		Domain: *domain, Summary: *summary, PublicSummary: *publicSummary,
		ContextManifest: *contextManifest, RegistryHash: *registryHash,
		RoutingEpoch: *routingEpoch, Revision: *revision,
	}
	if !filepath.IsAbs(config.Socket) || filepath.Clean(config.Socket) != config.Socket {
		return caseConfig{}, errors.New("snagline-case: socket must be an absolute clean path")
	}
	switch config.Mode {
	case "open", "get", "advice":
	default:
		return caseConfig{}, errors.New("snagline-case: mode must be open, get, or advice")
	}
	return config, nil
}

func runCase(ctx context.Context, config caseConfig, stdout io.Writer) error {
	client, err := edgeclient.New(edgeclient.Config{Socket: config.Socket})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	switch config.Mode {
	case "open":
		submission, err := client.OpenCase(ctx, edgeclient.OpenCaseRequest{
			CaseID:          config.CaseID,
			Domain:          config.Domain,
			Summary:         config.Summary,
			PublicSummary:   config.PublicSummary,
			ContextManifest: config.ContextManifest,
			Registry: edgeclient.RegistryCoordinates{
				RoutingEpoch: config.RoutingEpoch,
				Revision:     config.Revision,
				Hash:         config.RegistryHash,
			},
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, submission)
	case "get":
		record, err := client.GetCase(ctx, config.CaseID)
		if err != nil {
			return err
		}
		return writeJSON(stdout, record)
	case "advice":
		advice, err := client.ListAdvice(ctx, config.CaseID)
		if err != nil {
			return err
		}
		return writeJSON(stdout, advice)
	default:
		return errors.New("snagline-case: unreachable mode")
	}
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
