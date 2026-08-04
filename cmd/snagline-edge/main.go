// snagline-edge serves the local, provider-neutral support boundary over a
// Unix socket. It deliberately contains no provider effects or Buzz wiring.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/runtimeops"
	"github.com/avivsinai/snagline/internal/sspedge"
)

type edgeAPI interface {
	OpenCase(context.Context, edge.OpenCaseRequest) (edge.CaseSubmission, error)
	RetryCase(context.Context, string) (edge.CaseSubmission, error)
	GetCase(context.Context, string) (edge.CaseRecord, error)
	ListAdvice(context.Context, string) ([]edge.AdviceView, error)
	PresentAdvice(context.Context, string) (edge.AdviceView, error)
	ClaimFrontDeliveries(context.Context, sspedge.Front, string, time.Duration, int, time.Time) ([]sspedge.FrontDelivery, error)
	MarkFrontDelivered(context.Context, sspedge.FrontReceipt, time.Time) (sspedge.DeliveryOutcome, error)
}

// edgeLocalAPI joins the public provider-neutral edge service to the edge's
// own durable display outbox. Other local processes only use these methods
// through the versioned Unix socket; they never open the SQLite database.
type edgeLocalAPI struct {
	*edge.Service
	db *sspedge.DB
}

func (api edgeLocalAPI) ClaimFrontDeliveries(ctx context.Context, front sspedge.Front, owner string, ttl time.Duration, limit int, now time.Time) ([]sspedge.FrontDelivery, error) {
	return api.db.ClaimFrontDeliveries(ctx, front, owner, ttl, limit, now)
}
func (api edgeLocalAPI) MarkFrontDelivered(ctx context.Context, receipt sspedge.FrontReceipt, now time.Time) (sspedge.DeliveryOutcome, error) {
	return api.db.MarkFrontDelivered(ctx, receipt, now)
}

type apiError struct {
	OK   bool   `json:"ok"`
	Code string `json:"code"`
}

type openCaseRequestWire struct {
	CaseID          string `json:"case_id"`
	Domain          string `json:"domain"`
	Summary         string `json:"summary"`
	PublicSummary   string `json:"public_summary"`
	ContextManifest string `json:"context_manifest"`
	Registry        struct {
		RoutingEpoch int64  `json:"routing_epoch"`
		Revision     int64  `json:"revision"`
		Hash         string `json:"hash"`
	} `json:"registry"`
}

type commitReceiptResponseWire struct {
	AuthorityID string `json:"AuthorityID"`
	Revision    int64  `json:"Revision"`
	EnvelopeID  string `json:"EnvelopeID"`
	Commitment  string `json:"Commitment"`
}

type caseSubmissionResponseWire struct {
	EnvelopeID     string                    `json:"EnvelopeID"`
	CaseID         string                    `json:"CaseID"`
	Commitment     string                    `json:"Commitment"`
	AcceptedRemote bool                      `json:"AcceptedRemote"`
	Receipt        commitReceiptResponseWire `json:"Receipt"`
}

type registryResponseWire struct {
	RoutingEpoch int64  `json:"RoutingEpoch"`
	Revision     int64  `json:"Revision"`
	Hash         string `json:"Hash"`
}

type caseRecordResponseWire struct {
	EnvelopeID string               `json:"EnvelopeID"`
	CaseID     string               `json:"CaseID"`
	Commitment string               `json:"Commitment"`
	Summary    string               `json:"Summary"`
	Registry   registryResponseWire `json:"Registry"`
	ExpiresAt  time.Time            `json:"ExpiresAt"`
	Committed  bool                 `json:"Committed"`
}

type adviceResponseWire struct {
	AdviceID   string    `json:"AdviceID"`
	CaseID     string    `json:"CaseID"`
	Text       string    `json:"Text"`
	ReceivedAt time.Time `json:"ReceivedAt"`
}

func main() {
	config, err := parseEdgeRuntimeConfig(os.Args[1:])
	if err != nil {
		os.Exit(writeJSON(os.Stdout, apiError{OK: false, Code: "invalid_arguments"}))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runEdge(ctx, config); err != nil {
		// Every startup failure inside runEdge reports the same stdout code, so
		// without this the cause is unrecoverable from a container log. Errors
		// leaving runEdge are curated strings, never wrapped OS errors, so this
		// cannot publish a socket path. The stdout contract is unchanged.
		log.Printf("snagline-edge: runtime unavailable: %v", err)
		os.Exit(writeJSON(os.Stdout, apiError{OK: false, Code: "runtime_unavailable"}))
	}
}

// run is the narrow injected local-API harness used by focused tests. The
// production composition is runEdge in runtime.go.
func run(args []string, factory func() (edgeAPI, error), stdout io.Writer) int {
	flags := flag.NewFlagSet("snagline-edge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", "", "absolute Unix socket path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*socket) {
		return writeJSON(stdout, apiError{OK: false, Code: "invalid_arguments"})
	}
	service, err := factory()
	if err != nil || service == nil {
		return writeJSON(stdout, apiError{OK: false, Code: "runtime_unavailable"})
	}
	listener, err := runtimeops.ListenUnix(*socket)
	if err != nil {
		return writeJSON(stdout, apiError{OK: false, Code: "listen_failed"})
	}
	defer listener.Close()
	if err := http.Serve(listener, newHandler(service)); err != nil {
		return 1
	}
	return 0
}

func newHandler(service edgeAPI) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		var input openCaseRequestWire
		if err := decodeJSON(r, &input); err != nil {
			writeHTTP(w, http.StatusBadRequest, apiError{OK: false, Code: "invalid_request"})
			return
		}
		result, err := service.OpenCase(r.Context(), edge.OpenCaseRequest{CaseID: input.CaseID, Domain: input.Domain, Summary: input.Summary, PublicSummary: input.PublicSummary, ContextManifest: input.ContextManifest, Registry: edge.RegistryCoordinates{RoutingEpoch: input.Registry.RoutingEpoch, Revision: input.Registry.Revision, Hash: input.Registry.Hash}})
		if err != nil {
			writeHTTP(w, http.StatusUnprocessableEntity, apiError{OK: false, Code: "case_rejected"})
			return
		}
		writeHTTP(w, http.StatusAccepted, caseSubmissionResponse(result))
	})
	mux.HandleFunc("POST /v1/cases/{caseID}/retry", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			writeHTTP(w, http.StatusBadRequest, apiError{OK: false, Code: "invalid_request"})
			return
		}
		result, err := service.RetryCase(r.Context(), r.PathValue("caseID"))
		if err != nil {
			writeHTTP(w, http.StatusUnprocessableEntity, apiError{OK: false, Code: "retry_rejected"})
			return
		}
		writeHTTP(w, http.StatusAccepted, caseSubmissionResponse(result))
	})
	mux.HandleFunc("POST /v1/fronts/{front}/claims", func(w http.ResponseWriter, r *http.Request) {
		front, ok := parseFront(r.PathValue("front"))
		if !ok {
			writeHTTP(w, http.StatusNotFound, apiError{OK: false, Code: "not_found"})
			return
		}
		var input struct {
			Owner        string `json:"owner"`
			LeaseSeconds int64  `json:"lease_seconds"`
			Limit        int    `json:"limit"`
		}
		if err := decodeJSON(r, &input); err != nil || !validFrontOwner(input.Owner) || input.LeaseSeconds < 1 || input.LeaseSeconds > 900 || input.Limit < 1 || input.Limit > 6 {
			writeHTTP(w, http.StatusBadRequest, apiError{OK: false, Code: "invalid_request"})
			return
		}
		deliveries, err := service.ClaimFrontDeliveries(r.Context(), front, input.Owner, time.Duration(input.LeaseSeconds)*time.Second, input.Limit, time.Now().UTC())
		if err != nil {
			writeHTTP(w, http.StatusUnprocessableEntity, apiError{OK: false, Code: "claim_rejected"})
			return
		}
		result := struct {
			Deliveries []struct {
				CaseID     string `json:"case_id"`
				AdviceID   string `json:"advice_id"`
				MessageID  string `json:"message_id"`
				Text       string `json:"text"`
				ClaimToken string `json:"claim_token"`
			} `json:"deliveries"`
		}{Deliveries: make([]struct {
			CaseID     string `json:"case_id"`
			AdviceID   string `json:"advice_id"`
			MessageID  string `json:"message_id"`
			Text       string `json:"text"`
			ClaimToken string `json:"claim_token"`
		}, 0, len(deliveries))}
		for _, delivery := range deliveries {
			if !validBoundedFrontValue(delivery.CaseID, 512) || !validBoundedFrontValue(delivery.AdviceID, 512) || !validBoundedFrontValue(delivery.MessageID, 512) || !validBoundedFrontValue(delivery.Text, 8192) || !validBoundedFrontValue(delivery.ClaimToken, 128) {
				writeHTTP(w, http.StatusInternalServerError, apiError{OK: false, Code: "edge_state_invalid"})
				return
			}
			result.Deliveries = append(result.Deliveries, struct {
				CaseID     string `json:"case_id"`
				AdviceID   string `json:"advice_id"`
				MessageID  string `json:"message_id"`
				Text       string `json:"text"`
				ClaimToken string `json:"claim_token"`
			}{delivery.CaseID, delivery.AdviceID, delivery.MessageID, delivery.Text, delivery.ClaimToken})
		}
		writeHTTP(w, http.StatusOK, result)
	})
	mux.HandleFunc("POST /v1/fronts/{front}/acks", func(w http.ResponseWriter, r *http.Request) {
		front, ok := parseFront(r.PathValue("front"))
		if !ok {
			writeHTTP(w, http.StatusNotFound, apiError{OK: false, Code: "not_found"})
			return
		}
		var input struct {
			MessageID  string `json:"message_id"`
			ClaimToken string `json:"claim_token"`
			ReceiptID  string `json:"receipt_id"`
		}
		if err := decodeJSON(r, &input); err != nil || !validBoundedFrontValue(input.MessageID, 512) || !validBoundedFrontValue(input.ClaimToken, 128) || !validBoundedFrontValue(input.ReceiptID, 1024) {
			writeHTTP(w, http.StatusBadRequest, apiError{OK: false, Code: "invalid_request"})
			return
		}
		outcome, err := service.MarkFrontDelivered(r.Context(), sspedge.FrontReceipt{Front: front, MessageID: input.MessageID, ClaimToken: input.ClaimToken, ReceiptID: input.ReceiptID}, time.Now().UTC())
		if err != nil {
			writeHTTP(w, http.StatusUnprocessableEntity, apiError{OK: false, Code: "ack_rejected"})
			return
		}
		writeHTTP(w, http.StatusOK, struct {
			Outcome string `json:"outcome"`
		}{string(outcome)})
	})
	mux.HandleFunc("GET /v1/cases/{caseID}/advice", func(w http.ResponseWriter, r *http.Request) {
		result, err := service.ListAdvice(r.Context(), r.PathValue("caseID"))
		if err != nil {
			writeHTTP(w, http.StatusNotFound, apiError{OK: false, Code: "not_found"})
			return
		}
		wire := make([]adviceResponseWire, 0, len(result))
		for _, advice := range result {
			wire = append(wire, adviceResponse(advice))
		}
		writeHTTP(w, http.StatusOK, wire)
	})
	mux.HandleFunc("GET /v1/cases/{caseID}", func(w http.ResponseWriter, r *http.Request) {
		result, err := service.GetCase(r.Context(), r.PathValue("caseID"))
		if err != nil {
			writeHTTP(w, http.StatusNotFound, apiError{OK: false, Code: "not_found"})
			return
		}
		writeHTTP(w, http.StatusOK, caseRecordResponse(result))
	})
	mux.HandleFunc("GET /v1/advice/{adviceID}", func(w http.ResponseWriter, r *http.Request) {
		result, err := service.PresentAdvice(r.Context(), r.PathValue("adviceID"))
		if err != nil {
			writeHTTP(w, http.StatusNotFound, apiError{OK: false, Code: "not_found"})
			return
		}
		writeHTTP(w, http.StatusOK, adviceResponse(result))
	})
	return mux
}

func caseSubmissionResponse(value edge.CaseSubmission) caseSubmissionResponseWire {
	return caseSubmissionResponseWire{EnvelopeID: value.EnvelopeID, CaseID: value.CaseID, Commitment: value.Commitment, AcceptedRemote: value.AcceptedRemote,
		Receipt: commitReceiptResponseWire{AuthorityID: value.Receipt.AuthorityID, Revision: value.Receipt.Revision, EnvelopeID: value.Receipt.EnvelopeID, Commitment: value.Receipt.Commitment}}
}

func caseRecordResponse(value edge.CaseRecord) caseRecordResponseWire {
	return caseRecordResponseWire{EnvelopeID: value.EnvelopeID, CaseID: value.CaseID, Commitment: value.Commitment, Summary: value.Summary,
		Registry: registryResponseWire{RoutingEpoch: value.Registry.RoutingEpoch, Revision: value.Registry.Revision, Hash: value.Registry.Hash}, ExpiresAt: value.ExpiresAt, Committed: value.Committed}
}

func adviceResponse(value edge.AdviceView) adviceResponseWire {
	return adviceResponseWire{AdviceID: value.AdviceID, CaseID: value.CaseID, Text: value.Text, ReceivedAt: value.ReceivedAt}
}

func parseFront(value string) (sspedge.Front, bool) {
	switch sspedge.Front(value) {
	case sspedge.FrontCLI:
		return sspedge.FrontCLI, true
	case sspedge.FrontAMQ:
		return sspedge.FrontAMQ, true
	default:
		return "", false
	}
}

func validFrontOwner(value string) bool { return validBoundedFrontValue(value, 128) }
func validBoundedFrontValue(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}
func writeHTTP(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeJSON(w io.Writer, value any) int {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return 1
	}
	if reply, ok := value.(apiError); ok && !reply.OK {
		return 1
	}
	return 0
}
