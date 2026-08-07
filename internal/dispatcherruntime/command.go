package dispatcherruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	maxCommandInputBytes  = 64 << 10
	maxCommandOutputBytes = 16 << 10
)

var dispatcherEnvironment = []string{
	"SNAGLINE_DISPATCHER_KEY_DESCRIPTOR",
	"SNAGLINE_DISPATCHER_TENANT",
	"SNAGLINE_DISPATCHER_PRINCIPAL_ID",
	"SNAGLINE_DISPATCHER_AUTHOR_KEY_ID",
	"SNAGLINE_DISPATCHER_DB",
	"SNAGLINE_DISPATCHER_DB_KEY",
	"SNAGLINE_DISPATCHER_CONTROL_URL",
	"SNAGLINE_DISPATCHER_TLS_CERT",
	"SNAGLINE_DISPATCHER_TLS_KEY",
	"SNAGLINE_DISPATCHER_CONTROL_CA",
	"SNAGLINE_DISPATCHER_ENVELOPE_TTL",
}

type CommandSubmitter struct {
	executableSnapshot []byte
	environ            []string
}

// CommandRequest is the complete canonical request passed to the sealed
// one-shot dispatcher over stdin. No confidential advice content is placed in
// argv or inherited ambient environment.
type CommandRequest struct {
	EventID    string     `json:"event_id"`
	Submission Submission `json:"submission"`
}

func ValidateCommandRequest(request CommandRequest) error {
	if !eventIDPattern.MatchString(request.EventID) {
		return errors.New("dispatcher runtime: invalid event ID")
	}
	return ValidateSubmission(request.Submission)
}

func NewCommandSubmitter(executable string, lookup func(string) string) (*CommandSubmitter, error) {
	return newCommandSubmitter(executable, lookup, 0)
}

func newCommandSubmitter(executable string, lookup func(string) string, expectedUID uint32) (*CommandSubmitter, error) {
	if !filepath.IsAbs(executable) || lookup == nil {
		return nil, errors.New("dispatcher runtime: fixed absolute executable is required")
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return nil, errors.New("dispatcher runtime: executable rejected")
	}
	ownerUID, ownerOK := fileOwnerUID(info)
	if !info.Mode().IsRegular() || info.Mode()&0o022 != 0 || info.Mode()&0o111 == 0 || !ownerOK || ownerUID != expectedUID {
		return nil, errors.New("dispatcher runtime: executable rejected")
	}
	file, err := os.Open(executable)
	if err != nil {
		return nil, errors.New("dispatcher runtime: executable rejected")
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		file.Close()
		return nil, errors.New("dispatcher runtime: executable identity changed")
	}
	// Production admits only a root-owned image executable. Copying its opened
	// inode now lets every later submission execute a fresh sealed memfd, never
	// a pathname or mutable same-inode view.
	snapshot, readErr := io.ReadAll(io.LimitReader(file, 64<<20+1))
	file.Close()
	if readErr != nil || len(snapshot) == 0 || len(snapshot) > 64<<20 {
		return nil, errors.New("dispatcher runtime: executable snapshot rejected")
	}
	environ := make([]string, 0, len(dispatcherEnvironment))
	for _, name := range dispatcherEnvironment {
		value := strings.TrimSpace(lookup(name))
		if value == "" {
			return nil, errors.New("dispatcher runtime: incomplete dispatcher configuration")
		}
		environ = append(environ, name+"="+value)
	}
	return &CommandSubmitter{executableSnapshot: snapshot, environ: environ}, nil
}

func (s *CommandSubmitter) Submit(ctx context.Context, eventID string, input Submission) (Result, error) {
	request := CommandRequest{EventID: eventID, Submission: input}
	if err := ValidateCommandRequest(request); err != nil {
		return Result{}, err
	}
	requestBytes, err := json.Marshal(request)
	if err != nil || len(requestBytes) > maxCommandInputBytes {
		return Result{}, errors.New("dispatcher runtime: submission command input exceeded the safe bound")
	}
	executable, descriptorPath, err := sealedExecutable(s.executableSnapshot)
	if err != nil {
		return Result{}, fmt.Errorf("dispatcher runtime: secure executable unavailable: %w", err)
	}
	defer executable.Close()
	command := exec.CommandContext(ctx, descriptorPath, "--request-stdin")
	command.ExtraFiles = []*os.File{executable}
	command.Env = append([]string(nil), s.environ...)
	command.Stdin = bytes.NewReader(requestBytes)
	var stdout cappedBuffer
	command.Stdout = &stdout
	command.Stderr = io.Discard
	runErr := command.Run()
	if stdout.overflow {
		return Result{}, errors.New("dispatcher runtime: submission command output exceeded the safe bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	var result Result
	if err := decoder.Decode(&result); err != nil || ensureEOF(decoder) != nil || !validCommandResult(result) {
		return Result{}, errors.New("dispatcher runtime: invalid submission result")
	}
	if runErr != nil && result.OK {
		return Result{}, fmt.Errorf("dispatcher runtime: submission command failed: %w", runErr)
	}
	return result, nil
}

func validCommandResult(result Result) bool {
	if result.OK {
		return result.Code == "accepted_remote" && result.AdviceID != "" && result.AuthorityRevision > 0
	}
	if result.AdviceID != "" || result.AuthorityRevision != 0 {
		return false
	}
	switch result.Code {
	case "turn_request_mismatch", "pending_advice_conflict", "turn_in_flight", "replay_guard_full", "advice_not_accepted", "runtime_unavailable":
		return true
	default:
		return false
	}
}

type cappedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := maxCommandOutputBytes - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return written, nil
	}
	if len(value) > remaining {
		b.overflow = true
		value = value[:remaining]
	}
	_, _ = b.Buffer.Write(value)
	return written, nil
}
