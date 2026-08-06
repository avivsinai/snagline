package dispatcherruntime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommandSubmitterUsesFixedBinaryExactArgumentsAndSanitizedEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secure executable execution is intentionally Linux-only")
	}
	directory := t.TempDir()
	executable := filepath.Join(directory, "snagline-dispatcher")
	source := filepath.Join(directory, "fixture.go")
	program := `package main
import ("encoding/json"; "os")
func main() {
 var input struct { EventID string ` + "`json:\"event_id\"`" + `; Submission struct { CaseID string ` + "`json:\"case_id\"`" + `; CaseCommitment string ` + "`json:\"case_commitment\"`" + `; Text string ` + "`json:\"text\"`" + `; PublicSummary string ` + "`json:\"public_summary\"`" + ` } ` + "`json:\"submission\"`" + ` }
 if len(os.Args) != 2 || os.Args[1] != "--request-stdin" || os.Getenv("HOME") != "" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "" { os.Exit(2) }
 if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil { os.Exit(3) }
 if input.EventID != "` + strings.Repeat("f", 64) + `" || input.Submission.CaseID != "case-🧵" || input.Submission.CaseCommitment != "sha256:` + strings.Repeat("a", 64) + `" || input.Submission.Text != "Use the inert\x00recovery step." || input.Submission.PublicSummary != "A bounded recovery step is available." { os.Exit(4) }
 json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":true,"code":"accepted_remote","advice_id":"advice-1","authority_revision":7})
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-o", executable, source)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, output)
	}
	submitter, err := newCommandSubmitter(executable, func(name string) string { return "/fixed/" + name }, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if len(submitter.environ) != len(dispatcherEnvironment) {
		t.Fatalf("environment entries=%d", len(submitter.environ))
	}
	for _, entry := range submitter.environ {
		if strings.HasPrefix(entry, "HOME=") || strings.HasPrefix(entry, "AWS_SECRET_ACCESS_KEY=") {
			t.Fatalf("ambient credential leaked: %s", entry)
		}
	}
	input := validRequest
	input.CaseID = "case-🧵"
	input.Text = "Use the inert\x00recovery step."
	result, err := submitter.Submit(context.Background(), strings.Repeat("f", 64), input)
	if err != nil || !result.OK || result.AdviceID != "advice-1" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestCommandSubmitterRejectsSymlinkExecutableAndIncompleteEnvironment(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "dispatcher")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	if _, err := newCommandSubmitter(link, func(string) string { return "configured" }, uint32(os.Getuid())); err == nil {
		t.Fatal("symlink executable was accepted")
	}
	if _, err := newCommandSubmitter(executable, func(string) string { return "" }, uint32(os.Getuid())); err == nil {
		t.Fatal("incomplete environment was accepted")
	}
}

func TestProductionCommandSubmitterRejectsSameUIDExecutable(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "dispatcher")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, err := NewCommandSubmitter(executable, func(string) string { return "configured" }); err == nil {
			t.Fatal("production submitter accepted a same-UID executable")
		}
	}
}

func TestCommandSubmitterRejectsExecutablePathReplacementAfterValidation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sealed executable execution is intentionally Linux-only")
	}
	directory := t.TempDir()
	executable := filepath.Join(directory, "dispatcher")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ok\":true,\"code\":\"accepted_remote\",\"advice_id\":\"original\",\"authority_revision\":1}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	submitter, err := newCommandSubmitter(executable, func(name string) string { return "/fixed/" + name }, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ok\":true,\"code\":\"accepted_remote\",\"advice_id\":\"attacker\",\"authority_revision\":1}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, executable); err != nil {
		t.Fatal(err)
	}
	result, err := submitter.Submit(context.Background(), strings.Repeat("f", 64), validRequest)
	if err != nil || result.AdviceID != "original" {
		t.Fatalf("sealed original result=%+v err=%v", result, err)
	}
}

func TestCommandSubmitterIgnoresSameInodeOverwriteAfterSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sealed executable execution is intentionally Linux-only")
	}
	directory := t.TempDir()
	executable := filepath.Join(directory, "dispatcher")
	original := "#!/bin/sh\nprintf '%s\\n' '{\"ok\":true,\"code\":\"accepted_remote\",\"advice_id\":\"sealed\",\"authority_revision\":1}'\n"
	if err := os.WriteFile(executable, []byte(original), 0o755); err != nil {
		t.Fatal(err)
	}
	submitter, err := newCommandSubmitter(executable, func(name string) string { return "/fixed/" + name }, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(executable, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("#!/bin/sh\nprintf '%s\\n' '{\"ok\":true,\"code\":\"accepted_remote\",\"advice_id\":\"attacker\",\"authority_revision\":1}'\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := submitter.Submit(context.Background(), strings.Repeat("f", 64), validRequest)
	if err != nil || result.AdviceID != "sealed" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestCommandSubmitterFailsLoudlyOutsideLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux contract")
	}
	directory := t.TempDir()
	executable := filepath.Join(directory, "dispatcher")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	submitter, err := newCommandSubmitter(executable, func(name string) string { return "/fixed/" + name }, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := submitter.Submit(context.Background(), strings.Repeat("f", 64), validRequest); err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("non-Linux submit err=%v", err)
	}
}
