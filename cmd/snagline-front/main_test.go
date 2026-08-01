package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avivsinai/snagline/internal/front/amq"
)

func TestLoadAMQBindingAcceptsOnlyPrivateDescriptorValidatedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "amq.json")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content := `{"binary":"` + binary + `","root":"/private/amq","session":"support","from":"edge","to":"agent"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := loadAMQBinding(path)
	if err != nil {
		t.Fatal(err)
	}
	if binding != (amq.Lane{Binary: binary, Root: "/private/amq", Session: "support", From: "edge", To: "agent"}) {
		t.Fatalf("binding=%+v", binding)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAMQBinding(path); err == nil {
		t.Fatal("accepted group/world-readable AMQ binding")
	}
}

func TestAMQSenderUsesFixedArgvContractAndBoundedPassiveBody(t *testing.T) {
	var gotName string
	var gotArgs []string
	sender := amqSender{lane: amq.Lane{Binary: "/usr/local/bin/amq", Root: "/private/amq", Session: "support", From: "edge", To: "agent"}, execute: func(_ context.Context, name string, args ...string) error {
		gotName, gotArgs = name, append([]string(nil), args...)
		return nil
	}}
	if err := sender.SendPassive(context.Background(), sender.lane, amq.PassiveMessage{MessageID: "message-1", CaseID: "case-1", AdviceID: "advice-1", Text: "inert only"}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gotArgs, "\x00")
	if gotName != "/usr/local/bin/amq" || !strings.Contains(joined, "--kind\x00status") || !strings.Contains(joined, "--subject\x00snagline.passive_advice.v1") || !strings.Contains(joined, "--root\x00/private/amq") || !strings.Contains(joined, "--session\x00support") || !strings.Contains(joined, "--me\x00edge") || !strings.Contains(joined, "--to\x00agent") {
		t.Fatalf("argv=%q %q", gotName, gotArgs)
	}
	if strings.Contains(joined, "sh") || strings.Contains(joined, "-c") {
		t.Fatalf("shell-like argv=%q", gotArgs)
	}
}

func TestParseFrontConfigRejectsUnknownModesAndMissingAMQBinding(t *testing.T) {
	if _, err := parseFrontConfig([]string{"--mode", "buzz", "--socket", "/tmp/edge.sock", "--owner", "front"}); err == nil {
		t.Fatal("accepted unknown front mode")
	}
	if _, err := parseFrontConfig([]string{"--mode", "amq", "--socket", "/tmp/edge.sock", "--owner", "front"}); err == nil {
		t.Fatal("accepted AMQ without protected binding")
	}
	if _, err := parseFrontConfig([]string{"--mode", "cli", "--socket", "/tmp/edge.sock", "--owner", "front", "--lease", "5s", "--operation-timeout", "6s"}); err == nil {
		t.Fatal("accepted an operation timeout beyond its claim lease")
	}
}

func TestAMQSenderHonorsCanceledOperationContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sender := amqSender{lane: amq.Lane{Binary: "/usr/local/bin/amq", Root: "/private/amq", Session: "support", From: "edge", To: "agent"}, execute: func(ctx context.Context, _ string, _ ...string) error {
		return ctx.Err()
	}}
	if err := sender.SendPassive(ctx, sender.lane, amq.PassiveMessage{MessageID: "message-1", CaseID: "case-1", AdviceID: "advice-1", Text: "inert only"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled AMQ send error=%v", err)
	}
}
