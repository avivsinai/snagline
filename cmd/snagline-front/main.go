// snagline-front renders inert edge advice locally or displays it passively
// through AMQ. It never reads edge SQLite or performs provider actions.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/edgeclient"
	"github.com/avivsinai/snagline/internal/front/amq"
	"github.com/avivsinai/snagline/internal/front/cli"
	"github.com/avivsinai/snagline/internal/securefile"
)

const (
	maxAMQConfigBytes = 4096
	maxAMQBodyBytes   = 12 << 10
)

type frontConfig struct {
	Mode, Socket, Owner, AMQConfig string
	LeaseTTL, OperationTimeout     time.Duration
	Limit                          int
}

func main() {
	config, err := parseFrontConfig(os.Args[1:])
	if err != nil {
		os.Exit(1)
	}
	if err := runFront(context.Background(), config, os.Stdout); err != nil {
		os.Exit(1)
	}
}

func parseFrontConfig(args []string) (frontConfig, error) {
	flags := flag.NewFlagSet("snagline-front", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "", "cli or amq")
	socket := flags.String("socket", "", "absolute Unix socket")
	owner := flags.String("owner", "", "bounded local front identity")
	lease := flags.Duration("lease", time.Minute, "claim lease between 1s and 15m")
	operationTimeout := flags.Duration("operation-timeout", 15*time.Second, "bounded operation timeout no longer than claim lease")
	limit := flags.Int("limit", 1, "deliveries to claim, between 1 and 6")
	amqConfig := flags.String("amq-config", "", "absolute private AMQ binding JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return frontConfig{}, errors.New("invalid front flags")
	}
	config := frontConfig{Mode: *mode, Socket: *socket, Owner: *owner, LeaseTTL: *lease, OperationTimeout: *operationTimeout, Limit: *limit, AMQConfig: *amqConfig}
	if (config.Mode != "cli" && config.Mode != "amq") || !filepath.IsAbs(config.Socket) || filepath.Clean(config.Socket) != config.Socket || !bounded(config.Owner, 128) || config.LeaseTTL < time.Second || config.LeaseTTL > 15*time.Minute || config.LeaseTTL%time.Second != 0 || config.OperationTimeout < time.Second || config.OperationTimeout > config.LeaseTTL || config.Limit < 1 || config.Limit > 6 {
		return frontConfig{}, errors.New("invalid front configuration")
	}
	if config.Mode == "amq" && config.AMQConfig == "" {
		return frontConfig{}, errors.New("AMQ mode requires a protected local binding")
	}
	if config.Mode == "cli" && config.AMQConfig != "" {
		return frontConfig{}, errors.New("CLI mode does not use AMQ binding")
	}
	return config, nil
}

func runFront(ctx context.Context, config frontConfig, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	defer cancel()
	client, err := edgeclient.New(edgeclient.Config{Socket: config.Socket})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	switch config.Mode {
	case "cli":
		_, err := cli.RenderOnce(ctx, cli.Config{Client: client, Owner: config.Owner, LeaseTTL: config.LeaseTTL, Limit: config.Limit}, out, time.Now().UTC())
		return err
	case "amq":
		binding, err := loadAMQBinding(config.AMQConfig)
		if err != nil {
			return err
		}
		_, err = amq.DeliverOnce(ctx, amq.Config{Client: client, Sender: amqSender{lane: binding, execute: runCommand}, Owner: config.Owner, LeaseTTL: config.LeaseTTL, Limit: config.Limit, Lane: binding}, time.Now().UTC())
		return err
	default:
		return errors.New("unknown front mode")
	}
}

type amqBinding struct {
	Binary  string `json:"binary"`
	Root    string `json:"root"`
	Session string `json:"session"`
	From    string `json:"from"`
	To      string `json:"to"`
}

func loadAMQBinding(path string) (amq.Lane, error) {
	raw, err := securefile.ReadPrivateBounded(path, maxAMQConfigBytes)
	if err != nil {
		return amq.Lane{}, errors.New("AMQ binding unavailable")
	}
	var config amqBinding
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return amq.Lane{}, errors.New("AMQ binding is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return amq.Lane{}, errors.New("AMQ binding must contain one JSON value")
	}
	if !absoluteClean(config.Binary) || !absoluteClean(config.Root) || !boundedHandle(config.Session) || !boundedHandle(config.From) || !boundedHandle(config.To) {
		return amq.Lane{}, errors.New("AMQ binding is invalid")
	}
	info, err := os.Stat(config.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return amq.Lane{}, errors.New("AMQ binary is not a trusted executable")
	}
	return amq.Lane{Binary: config.Binary, Root: config.Root, Session: config.Session, From: config.From, To: config.To}, nil
}

type commandRunner func(context.Context, string, ...string) error

type amqSender struct {
	lane    amq.Lane
	execute commandRunner
}

func (s amqSender) SendPassive(ctx context.Context, lane amq.Lane, message amq.PassiveMessage) error {
	if lane != s.lane || s.execute == nil || !validPassiveMessage(message) {
		return errors.New("invalid AMQ passive display")
	}
	body := fmt.Sprintf("Snagline passive advice display (inert; do not execute).\ncase_id: %s\nadvice_id: %s\nmessage_id: %s\n\n%s", message.CaseID, message.AdviceID, message.MessageID, message.Text)
	if len(body) > maxAMQBodyBytes {
		return errors.New("AMQ passive display exceeds body bound")
	}
	return s.execute(ctx, lane.Binary, "send", "--root", lane.Root, "--session", lane.Session, "--me", lane.From, "--to", lane.To, "--kind", "status", "--subject", "snagline.passive_advice.v1", "--body", body, "--strict")
}

func runCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func absoluteClean(value string) bool { return filepath.IsAbs(value) && filepath.Clean(value) == value }
func bounded(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum
}
func boundedHandle(value string) bool {
	return bounded(value, 128) && !strings.ContainsAny(value, "\t\r\n ")
}
func validPassiveMessage(message amq.PassiveMessage) bool {
	return bounded(message.MessageID, 512) && bounded(message.CaseID, 512) && bounded(message.AdviceID, 512) && bounded(message.Text, 8192)
}
