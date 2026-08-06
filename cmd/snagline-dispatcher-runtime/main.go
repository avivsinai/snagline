package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/avivsinai/snagline/internal/dispatcherruntime"
	"github.com/avivsinai/snagline/internal/securetransport"
)

const (
	defaultListenAddress = ":8443"
	defaultExecutable    = "/usr/local/bin/snagline-dispatcher"
	shutdownTimeout      = 10 * time.Second
)

type config struct {
	listenAddress  string
	executable     string
	serverCert     string
	serverKey      string
	proxyClientCA  string
	proxySAN       string
	globalCap      int
	requestTimeout time.Duration
}

func main() {
	if err := run(); err != nil {
		log.Printf("snagline dispatcher runtime stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	settings, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	submitter, err := dispatcherruntime.NewCommandSubmitter(settings.executable, os.Getenv)
	if err != nil {
		return err
	}
	handler, err := dispatcherruntime.New(dispatcherruntime.Config{
		Submitter:         submitter,
		ProxyClientSAN:    settings.proxySAN,
		GlobalConcurrency: settings.globalCap,
		RequestTimeout:    settings.requestTimeout,
	})
	if err != nil {
		return err
	}
	tlsConfig, err := securetransport.LoadServerTLS(settings.serverCert, settings.serverKey, settings.proxyClientCA)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              settings.listenAddress,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       settings.requestTimeout + 5*time.Second,
		WriteTimeout:      settings.requestTimeout + 5*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	serveError := make(chan error, 1)
	go func() { serveError <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func loadConfig(lookup func(string) string) (config, error) {
	settings := config{
		listenAddress: strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_LISTEN")),
		executable:    strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_EXECUTABLE")),
		serverCert:    strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_TLS_CERT")),
		serverKey:     strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_TLS_KEY")),
		proxyClientCA: strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_PROXY_CLIENT_CA")),
		proxySAN:      strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_PROXY_CLIENT_SAN")),
	}
	if settings.listenAddress == "" {
		settings.listenAddress = defaultListenAddress
	}
	if settings.executable == "" {
		settings.executable = defaultExecutable
	}
	settings.globalCap = parsePositiveInt(lookup("SNAGLINE_DISPATCHER_RUNTIME_GLOBAL_CAP"))
	settings.requestTimeout, _ = time.ParseDuration(strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_REQUEST_TIMEOUT")))
	if settings.listenAddress != defaultListenAddress || settings.serverCert == "" || settings.serverKey == "" || settings.proxyClientCA == "" || settings.proxySAN == "" || settings.globalCap < 1 || settings.globalCap > 16 || settings.requestTimeout <= 0 || settings.requestTimeout > time.Minute {
		return config{}, errors.New("snagline dispatcher runtime: incomplete or invalid configuration")
	}
	return settings, nil
}

func parsePositiveInt(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 1 {
		return 0
	}
	return value
}
