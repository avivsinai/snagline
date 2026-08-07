package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/avivsinai/snagline/internal/dispatcherproxy"
	"github.com/avivsinai/snagline/internal/securetransport"
)

const defaultListenAddress = ":8080"

type config struct {
	listenAddress     string
	runtimeURL        string
	runtimeServerName string
	certificate       string
	privateKey        string
	rootCA            string
	timeout           time.Duration
	maxConcurrency    int
}

func main() {
	if err := run(); err != nil {
		log.Printf("snagline dispatcher proxy stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	settings, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	tlsConfig, err := securetransport.LoadClientTLS(settings.certificate, settings.privateKey, settings.rootCA)
	if err != nil {
		return err
	}
	tlsConfig.ServerName = settings.runtimeServerName
	client := &http.Client{Transport: &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   tlsConfig,
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
	}, Timeout: settings.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	handler, err := dispatcherproxy.New(dispatcherproxy.Config{
		UpstreamURL:       settings.runtimeURL,
		RuntimeServerName: settings.runtimeServerName,
		Client:            client,
		RequestTimeout:    settings.timeout,
		MaxConcurrency:    settings.maxConcurrency,
	})
	if err != nil {
		return err
	}
	server := &http.Server{Addr: settings.listenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: settings.timeout + 5*time.Second, WriteTimeout: settings.timeout + 5*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	serveError := make(chan error, 1)
	go func() { serveError <- server.ListenAndServe() }()
	select {
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func loadConfig(lookup func(string) string) (config, error) {
	settings := config{
		listenAddress:     strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_PROXY_LISTEN")),
		runtimeURL:        strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_URL")),
		runtimeServerName: strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_SERVER_NAME")),
		certificate:       strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_PROXY_TLS_CERT")),
		privateKey:        strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_PROXY_TLS_KEY")),
		rootCA:            strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_RUNTIME_CA")),
	}
	if settings.listenAddress == "" {
		settings.listenAddress = defaultListenAddress
	}
	settings.timeout, _ = time.ParseDuration(strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_PROXY_TIMEOUT")))
	settings.maxConcurrency, _ = strconv.Atoi(strings.TrimSpace(lookup("SNAGLINE_DISPATCHER_PROXY_GLOBAL_CAP")))
	if settings.listenAddress != defaultListenAddress || settings.runtimeURL == "" || settings.runtimeServerName == "" || settings.certificate == "" || settings.privateKey == "" || settings.rootCA == "" || settings.timeout <= 0 || settings.timeout > time.Minute || settings.maxConcurrency < 1 || settings.maxConcurrency > 16 {
		return config{}, errors.New("snagline dispatcher proxy: incomplete or invalid configuration")
	}
	return settings, nil
}
