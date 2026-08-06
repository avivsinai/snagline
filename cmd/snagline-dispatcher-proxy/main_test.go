package main

import "testing"

func TestLoadConfigRequiresRuntimeIdentityAndCredentials(t *testing.T) {
	values := map[string]string{
		"SNAGLINE_DISPATCHER_RUNTIME_URL":         "https://runtime.svc.example:8443/v1/submit-inert-advice",
		"SNAGLINE_DISPATCHER_RUNTIME_SERVER_NAME": "runtime.svc.example",
		"SNAGLINE_DISPATCHER_PROXY_TLS_CERT":      "/run/proxy/proxy-client.crt",
		"SNAGLINE_DISPATCHER_PROXY_TLS_KEY":       "/run/proxy/proxy-client.key",
		"SNAGLINE_DISPATCHER_RUNTIME_CA":          "/run/proxy/runtime-ca.pem",
		"SNAGLINE_DISPATCHER_PROXY_TIMEOUT":       "20s",
	}
	settings, err := loadConfig(func(name string) string { return values[name] })
	if err != nil || settings.listenAddress != defaultListenAddress {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}
	values["SNAGLINE_DISPATCHER_RUNTIME_SERVER_NAME"] = ""
	if _, err := loadConfig(func(name string) string { return values[name] }); err == nil {
		t.Fatal("missing runtime identity accepted")
	}
	values["SNAGLINE_DISPATCHER_RUNTIME_SERVER_NAME"] = "runtime.svc.example"
	values["SNAGLINE_DISPATCHER_PROXY_LISTEN"] = "0.0.0.0:9090"
	if _, err := loadConfig(func(name string) string { return values[name] }); err == nil {
		t.Fatal("listen drift accepted")
	}
}
