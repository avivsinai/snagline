package main

import "testing"

func TestLoadConfigRequiresPinnedMutualTLSAndBoundedConcurrency(t *testing.T) {
	values := map[string]string{
		"SNAGLINE_DISPATCHER_RUNTIME_TLS_CERT":        "/cert",
		"SNAGLINE_DISPATCHER_RUNTIME_TLS_KEY":         "/key",
		"SNAGLINE_DISPATCHER_PROXY_CLIENT_CA":         "/ca",
		"SNAGLINE_DISPATCHER_PROXY_CLIENT_SAN":        "dns:snagline-dispatcher-proxy",
		"SNAGLINE_DISPATCHER_RUNTIME_GLOBAL_CAP":      "4",
		"SNAGLINE_DISPATCHER_RUNTIME_REQUEST_TIMEOUT": "20s",
	}
	settings, err := loadConfig(func(name string) string { return values[name] })
	if err != nil {
		t.Fatal(err)
	}
	if settings.globalCap != 4 || settings.listenAddress != ":8443" || settings.executable != defaultExecutable {
		t.Fatalf("settings=%+v", settings)
	}
	for _, mutation := range []func(){
		func() { values["SNAGLINE_DISPATCHER_PROXY_CLIENT_SAN"] = "" },
		func() { values["SNAGLINE_DISPATCHER_RUNTIME_GLOBAL_CAP"] = "17" },
		func() { values["SNAGLINE_DISPATCHER_RUNTIME_LISTEN"] = "0.0.0.0:9443" },
	} {
		copy := make(map[string]string, len(values))
		for key, value := range values {
			copy[key] = value
		}
		mutation()
		if _, err := loadConfig(func(name string) string { return values[name] }); err == nil {
			t.Fatal("invalid configuration was accepted")
		}
		values = copy
	}
}
