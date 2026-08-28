package application

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp/workflow"
	"github.com/BananaLabs-OSS/Pulp-Lua/orchestrator"
	"github.com/BurntSushi/toml"
	"github.com/vmihailenco/msgpack/v5"
)

type ownerResult struct {
	Version string         `msgpack:"version"`
	OK      bool           `msgpack:"ok"`
	Value   map[string]any `msgpack:"value"`
}

func TestApplicationManifestIsAcyclicAndCapabilityScoped(t *testing.T) {
	var app struct {
		Name         string   `toml:"name"`
		Cells        []string `toml:"cells"`
		Orchestrator struct {
			Script string `toml:"script"`
			SHA256 string `toml:"sha256"`
		} `toml:"orchestrator"`
	}
	if _, err := toml.DecodeFile("pulp.app.toml", &app); err != nil {
		t.Fatal(err)
	}
	if app.Name != "bananauth" || len(app.Cells) != 4 {
		t.Fatalf("app = %#v", app)
	}
	script, err := os.ReadFile(app.Orchestrator.Script)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(script)); got != app.Orchestrator.SHA256 {
		t.Fatalf("script sha256 = %s, manifest = %s", got, app.Orchestrator.SHA256)
	}
	type cellManifest struct {
		Name       string   `toml:"name"`
		WASM       string   `toml:"wasm"`
		WASMSHA256 string   `toml:"wasm_sha256"`
		Provides   []string `toml:"provides"`
		Consumes   []string `toml:"consumes"`
		DependsOn  []string `toml:"depends_on"`
	}
	cells := map[string]cellManifest{}
	providers := map[string]string{}
	for _, relative := range app.Cells {
		path := filepath.Clean(relative)
		var cell cellManifest
		if _, err := toml.DecodeFile(path, &cell); err != nil {
			t.Fatal(err)
		}
		if _, duplicate := cells[cell.Name]; duplicate {
			t.Fatalf("duplicate cell %q", cell.Name)
		}
		if cell.WASM == "" {
			t.Fatalf("%s does not declare a WASM artifact", cell.Name)
		}
		artifact := filepath.Join(filepath.Dir(path), cell.WASM)
		wasm, err := os.ReadFile(artifact)
		if err != nil {
			t.Fatalf("read %s: %v", artifact, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(wasm)); got != cell.WASMSHA256 {
			t.Fatalf("%s wasm sha256 = %s, manifest = %s", cell.Name, got, cell.WASMSHA256)
		}
		cells[cell.Name] = cell
		for _, capability := range cell.Provides {
			if prior := providers[capability]; prior != "" {
				t.Fatalf("capability %q provided by %q and %q", capability, prior, cell.Name)
			}
			providers[capability] = cell.Name
		}
	}
	for _, cell := range cells {
		for _, dependency := range cell.DependsOn {
			if _, ok := cells[dependency]; !ok {
				t.Fatalf("%s depends on missing %s", cell.Name, dependency)
			}
		}
		for _, capability := range cell.Consumes {
			if providers[capability] == "" {
				t.Fatalf("%s consumes missing capability %s", cell.Name, capability)
			}
		}
	}
	state := map[string]uint8{}
	var visit func(string)
	visit = func(name string) {
		if state[name] == 1 {
			t.Fatalf("dependency cycle at %s", name)
		}
		if state[name] == 2 {
			return
		}
		state[name] = 1
		for _, dependency := range cells[name].DependsOn {
			visit(dependency)
		}
		state[name] = 2
	}
	for name := range cells {
		visit(name)
	}
}

func TestLuaSequencesSessionAndIdentityEventsThroughOwners(t *testing.T) {
	script, err := os.ReadFile("bananauth.lua")
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	runtime, err := orchestrator.New(orchestrator.Options{
		Script: string(script),
		Caller: orchestrator.CallFunc(func(target, provider string, payload []byte) ([]byte, error) {
			if target != "auth-session" && target != "auth-identity" {
				t.Fatalf("target = %q", target)
			}
			calls = append(calls, target+":"+provider)
			var request map[string]any
			if err := msgpack.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			version := "auth-session.v1"
			if target == "auth-identity" {
				version = "auth-identity.v1"
			}
			return msgpack.Marshal(ownerResult{
				Version: version, OK: true,
				Value: map[string]any{"session_id": request["session_id"], "active": provider != "auth.session.v1.revoke"},
			})
		}),
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	events := []struct {
		event    string
		target   string
		provider string
	}{
		{"bananauth.session.created.v1", "auth-session", "auth.session.v1.create"},
		{"bananauth.session.verified.v1", "auth-session", "auth.session.v1.get"},
		{"bananauth.session.revoked.v1", "auth-session", "auth.session.v1.revoke"},
		{"bananauth.identity.native.authenticate.v1", "auth-identity", "auth.identity.v1.native.authenticate"},
		{"bananauth.identity.native.attach.v1", "auth-identity", "auth.identity.v1.native.attach"},
		{"bananauth.identity.email-verification.issue.v1", "auth-identity", "auth.identity.v1.email-verification.issue"},
		{"bananauth.identity.email-verification.consume.v1", "auth-identity", "auth.identity.v1.email-verification.consume"},
	}
	for _, test := range events {
		requestWire, err := msgpack.Marshal(map[string]any{"session_id": "session-1", "request_id": "request-1", "now": int64(100)})
		if err != nil {
			t.Fatal(err)
		}
		result, err := runtime.Dispatch(workflow.DispatchRequest{
			Event:   test.event,
			Payload: map[string]any{"request_msgpack": requestWire},
		})
		if err != nil {
			t.Fatalf("%s: %v", test.event, err)
		}
		responseWire, err := workflow.DecodeValue[[]byte](result)
		if err != nil {
			t.Fatal(err)
		}
		var response ownerResult
		if err := msgpack.Unmarshal(responseWire, &response); err != nil {
			t.Fatal(err)
		}
		expectedVersion := "auth-session.v1"
		if test.target == "auth-identity" {
			expectedVersion = "auth-identity.v1"
		}
		if !response.OK || response.Version != expectedVersion {
			t.Fatalf("%s response = %#v", test.event, response)
		}
		expectedCall := test.target + ":" + test.provider
		if calls[len(calls)-1] != expectedCall {
			t.Fatalf("%s call = %q", test.event, calls[len(calls)-1])
		}
	}
}
