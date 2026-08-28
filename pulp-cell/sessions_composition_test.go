package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp/workflow"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

type fakeSessionDispatcher struct {
	active map[string]bool
	events []string
}

func (f *fakeSessionDispatcher) Dispatch(request workflow.DispatchRequest) (workflow.DispatchResult, error) {
	f.events = append(f.events, request.Event)
	payload, ok := request.Payload.(map[string]any)
	if !ok {
		return workflow.DispatchResult{}, fmt.Errorf("invalid payload")
	}
	raw, ok := payload["request_msgpack"].([]byte)
	if !ok {
		return workflow.DispatchResult{}, fmt.Errorf("missing request wire")
	}
	var input map[string]any
	if err := msgpack.Unmarshal(raw, &input); err != nil {
		return workflow.DispatchResult{}, err
	}
	id, _ := input["session_id"].(string)
	switch request.Event {
	case sessionCreatedEvent:
		f.active[id] = true
	case sessionRevokedEvent:
		f.active[id] = false
	case sessionVerifiedEvent:
	default:
		return workflow.DispatchResult{}, fmt.Errorf("unexpected event %q", request.Event)
	}
	response, err := msgpack.Marshal(sessionWorkflowResult{
		Version: "auth-session.v1",
		OK:      true,
		Value:   sessionWorkflowSession{SessionID: id, Active: f.active[id]},
	})
	if err != nil {
		return workflow.DispatchResult{}, err
	}
	return workflow.DispatchResult{Value: response}, nil
}

func TestComposedSessionManagerUsesLuaWorkflowBoundary(t *testing.T) {
	dispatcher := &fakeSessionDispatcher{active: map[string]bool{}}
	manager := NewComposedSessionManager("test-secret-with-enough-entropy", time.Hour, dispatcher)
	manager.newSessionID = func() string { return "session-composed-1" }
	token, expires, err := manager.Create(uuid.MustParse("c4e6a148-6252-4ebf-8c7c-c45ed5c2bc43"))
	if err != nil || token == "" || expires != 3600 {
		t.Fatalf("create = token:%t expires:%d err:%v", token != "", expires, err)
	}
	if len(dispatcher.events) != 1 || dispatcher.events[0] != sessionCreatedEvent {
		t.Fatalf("events after create = %#v", dispatcher.events)
	}
	var sessionID string
	for id := range dispatcher.active {
		sessionID = id
	}
	if sessionID == "" || !manager.Exists(sessionID) {
		t.Fatal("composed session did not verify")
	}
	manager.Revoke(sessionID)
	if manager.Exists(sessionID) {
		t.Fatal("revoked composed session remained active")
	}
	want := []string{sessionCreatedEvent, sessionVerifiedEvent, sessionRevokedEvent, sessionVerifiedEvent}
	if fmt.Sprint(dispatcher.events) != fmt.Sprint(want) {
		t.Fatalf("events = %#v, want %#v", dispatcher.events, want)
	}
}

func TestLegacySessionManagerRemainsAvailableForRollbackManifest(t *testing.T) {
	manager := NewSessionManager("test-secret-with-enough-entropy", time.Hour)
	manager.newSessionID = func() string { return "session-legacy-1" }
	if _, _, err := manager.Create(uuid.MustParse("c4e6a148-6252-4ebf-8c7c-c45ed5c2bc43")); err != nil {
		t.Fatal(err)
	}
	if !manager.Exists("session-legacy-1") {
		t.Fatal("legacy session was not active")
	}
	manager.Revoke("session-legacy-1")
	if manager.Exists("session-legacy-1") {
		t.Fatal("legacy session remained active after revoke")
	}
}
