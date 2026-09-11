package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp/workflow"
	"github.com/vmihailenco/msgpack/v5"
)

type completionDispatcher struct {
	mu                          sync.Mutex
	identityRequest             map[string]any
	identityCalls, sessionCalls int
	failFirstSession            bool
	session                     sessionWorkflowSession
}

func (d *completionDispatcher) Dispatch(call workflow.DispatchRequest) (workflow.DispatchResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	payload := call.Payload.(map[string]any)
	var request map[string]any
	if err := msgpack.Unmarshal(payload["request_msgpack"].([]byte), &request); err != nil {
		return workflow.DispatchResult{}, err
	}
	var response []byte
	var err error
	switch call.Event {
	case identityEmailVerificationConsumeEvent:
		d.identityCalls++
		if d.identityRequest == nil {
			d.identityRequest = request
		}
		response, err = msgpack.Marshal(identityResult[emailVerificationConsumeResult]{
			Version: "auth-identity.v1", OK: true,
			Value: emailVerificationConsumeResult{Verified: true, AccountID: "8b0d821e-baba-4b18-8f5e-6035fb8864d0"},
		})
	case sessionCreatedOwnedEvent:
		d.sessionCalls++
		if d.failFirstSession && d.sessionCalls == 1 {
			return workflow.DispatchResult{}, errors.New("simulated owner interruption")
		}
		d.session = sessionWorkflowSession{
			SessionID: request["session_id"].(string), AccountID: request["account_id"].(string),
			CreatedAt: time.Now().Add(-time.Second).UnixMilli(), ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), Active: true,
		}
		response, err = msgpack.Marshal(sessionWorkflowResult{Version: "auth-session.v1", OK: true, Value: d.session})
	default:
		return workflow.DispatchResult{}, errors.New("unexpected event")
	}
	return workflow.DispatchResult{Value: response}, err
}

func TestEmailSessionCompletionRecoversAfterIdentityConsume(t *testing.T) {
	dispatch := &completionDispatcher{failFirstSession: true}
	manager := NewComposedSessionManager("test-secret-with-enough-entropy", time.Hour, dispatch)
	handler := NewComposedAuthHandler(manager, dispatch)
	request := EmailVerificationSessionRequest{Email: "User@Example.com", Code: "123456", RequestID: "50da0df8-0ff4-4e19-9c17-b7c71b98b7c1"}
	if _, code, err := handler.completeEmailSession(request); err == nil || code != "session_unavailable" {
		t.Fatalf("interrupted completion = code:%q err:%v", code, err)
	}
	completed, code, err := handler.completeEmailSession(request)
	if err != nil || code != "" || completed.Token == "" || completed.AccountID == "" || completed.SessionID == "" {
		t.Fatalf("recovered completion = %#v code:%q err:%v", completed, code, err)
	}
	if dispatch.identityCalls != 2 || dispatch.sessionCalls != 2 {
		t.Fatalf("owner calls identity/session = %d/%d", dispatch.identityCalls, dispatch.sessionCalls)
	}
	if dispatch.identityRequest["request_id"] != "email-session:identity:"+request.RequestID {
		t.Fatalf("identity request = %#v", dispatch.identityRequest)
	}
}

func TestEmailSessionCompletionRejectsCallerIdentityAndMalformedCoordinator(t *testing.T) {
	dispatch := &completionDispatcher{}
	handler := NewComposedAuthHandler(NewComposedSessionManager("test-secret-with-enough-entropy", time.Hour, dispatch), dispatch)
	for _, requestID := range []string{"", "browser-account-id", "50DA0DF8-0FF4-4E19-9C17-B7C71B98B7C1"} {
		completed, code, err := handler.completeEmailSession(EmailVerificationSessionRequest{Email: "u@example.com", Code: "123456", RequestID: requestID})
		if err != nil || code != "invalid_request" || completed.Token != "" || dispatch.identityCalls != 0 {
			t.Fatalf("request %q = %#v %q %v", requestID, completed, code, err)
		}
	}
}

func TestEmailSessionCompletionIsRaceSafe(t *testing.T) {
	dispatch := &completionDispatcher{}
	handler := NewComposedAuthHandler(NewComposedSessionManager("test-secret-with-enough-entropy", time.Hour, dispatch), dispatch)
	request := EmailVerificationSessionRequest{Email: "u@example.com", Code: "123456", RequestID: "50da0df8-0ff4-4e19-9c17-b7c71b98b7c1"}
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, code, err := handler.completeEmailSession(request)
			if err != nil || code != "" || result.Token == "" {
				t.Errorf("completion: %#v %q %v", result, code, err)
			}
		}()
	}
	group.Wait()
}
