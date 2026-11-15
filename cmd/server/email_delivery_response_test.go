package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestEmailDeliveryResponseDistinguishesQueuedAndSuppressedOwnerReceipts(t *testing.T) {
	for _, tc := range []struct {
		name             string
		accepted, queued bool
		status           int
	}{
		{"queued", true, true, http.StatusOK},
		{"suppressed", true, false, http.StatusTooManyRequests},
		{"not accepted", false, false, http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := &AuthHandler{identity: func(event string, _ []byte) ([]byte, error) {
				if event != identityEmailVerificationIssueEvent {
					t.Fatalf("unexpected identity call: %s", event)
				}
				return msgpack.Marshal(map[string]any{
					"version": "auth-identity.v1",
					"ok":      true,
					"value":   map[string]bool{"accepted": tc.accepted, "effect_queued": tc.queued},
				})
			}}
			req := httptest.NewRequest(http.MethodPost, "/auth/email-verification", strings.NewReader(`{"email":"email@example.test"}`))
			rec := httptest.NewRecorder()
			handler.issueEmailVerificationComposed(rec, req)
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != tc.status {
				t.Fatalf("response %d %s, want %d", rec.Code, rec.Body, tc.status)
			}
			if (body["sent"] == true) != tc.queued {
				t.Fatalf("unexpected delivery acknowledgement: %v", body)
			}
			if tc.status == http.StatusTooManyRequests && (body["retry_after"] != float64(600) || rec.Header().Get("Retry-After") != "600") {
				t.Fatalf("missing retry guidance: %v %v", body, rec.Header())
			}
		})
	}
}
