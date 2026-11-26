package main

import (
	"strings"
	"testing"
)

func TestSessionsVerificationHTML(t *testing.T) {
	markup := sessionsVerificationHTML(sessionsVerificationSubject, "Your verification code: A6Z12B\n<script>not markup</script>")
	for _, want := range []string{"<!DOCTYPE html>", "sessions.gg", "style=", "A6Z12B", "&lt;script&gt;"} {
		if !strings.Contains(markup, want) {
			t.Errorf("verification HTML is missing %q", want)
		}
	}
	if strings.Contains(markup, "<script>") {
		t.Fatal("verification message was interpreted as markup")
	}
	if sessionsVerificationHTML("Other notification", "A6Z12B") != "" {
		t.Fatal("unrelated notification received the Sessions verification template")
	}
}
