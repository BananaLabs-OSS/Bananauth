package main

import "testing"

func TestEmailIntentHTTPV2UsesOnlyFixedProviders(t *testing.T) {
	for _, v := range []struct {
		intent, issue, consume string
		ok                     bool
	}{{"login", "bananauth.identity.email-login.issue.v2", "bananauth.identity.email-login.consume.v2", true}, {"", "bananauth.identity.email-login.issue.v2", "bananauth.identity.email-login.consume.v2", true}, {"signup", "bananauth.identity.email-signup.issue.v2", "bananauth.identity.email-signup.consume.v2", true}, {"broadcast", "", "", false}, {"email_change", "", "", false}, {"Signup", "", "", false}} {
		issue, consume, ok := emailIntentEventsV2(v.intent)
		if issue != v.issue || consume != v.consume || ok != v.ok {
			t.Fatalf("intent%q map changed", v.intent)
		}
	}
}
