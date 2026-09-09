package main

import "testing"

func TestOutboundDeliveryRequiresExplicitAffirmativeValue(t *testing.T) {
	for _, value := range []string{"", "false", "1", "yes", "enabled", " true-ish "} {
		if outboundDeliveryEnabled(func(string) string { return value }) {
			t.Fatalf("delivery enabled by %q", value)
		}
	}
	for _, value := range []string{"true", "TRUE", " true "} {
		if !outboundDeliveryEnabled(func(string) string { return value }) {
			t.Fatalf("delivery rejected %q", value)
		}
	}
}
