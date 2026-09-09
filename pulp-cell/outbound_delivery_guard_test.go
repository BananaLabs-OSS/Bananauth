package main

import "testing"

func TestOutboundDeliveryConfigFailsClosed(t *testing.T) {
	for _, value := range []string{"", "false", "1", "yes", "enabled", " true-ish "} {
		if outboundDeliveryEnabled(value) {
			t.Fatalf("delivery enabled by %q", value)
		}
	}
	for _, value := range []string{"true", "TRUE", " true "} {
		if !outboundDeliveryEnabled(value) {
			t.Fatalf("delivery rejected %q", value)
		}
	}
}
