package firewall

import (
	"context"
	"testing"
)

func TestParsePortProto(t *testing.T) {
	// Simple port
	port, proto, err := ParsePortProto("80")
	if err != nil || port != "80" || proto != "tcp" {
		t.Fatalf("unexpected port parse: %s %s %v", port, proto, err)
	}

	// Port with protocol
	port, proto, err = ParsePortProto("53/udp")
	if err != nil || port != "53" || proto != "udp" {
		t.Fatalf("unexpected port parse: %s %s %v", port, proto, err)
	}

	// Port range
	port, proto, err = ParsePortProto("8000-8080/tcp")
	if err != nil || port != "8000-8080" || proto != "tcp" {
		t.Fatalf("unexpected port range parse: %s %s %v", port, proto, err)
	}

	// Invalid port
	_, _, err = ParsePortProto("99999/tcp")
	if err == nil {
		t.Fatalf("expected error for port > 65535")
	}
}

func TestMockBackend(t *testing.T) {
	mock := &MockBackend{}
	ctx := context.Background()

	err := mock.Allow(ctx, Rule{Port: "80", Protocol: "tcp"})
	if err != nil {
		t.Fatalf("mock allow failed: %v", err)
	}

	rules, active, err := mock.Status(ctx)
	if err != nil || !active || len(rules) != 1 {
		t.Fatalf("unexpected status: %v %v %v", rules, active, err)
	}
}
