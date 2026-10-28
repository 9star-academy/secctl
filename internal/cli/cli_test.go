package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/9star-academy/secctl/internal/firewall"
)

func TestAppHelpAndVersion(t *testing.T) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	app := New("1.0.0", out, errOut, nil)

	// Help test
	code := app.Run(context.Background(), []string{"--help"})
	if code != 0 || !strings.Contains(out.String(), "secctl") {
		t.Fatalf("help failed: %d, out: %s", code, out.String())
	}

	// Version test
	out.Reset()
	code = app.Run(context.Background(), []string{"--version"})
	if code != 0 || !strings.Contains(out.String(), "1.0.0") {
		t.Fatalf("version failed: %d, out: %s", code, out.String())
	}
}

func TestAppAllowAndDeny(t *testing.T) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	app := New("1.0.0", out, errOut, nil)
	app.FW = &firewall.MockBackend{} // Use mock backend to avoid requiring root in CI

	// Allow
	code := app.Run(context.Background(), []string{"allow", "80,443/tcp", "--comment", "web"})
	if code != 0 {
		t.Fatalf("allow failed with code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "已成功放行端口: 80/tcp") {
		t.Errorf("expected 80/tcp allowed, got: %s", out.String())
	}

	// Status
	out.Reset()
	code = app.Run(context.Background(), []string{"status"})
	if code != 0 {
		t.Fatalf("status failed: %d", code)
	}

	// Deny
	out.Reset()
	code = app.Run(context.Background(), []string{"deny", "80/tcp"})
	if code != 0 {
		t.Fatalf("deny failed: %d", code)
	}
}

func TestAppAudit(t *testing.T) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	app := New("1.0.0", out, errOut, nil)

	code := app.Run(context.Background(), []string{"audit"})
	if code != 0 {
		t.Fatalf("audit failed with code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "服务器安全审计报告") {
		t.Errorf("expected audit report header, got: %s", out.String())
	}
}
