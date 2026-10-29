package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/9star-academy/secctl/internal/audit"
	"github.com/9star-academy/secctl/internal/ssh"
	"os"
	"path/filepath"
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

func TestFirewallArgumentsValidatedBeforeMutation(t *testing.T) {
	for _, args := range [][]string{
		{"allow", "80,invalid"}, {"allow", "5432", "--form", "10.0.0.0/8"},
		{"allow", "5432", "--from"}, {"allow", "5432", "--from", "not-an-ip"},
		{"deny", "80", "--unknown"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
			app := New("test", out, errOut, nil)
			fw := &firewall.MockBackend{}
			app.FW = fw
			if app.Run(context.Background(), args) == 0 || len(fw.Rules) != 0 {
				t.Fatalf("invalid args mutated rules or succeeded: rules=%v err=%s", fw.Rules, errOut)
			}
		})
	}
}

type fakeSSH struct {
	opts   ssh.HardenOptions
	err    error
	called bool
}

func (s *fakeSSH) Harden(_ context.Context, opts ssh.HardenOptions) (*ssh.HardenResult, error) {
	s.opts = opts
	s.called = true
	return &ssh.HardenResult{}, s.err
}

type fakeShield struct {
	enabled bool
	err     error
}

func (s *fakeShield) Enable(context.Context) error            { s.enabled = true; return s.err }
func (s *fakeShield) Disable(context.Context) error           { s.enabled = false; return s.err }
func (s *fakeShield) Apply(context.Context) error             { return s.err }
func (s *fakeShield) IsEnabled(context.Context) (bool, error) { return s.enabled, s.err }

type failingFW struct{ firewall.MockBackend }

func (*failingFW) Allow(context.Context, firewall.Rule) error { return errors.New("firewall failed") }
func (*failingFW) Deny(context.Context, firewall.Rule) error  { return errors.New("firewall failed") }
func (*failingFW) Status(context.Context) ([]firewall.Rule, bool, error) {
	return nil, false, errors.New("status failed")
}

type fakeAuditor struct {
	report *audit.AuditReport
	err    error
}

func (a fakeAuditor) Audit(context.Context) (*audit.AuditReport, error) { return a.report, a.err }

func TestSSHCommandValidationAndFirewallFailure(t *testing.T) {
	for _, test := range []struct {
		args            []string
		failFW, failSSH bool
		want            int
	}{
		{[]string{"ssh"}, false, false, 1}, {[]string{"ssh", "unknown"}, false, false, 1},
		{[]string{"ssh", "harden", "--bad"}, false, false, 1}, {[]string{"ssh", "harden", "--port", "65536"}, false, false, 1},
		{[]string{"ssh", "harden", "--timeout", "0"}, false, false, 1}, {[]string{"ssh", "harden", "extra"}, false, false, 1},
		{[]string{"ssh", "harden", "--port", "22022"}, true, false, 1},
		{[]string{"ssh", "harden"}, false, true, 1}, {[]string{"ssh", "harden", "--port", "22022"}, false, false, 0},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			app := New("test", &bytes.Buffer{}, &bytes.Buffer{}, nil)
			hardener := &fakeSSH{}
			app.SSH = hardener
			if test.failSSH {
				hardener.err = errors.New("ssh failed")
			}
			if test.failFW {
				app.FW = &failingFW{}
			} else {
				app.FW = &firewall.MockBackend{}
			}
			if got := app.Run(context.Background(), test.args); got != test.want {
				t.Fatalf("got=%d want=%d", got, test.want)
			}
			if test.failFW && hardener.called {
				t.Fatal("harden called after failed port opening")
			}
		})
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "id.pub")
	if err := os.WriteFile(key, []byte("ssh-ed25519 example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	app := New("test", &bytes.Buffer{}, &bytes.Buffer{}, nil)
	hardener := &fakeSSH{}
	app.SSH = hardener
	if app.Run(context.Background(), []string{"ssh", "harden", "--key", key}) != 0 || len(hardener.opts.ManualKeys) != 1 {
		t.Fatal("local key not passed")
	}
	if app.Run(context.Background(), []string{"ssh", "harden", "--key", filepath.Join(dir, "missing")}) == 0 {
		t.Fatal("missing key accepted")
	}
	if err := os.WriteFile(key, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if app.Run(context.Background(), []string{"ssh", "harden", "--key", key}) == 0 {
		t.Fatal("empty key accepted")
	}
}

func TestDispatchStatusErrorsAndShield(t *testing.T) {
	ctx := context.Background()
	app := New("test", nil, nil, nil)
	app.Out = &bytes.Buffer{}
	app.Err = &bytes.Buffer{}
	app.Shield = &fakeShield{}
	for _, args := range [][]string{{}, {"help"}, {"version"}, {"docker-shield", "enable"}, {"docker-shield", "status"}, {"docker-shield", "disable"}, {"docker-shield", "status"}} {
		if app.Run(ctx, args) != 0 {
			t.Fatalf("failed: %v", args)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"docker-shield"}, {"docker-shield", "bad"}, {"allow"}, {"deny"}} {
		if app.Run(ctx, args) == 0 {
			t.Fatalf("accepted: %v", args)
		}
	}
	app.Shield = &fakeShield{err: errors.New("failed")}
	for _, action := range []string{"enable", "disable", "status"} {
		if app.Run(ctx, []string{"docker-shield", action}) == 0 {
			t.Fatalf("ignored shield failure: %s", action)
		}
	}
	app.FW = &failingFW{}
	for _, args := range [][]string{{"allow", "80"}, {"deny", "80"}, {"status"}} {
		if app.Run(ctx, args) == 0 {
			t.Fatalf("ignored firewall failure: %v", args)
		}
	}
	app.FW = &firewall.MockBackend{Rules: []firewall.Rule{{Port: "80", Protocol: "tcp", Action: "ALLOW", Number: 1}}}
	if app.Run(ctx, []string{"status"}) != 0 {
		t.Fatal("status")
	}
	app.Auditor = fakeAuditor{err: errors.New("scan failed")}
	if app.Run(ctx, []string{"audit"}) == 0 {
		t.Fatal("ignored scan error")
	}
	app.Auditor = fakeAuditor{report: &audit.AuditReport{FirewallError: "unknown", DockerInstalled: true, DockerShieldError: "unknown", Suggestions: []string{"review"}}}
	if app.Run(ctx, []string{"audit"}) != 0 {
		t.Fatal("unknown states failed report")
	}
}
