package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingBackendDoesNotReportSuccess(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	fw := DetectFirewall()
	if fw.Deny(context.Background(), Rule{Port: "8080", Protocol: "tcp"}) == nil {
		t.Fatal("missing firewall reported successful deny")
	}
	if _, active, err := fw.Status(context.Background()); active || err == nil {
		t.Fatalf("missing firewall status: active=%v err=%v", active, err)
	}
}

func TestIptablesDenyInstallsBlock(t *testing.T) {
	old := CommandRunner
	t.Cleanup(func() { CommandRunner = old })
	var calls []string
	CommandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	if err := (&IptablesBackend{}).Deny(context.Background(), Rule{Port: "8080", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "-I INPUT -p tcp --dport 8080 -j DROP") {
		t.Fatalf("no priority block: %v", calls)
	}
}

func TestUFWRequiresActiveAndPrioritizesDeny(t *testing.T) {
	old := CommandRunner
	t.Cleanup(func() { CommandRunner = old })
	active := false
	var calls []string
	CommandRunner = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		text := strings.Join(args, " ")
		calls = append(calls, text)
		if text == "status" || text == "status numbered" {
			if active {
				return []byte("Status: active\n"), nil
			}
			return []byte("Status: inactive\n"), nil
		}
		return nil, nil
	}
	u := &UFWBackend{}
	if err := u.Allow(context.Background(), Rule{Port: "80", Protocol: "tcp"}); err == nil {
		t.Fatal("inactive ufw reported effective allow")
	}
	active = true
	if err := u.Deny(context.Background(), Rule{Port: "8080", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "insert 1 deny 8080/tcp") {
		t.Fatalf("deny can be shadowed: %v", calls)
	}
	CommandRunner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("failed") }
	if u.Allow(context.Background(), Rule{Port: "80", Protocol: "tcp"}) == nil {
		t.Fatal("command failure swallowed")
	}
}

func TestPortRangesRejectMalformedSeparators(t *testing.T) {
	for _, spec := range []string{"-80", "80--90", "80-90-", "80:90:", "0-1", "90-80"} {
		if _, _, err := ParsePortProto(spec); err == nil {
			t.Errorf("accepted %q", spec)
		}
	}
}

func TestBackendsCommandsAndStatus(t *testing.T) {
	old := CommandRunner
	t.Cleanup(func() { CommandRunner = old })
	ctx := context.Background()
	var calls []string
	CommandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "ufw" && len(args) > 0 && args[0] == "status" {
			return []byte("Status: active\n[ 1] 22/tcp ALLOW IN Anywhere # SSH\n[ 2] 5432/tcp ALLOW FWD 10.0.0.0/8\n[ 3] 80/tcp (v6) DENY IN Anywhere (v6)\n"), nil
		}
		if name == "iptables" && len(args) > 0 && args[0] == "-S" {
			return []byte("-P INPUT ACCEPT\n-A INPUT -p tcp -s 10.0.0.0/8 --dport 5432 -j ACCEPT\n-A INPUT -p udp --dport 53 -j DROP\n"), nil
		}
		return nil, nil
	}
	u := &UFWBackend{}
	i := &IptablesBackend{}
	rules, active, err := u.Status(ctx)
	if err != nil || !active || len(rules) != 3 || !rules[1].Routed || rules[2].FromIP != "Anywhere (v6)" {
		t.Fatalf("ufw parse: %+v active=%v err=%v", rules, active, err)
	}
	rules, active, err = i.Status(ctx)
	if err != nil || !active || len(rules) != 2 || rules[0].Port != "5432" || rules[0].FromIP != "10.0.0.0/8" {
		t.Fatalf("iptables parse: %+v active=%v err=%v", rules, active, err)
	}
	for _, rule := range []Rule{{Port: "8000-8010", Protocol: "any", FromIP: "10.0.0.0/8", Comment: "range"}, {Port: "53", Protocol: "udp", Routed: true}, {Port: "443", Protocol: "any"}} {
		if err := u.Allow(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}
	if err := i.Allow(ctx, Rule{Port: "8000-8010", Protocol: "any", FromIP: "192.0.2.1", Comment: "range"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "route insert 1 allow from any to any port 53 proto udp") {
		t.Fatalf("invalid routed syntax: %v", calls)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "--dport 8000:8010") {
		t.Fatal("range not normalized")
	}
	for _, rule := range []Rule{{Port: "bad", Protocol: "tcp"}, {Port: "80", Protocol: "tcp", Routed: true}, {Port: "80", Protocol: "tcp", FromIP: "::1"}} {
		if i.Allow(ctx, rule) == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
	if u.Allow(ctx, Rule{Port: "80", Protocol: "tcp", FromIP: "invalid"}) == nil {
		t.Fatal("invalid IP accepted")
	}
	if err := u.Enable(ctx); err != nil {
		t.Fatal(err)
	}
	if i.Enable(ctx) == nil {
		t.Fatal("iptables no-op enable accepted")
	}
	CommandRunner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("command failed") }
	if _, _, err := i.Status(ctx); err == nil {
		t.Fatal("iptables error ignored")
	}
	if _, _, err := u.Status(ctx); err == nil {
		t.Fatal("ufw error ignored")
	}
	if u.Enable(ctx) == nil || i.Allow(ctx, Rule{Port: "80", Protocol: "tcp"}) == nil {
		t.Fatal("mutation error ignored")
	}
}

func TestRuleParsingAndBackendDetection(t *testing.T) {
	for _, text := range []string{"", "80/invalid", "80/tcp/extra", "65536", "0", "80-90-", "90:80"} {
		if _, _, err := ParsePortProto(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	for _, text := range []string{"bad", "[ 1]", "[ 1] 80/tcp UNKNOWN Anywhere"} {
		if _, err := parseUFWRuleLine(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	if err := os.WriteFile(filepath.Join(bin, "iptables"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if DetectFirewall().Name() != "iptables" {
		t.Fatal("iptables not detected")
	}
	if err := os.WriteFile(filepath.Join(bin, "ufw"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if DetectFirewall().Name() != "ufw" {
		t.Fatal("ufw not preferred")
	}
	unavailable := &UnavailableBackend{}
	if unavailable.Name() != "unavailable" || unavailable.IsAvailable() || unavailable.Enable(context.Background()) == nil || unavailable.Allow(context.Background(), Rule{}) == nil {
		t.Fatal("unavailable reported usable")
	}
	mock := &MockBackend{}
	if mock.Name() != "mock" || !mock.IsAvailable() || mock.Enable(context.Background()) != nil || mock.Deny(context.Background(), Rule{}) != nil {
		t.Fatal("explicit test backend failed")
	}
}

func TestUFWReordersExistingAllowDenyDecisions(t *testing.T) {
	old := CommandRunner
	t.Cleanup(func() { CommandRunner = old })
	var deleted []string
	CommandRunner = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		if strings.HasPrefix(command, "status") {
			return []byte("Status: active\n[ 1] 80/tcp ALLOW IN Anywhere\n[ 2] 80/tcp DENY IN Anywhere\n[ 3] 80/tcp (v6) DENY IN Anywhere (v6)\n"), nil
		}
		if strings.HasPrefix(command, "delete ") {
			deleted = append(deleted, command)
			return []byte("Rule deleted"), nil
		}
		if len(deleted) != 2 {
			return []byte("Skipping inserting existing rule"), nil
		}
		return []byte("Rule inserted"), nil
	}
	if err := (&UFWBackend{}).Deny(context.Background(), Rule{Port: "80", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deleted, ",") != "delete allow 80/tcp,delete deny 80/tcp" {
		t.Fatalf("old decisions still shadow new rule; deleted=%v", deleted)
	}
}

func TestUFWPreservesOtherScopesAndRejectsSkippedInsert(t *testing.T) {
	old := CommandRunner
	t.Cleanup(func() { CommandRunner = old })
	var deleted []string
	CommandRunner = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		if command == "status numbered" {
			return []byte("Status: active\n[ 1] 80/tcp ALLOW OUT Anywhere\n[ 2] 80/tcp on eth0 ALLOW IN Anywhere\n[ 3] 80/tcp ALLOW IN 192.0.2.1\n[ 4] 80/tcp (v6) ALLOW IN Anywhere (v6)\n"), nil
		}
		if strings.HasPrefix(command, "delete ") {
			deleted = append(deleted, command)
			return nil, nil
		}
		return []byte("Rule inserted"), nil
	}
	if err := (&UFWBackend{}).Deny(context.Background(), Rule{Port: "80", Protocol: "tcp", FromIP: "192.0.2.1/32"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deleted, ",") != "delete allow from 192.0.2.1/32 to any port 80 proto tcp" {
		t.Fatalf("unrelated rules removed: %v", deleted)
	}
	CommandRunner = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "status" {
			return []byte("Status: active\n"), nil
		}
		return []byte("Skipping inserting existing rule"), nil
	}
	if (&UFWBackend{}).Deny(context.Background(), Rule{Port: "80", Protocol: "tcp"}) == nil {
		t.Fatal("skipped insertion reported success")
	}
	for input, want := range map[string]string{"Anywhere (v6)": "", "192.0.2.1/32": "192.0.2.1", "192.0.2.99/24": "192.0.2.0/24", "::/0": "", "::1": "::1"} {
		if got := sourceKey(input); got != want {
			t.Errorf("%q => %q, want %q", input, got, want)
		}
	}
	for _, line := range []string{"[ x] 80/tcp ALLOW IN Anywhere", "[ 1] ALLOW Anywhere"} {
		if _, err := parseUFWRuleLine(line); err == nil {
			t.Errorf("malformed row accepted: %s", line)
		}
	}
}
