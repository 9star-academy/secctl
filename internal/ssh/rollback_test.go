package ssh

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubSSH(t *testing.T, failReload bool) *[]string {
	t.Helper()
	bin := t.TempDir()
	for _, name := range []string{"sshd", "systemd-run", "systemctl"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	old := CommandRunner
	t.Cleanup(func() { CommandRunner = old })
	calls := []string{}
	CommandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "-T" {
			return []byte("port 22022\npubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin without-password\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"), nil
		}
		if name == "ss" {
			return []byte(`LISTEN 0 128 0.0.0.0:22022 users:(("sshd",pid=1,fd=3))`), nil
		}
		if failReload && name == "systemctl" && len(args) > 0 && args[0] == "reload" {
			return nil, errors.New("reload failed")
		}
		return nil, nil
	}
	return &calls
}

func TestRollbackRecoversAndCannotOverwriteAfterConfirmation(t *testing.T) {
	calls := stubSSH(t, false)
	ctx := context.Background()
	config := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(config, []byte("Port 22\n"), 0640); err != nil {
		t.Fatal(err)
	}
	guard, err := StartRollback(ctx, config, []byte("Port 22\n"), 0640, 60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartRollback(ctx, config, nil, 0600, 60); err == nil {
		t.Fatal("concurrent transaction accepted")
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "systemd-run --quiet --unit=secctl-rollback-") {
		t.Fatal("independent timer not scheduled")
	}
	if err := guard.Apply(func() error { return os.WriteFile(config, []byte("Port 22022\n"), 0600) }); err != nil {
		t.Fatal(err)
	}
	// The recovery path uses only disk state, with no original Manager or Guard instance.
	if err := RunRollback(ctx, guard.Dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(config)
	info, _ := os.Stat(config)
	if string(data) != "Port 22\n" || info.Mode().Perm() != 0640 {
		t.Fatalf("restore failed: %q %v", data, info.Mode())
	}
	if err := guard.Confirm(ctx); err == nil {
		t.Fatal("confirmed a transaction that already rolled back")
	}
	guard, err = StartRollback(ctx, config, []byte("Port 22\n"), 0640, 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(guard.Dir); !os.IsNotExist(err) {
		t.Fatal("confirmed transaction state not removed")
	}
}

func TestHardenConfirmEOFAndReloadFailure(t *testing.T) {
	for _, test := range []struct {
		name, input string
		fail        bool
		wantErr     bool
	}{
		{"confirm", "confirm\n", false, false}, {"eof", "", false, true}, {"reload-failed", "confirm\n", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubSSH(t, test.fail)
			config := filepath.Join(t.TempDir(), "sshd_config")
			original := "Port 22\nPasswordAuthentication yes\n"
			if err := os.WriteFile(config, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			manager := NewManager(&bytes.Buffer{}, strings.NewReader(test.input))
			manager.ValidateKeys = func(string) error { return nil }
			_, err := manager.Harden(context.Background(), HardenOptions{ConfigPath: config, Port: 22022, DisablePassword: true, TimeoutSeconds: 60})
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v", err)
			}
			data, _ := os.ReadFile(config)
			if test.wantErr && string(data) != original {
				t.Fatalf("failure retained modified config: %s", data)
			}
			if !test.wantErr && !strings.Contains(string(data), "Port 22022") {
				t.Fatal("confirmation lost config")
			}
		})
	}
}

func TestHardenRefusesMissingSchedulerAndEffectiveConfigMismatch(t *testing.T) {
	stubSSH(t, false)
	config := filepath.Join(t.TempDir(), "sshd_config")
	original := "Port 22\n"
	if err := os.WriteFile(config, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(&bytes.Buffer{}, strings.NewReader("confirm\n"))
	CommandRunner = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("passwordauthentication yes\n"), nil
	}
	if _, err := manager.Harden(context.Background(), HardenOptions{ConfigPath: config, Port: 22022, TimeoutSeconds: 60}); err == nil {
		t.Fatal("effective mismatch accepted")
	}
	data, _ := os.ReadFile(config)
	if string(data) != original {
		t.Fatal("failed preflight changed config")
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := StartRollback(context.Background(), config, []byte(original), 0600, 60); err == nil {
		t.Fatal("missing scheduler accepted")
	}
}

func TestRollbackFailuresKeepRecoveryState(t *testing.T) {
	stubSSH(t, false)
	ctx := context.Background()
	config := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(config, []byte("Port 22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	originalRunner := CommandRunner
	CommandRunner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("scheduler failed") }
	if _, err := StartRollback(ctx, config, []byte("Port 22\n"), 0600, 60); err == nil {
		t.Fatal("scheduler failure swallowed")
	}
	if _, err := os.Stat(config + ".secctl.pending"); !os.IsNotExist(err) {
		t.Fatal("failed schedule retained an unusable state")
	}
	CommandRunner = originalRunner
	guard, err := StartRollback(ctx, config, []byte("Port 22\n"), 0600, 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("Port 22022\n"), 0600); err != nil {
		t.Fatal(err)
	}
	CommandRunner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("reload failed") }
	if guard.Rollback(ctx) == nil {
		t.Fatal("recovery reload failure swallowed")
	}
	data, _ := os.ReadFile(config)
	if string(data) != "Port 22\n" {
		t.Fatal("backup not restored")
	}
	if _, err := os.Stat(filepath.Join(guard.Dir, "pending")); err != nil {
		t.Fatal("retry state removed after failed reload")
	}
	CommandRunner = originalRunner
	if err := RunRollback(ctx, guard.Dir); err != nil {
		t.Fatal(err)
	}
	if err := guard.Apply(func() error { return errors.New("must not run") }); err == nil || !strings.Contains(err.Error(), "回滚已开始") {
		t.Fatalf("apply after rollback: %v", err)
	}
}

func TestConfirmFailureDisarmsRollback(t *testing.T) {
	stubSSH(t, false)
	ctx := context.Background()
	config := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(config, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	guard, err := StartRollback(ctx, config, []byte("original"), 0600, 60)
	if err != nil {
		t.Fatal(err)
	}
	CommandRunner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("bus failed") }
	if guard.Confirm(ctx) == nil {
		t.Fatal("stop failure ignored")
	}
	if err := RunRollback(ctx, guard.Dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(config)
	if string(data) != "new" {
		t.Fatal("confirmed configuration was rolled back")
	}
}
