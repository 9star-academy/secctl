package ssh

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type socketFixture struct {
	calls       []string
	killMode    string
	stale       bool
	failStart   bool
	failRestore bool
	listening   int
	planned     int
}

func mockSocket(t *testing.T, config string) *socketFixture {
	t.Helper()
	stubSSH(t, false)
	base := CommandRunner
	f := &socketFixture{killMode: "process", listening: 22, planned: 22}
	CommandRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		f.calls = append(f.calls, call)
		switch call {
		case "systemctl show ssh.socket --property=LoadState --property=ActiveState --property=Accept --property=Triggers --property=Listen":
			return []byte("LoadState=loaded\nActiveState=active\nAccept=no\nTriggers=ssh.service\nListen=0.0.0.0:22 (Stream) [::]:22 (Stream)\n"), nil
		case "systemctl show ssh.service --property=KillMode --value":
			return []byte(f.killMode + "\n"), nil
		case "systemctl daemon-reload":
			data, err := os.ReadFile(config)
			if err != nil {
				return nil, err
			}
			f.planned = 22
			if strings.Contains(string(data), "Port 22022") && !f.stale {
				f.planned = 22022
			}
			return nil, nil
		case "systemctl show ssh.socket --property=Listen --value":
			p := strconv.Itoa(f.planned)
			return []byte("0.0.0.0:" + p + " (Stream) [::]:" + p + " (Stream)\n"), nil
		case "systemctl stop ssh.service ssh.socket":
			f.listening = 0
			return nil, nil
		case "systemctl start ssh.socket ssh.service":
			if f.failStart && f.planned == 22022 || f.failRestore && f.planned == 22 {
				return nil, errors.New("socket bind failed")
			}
			f.listening = f.planned
			return nil, nil
		}
		if name == "ss" {
			if args[len(args)-1] == "sport = :"+strconv.Itoa(f.listening) {
				return []byte(`LISTEN 0 4096 *:` + strconv.Itoa(f.listening) + ` users:(("systemd",pid=1,fd=9))`), nil
			}
			return nil, nil
		}
		return base(ctx, name, args...)
	}
	return f
}

func socketConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte("Port 22\nPasswordAuthentication yes\n"), 0640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSocketPortChangeConfirmsNewListener(t *testing.T) {
	config := socketConfig(t)
	f := mockSocket(t, config)
	m := NewManager(&bytes.Buffer{}, strings.NewReader("confirm\n"))
	_, err := m.Harden(context.Background(), HardenOptions{ConfigPath: config, Port: 22022, TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(f.calls, "\n")
	for _, want := range []string{"systemctl daemon-reload", "systemctl stop ssh.service ssh.socket", "systemctl start ssh.socket ssh.service"} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %s: %s", want, calls)
		}
	}
	if f.listening != 22022 || strings.Contains(calls, "systemctl reload ssh") {
		t.Fatalf("socket port did not switch: %d, %s", f.listening, calls)
	}
	if strings.Index(calls, "systemd-run ") > strings.Index(calls, "systemctl daemon-reload") {
		t.Fatal("listener changed before independent recovery was scheduled")
	}
	if _, err := os.Stat(config + ".secctl.pending"); !os.IsNotExist(err) {
		t.Fatal("confirmed socket transaction retained pending state")
	}
}

func TestSocketFailureRestoresOriginalListener(t *testing.T) {
	for _, scenario := range []string{"eof", "restart", "generator-conflict", "unsafe-kill-mode"} {
		t.Run(scenario, func(t *testing.T) {
			config := socketConfig(t)
			original, _ := os.ReadFile(config)
			f := mockSocket(t, config)
			f.failStart = scenario == "restart"
			f.stale = scenario == "generator-conflict"
			if scenario == "unsafe-kill-mode" {
				f.killMode = "control-group"
			}
			m := NewManager(&bytes.Buffer{}, strings.NewReader(""))
			_, err := m.Harden(context.Background(), HardenOptions{ConfigPath: config, Port: 22022, TimeoutSeconds: 60})
			if err == nil {
				t.Fatal("unsafe or unconfirmed socket change returned success")
			}
			got, _ := os.ReadFile(config)
			if !bytes.Equal(got, original) || f.listening != 22 {
				t.Fatalf("original configuration/listener not restored: %q port=%d err=%v", got, f.listening, err)
			}
			if scenario == "unsafe-kill-mode" && strings.Contains(strings.Join(f.calls, "\n"), "systemctl stop ") {
				t.Fatal("unsafe service was stopped")
			}
		})
	}
}

func TestSocketIndependentRollbackSurvivesStoppedListener(t *testing.T) {
	config := socketConfig(t)
	f := mockSocket(t, config)
	original := "Port 22\nPasswordAuthentication yes\n"
	// Capture a real Manager transaction's disk state just before the process disappears.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := CommandRunner
	CommandRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" && strings.Join(args, " ") == "start ssh.socket ssh.service" && f.planned == 22022 {
			data, err := os.ReadFile(filepath.Join(config+".secctl.pending", "state.json"))
			if err != nil || !bytes.Contains(data, []byte(`"socket"`)) || !bytes.Contains(data, []byte("0.0.0.0:22")) {
				t.Errorf("socket recovery information not persisted: %s, %v", data, err)
			}
			// Simulate the separate recovery binary after the listener has been stopped.
			f.failRestore = true
			cancel()
		}
		return base(ctx, name, args...)
	}
	m := NewManager(&bytes.Buffer{}, strings.NewReader(""))
	_, err := m.Harden(ctx, HardenOptions{ConfigPath: config, Port: 22022, TimeoutSeconds: 60})
	if err == nil {
		t.Fatal("unconfirmed transaction succeeded")
	}
	dir := config + ".secctl.pending"
	if _, err := os.Stat(filepath.Join(dir, "pending")); err != nil {
		t.Fatal("failed listener recovery lost retry state", err)
	}
	f.failRestore = false
	f.listening = 0
	if err := RunRollback(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(config)
	if string(got) != original || f.listening != 22 {
		t.Fatalf("independent recovery failed: %q port=%d", got, f.listening)
	}
	if _, err := os.Stat(filepath.Join(dir, "pending")); !os.IsNotExist(err) {
		t.Fatal("successful recovery left pending marker")
	}
}

func TestSocketCommandFailuresRestoreOriginalPort(t *testing.T) {
	for _, failed := range []string{"daemon-reload", "show ssh.socket --property=Listen --value", "stop ssh.service ssh.socket", "listener"} {
		t.Run(failed, func(t *testing.T) {
			config := socketConfig(t)
			f := mockSocket(t, config)
			base := CommandRunner
			CommandRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				data, _ := os.ReadFile(config)
				if strings.Contains(string(data), "Port 22022") {
					if name == "systemctl" && strings.Join(args, " ") == failed {
						return nil, errors.New("systemd operation failed")
					}
					if name == "ss" && failed == "listener" {
						return nil, nil
					}
				}
				return base(ctx, name, args...)
			}
			_, err := NewManager(&bytes.Buffer{}, strings.NewReader("confirm\n")).Harden(context.Background(), HardenOptions{ConfigPath: config, Port: 22022, TimeoutSeconds: 60})
			if err == nil || f.listening != 22 {
				t.Fatalf("failed operation accepted or listener lost: %v, %d", err, f.listening)
			}
		})
	}
}

func TestSocketPreflightRejectsUnknownActivation(t *testing.T) {
	for _, output := range []string{"", "LoadState=loaded\nActiveState=activating\n", "LoadState=loaded\nActiveState=active\nAccept=yes\nTriggers=ssh@.service\n"} {
		t.Run(output, func(t *testing.T) {
			config := socketConfig(t)
			mockSocket(t, config)
			base := CommandRunner
			CommandRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "systemctl" && len(args) > 4 && args[0] == "show" {
					return []byte(output), nil
				}
				return base(ctx, name, args...)
			}
			if _, err := captureSSHSocket(context.Background()); err == nil {
				t.Fatal("unknown or per-connection socket accepted")
			}
		})
	}
}

func TestSocketTCPListenerParsing(t *testing.T) {
	for _, invalid := range []string{"", "0.0.0.0:22", "/run/ssh.sock (Stream)", "[::]:22 (Datagram)", "0.0.0.0:99999 (Stream)", "vsock:2:22 (Stream)"} {
		if _, err := parseSocketListeners(invalid); err == nil {
			t.Fatalf("unsupported listener accepted: %q", invalid)
		}
	}
	got, err := parseSocketListeners("[::]:22 (Stream) 127.0.0.1:22 (Stream)")
	if err != nil || len(got) != 2 || got[0] != "127.0.0.1:22" {
		t.Fatalf("valid IPv4/IPv6 listeners rejected: %v, %v", got, err)
	}
}
