package dockershield

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShieldCannotTrustMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "after.rules")
	if err := os.WriteFile(path, []byte(UFWRulesTagBegin+"\n"+UFWRulesTagEnd+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &ShieldManager{AfterRulesPath: path}
	t.Setenv("PATH", t.TempDir())
	enabled, _ := s.IsEnabled(context.Background())
	if enabled {
		t.Fatal("file marker reported live protection without firewall tools")
	}
}

func TestShieldLifecycleAndFailureRestoresFile(t *testing.T) {
	for _, failReload := range []bool{false, true} {
		t.Run(map[bool]string{false: "lifecycle", true: "failed-reload"}[failReload], func(t *testing.T) {
			dir := t.TempDir()
			rules := filepath.Join(dir, "after.rules")
			original := "*filter\nCOMMIT\n"
			if err := os.WriteFile(rules, []byte(original), 0640); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"ufw", "iptables", "iptables-restore", "docker", "systemctl"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			old := CommandRunner
			t.Cleanup(func() { CommandRunner = old })
			live := false
			var calls []string
			CommandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
				command := name + " " + strings.Join(args, " ")
				calls = append(calls, command)
				switch command {
				case "ufw status":
					return []byte("Status: active\n"), nil
				case "ufw reload":
					if failReload {
						return nil, errors.New("reload failed")
					}
					persisted, err := os.ReadFile(rules)
					if err != nil {
						return nil, err
					}
					if strings.Contains(string(persisted), UFWRulesTagBegin) && !strings.Contains(string(persisted), ":ufw-user-forward - [0:0]") {
						return nil, errors.New("iptables-restore: Chain 'ufw-user-forward' does not exist")
					}
					return nil, nil
				case "docker network ls -q":
					return []byte("bridge-id\n"), nil
				case `docker network inspect --format {{.Driver}}|{{.EnableIPv6}}|{{index .Options "com.docker.network.bridge.name"}} bridge-id`:
					return []byte("bridge|false|docker0\n"), nil
				case "iptables -S FORWARD":
					return []byte("-A FORWARD -j DOCKER-USER\n"), nil
				case "iptables -S DOCKER-USER":
					if live {
						return []byte("-A DOCKER-USER -m comment --comment secctl-shield -j SECCTL-DOCKER\n-A DOCKER-USER -j RETURN\n"), nil
					}
					return []byte("-A DOCKER-USER -j RETURN\n"), nil
				case "iptables -S SECCTL-DOCKER":
					if !live {
						return nil, errors.New("no chain")
					}
					return []byte(liveRules()), nil
				}
				if name == "iptables-restore" {
					data, err := os.ReadFile(args[len(args)-1])
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(data), ":ufw-user-forward") || strings.Contains(string(data), ":DOCKER-USER") {
						t.Fatal("Docker restart must not flush UFW authorization or unrelated Docker rules")
					}
				}
				if strings.HasPrefix(command, "iptables -I DOCKER-USER 1") {
					live = true
				}
				if strings.HasPrefix(command, "iptables -D DOCKER-USER") {
					live = false
				}
				return nil, nil
			}
			config := filepath.Join(dir, "ufw-default")
			if err := os.WriteFile(config, []byte("MANAGE_BUILTINS=no\n"), 0600); err != nil {
				t.Fatal(err)
			}
			s := &ShieldManager{AfterRulesPath: rules, UFWConfigPath: config, DropInPath: filepath.Join(dir, "docker.service.d", "secctl-shield.conf"), StateDir: filepath.Join(dir, "state")}
			err := s.Enable(context.Background())
			data, _ := os.ReadFile(rules)
			if failReload {
				if err == nil || string(data) != original {
					t.Fatalf("failure swallowed or file not restored: err=%v data=%s", err, data)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "-j DROP") || !strings.Contains(string(data), "-j ufw-user-forward") {
				t.Fatalf("no filtering: %s", data)
			}
			if strings.Contains(string(data), ":DOCKER-USER") {
				t.Fatal("must not flush unrelated DOCKER-USER rules")
			}
			if enabled, err := s.IsEnabled(context.Background()); err != nil || !enabled {
				t.Fatalf("enabled=%v err=%v calls=%v", enabled, err, calls)
			}
			if err := s.Enable(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := s.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(config, []byte("MANAGE_BUILTINS=yes\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.Enable(context.Background()); err == nil {
				t.Fatal("destructive UFW builtin management accepted")
			}
			if err := os.WriteFile(config, []byte("MANAGE_BUILTINS=no\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.Disable(context.Background()); err != nil {
				t.Fatal(err)
			}
			if enabled, _ := s.IsEnabled(context.Background()); enabled {
				t.Fatal("disable left protection reported active")
			}
			data, _ = os.ReadFile(rules)
			if strings.Contains(string(data), UFWRulesTagBegin) {
				t.Fatal("persistent block remained")
			}
		})
	}
}
