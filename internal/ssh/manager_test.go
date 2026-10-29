package ssh

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReloadFailureIsReported(t *testing.T) {
	bin := t.TempDir()
	for _, name := range []string{"systemctl", "service"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	if err := ReloadSSHD(context.Background()); err == nil {
		t.Fatal("failed reload reported success")
	}
}

func TestManagedDirectivesPrecedeIncludes(t *testing.T) {
	got, err := UpdateSSHDConfig("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n", HardenOptions{DisablePassword: true, Port: 22022})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(got, "PasswordAuthentication no") > strings.Index(got, "Include ") {
		t.Fatal("Include can override hardening")
	}
	if strings.Index(got, "Port 22022") > strings.Index(got, "Include ") {
		t.Fatal("port not prepended")
	}
}

func TestMatchAndInvalidPortRejectedBeforeRewrite(t *testing.T) {
	for _, opts := range []HardenOptions{{Port: 65536}, {Port: -1}} {
		if _, err := UpdateSSHDConfig("Port 22\n", opts); err == nil {
			t.Fatal("invalid port accepted")
		}
	}
	if _, err := UpdateSSHDConfig("Match User guest\n X11Forwarding no\n", HardenOptions{Port: 22022}); err == nil {
		t.Fatal("unsupported Match block rewritten")
	}
}

func TestUpdateSSHDConfig(t *testing.T) {
	sample := `# Package generated configuration file
# See the sshd_config(5) manpage for details

Port 22
PermitRootLogin yes
PasswordAuthentication yes
`

	opts := HardenOptions{
		Port:             22022,
		DisablePassword:  true,
		DisableRootLogin: true,
	}

	result, err := UpdateSSHDConfig(sample, opts)
	if err != nil {
		t.Fatalf("UpdateSSHDConfig failed: %v", err)
	}

	if !strings.Contains(result, "Port 22022") {
		t.Errorf("expected Port 22022 in config, got:\n%s", result)
	}
	if !strings.Contains(result, "PasswordAuthentication no") {
		t.Errorf("expected PasswordAuthentication no, got:\n%s", result)
	}
	if !strings.Contains(result, "PermitRootLogin no") {
		t.Errorf("expected PermitRootLogin no, got:\n%s", result)
	}
	if !strings.Contains(result, "PubkeyAuthentication yes") {
		t.Errorf("expected PubkeyAuthentication yes, got:\n%s", result)
	}
}

func TestIsValidSSHKey(t *testing.T) {
	validRSA := testPublicKey("ssh-rsa")
	validEd25519 := testPublicKey("ssh-ed25519")
	invalid := "some-random-text-without-valid-prefix"

	if !isValidSSHKey(validRSA) {
		t.Errorf("expected valid RSA key")
	}
	if !isValidSSHKey(validEd25519) {
		t.Errorf("expected valid Ed25519 key")
	}
	if isValidSSHKey(invalid) {
		t.Errorf("expected invalid for non-key text")
	}
}

func testPublicKey(kind string) string {
	var raw []byte
	appendField := func(value []byte) {
		size := make([]byte, 4)
		binary.BigEndian.PutUint32(size, uint32(len(value)))
		raw = append(raw, size...)
		raw = append(raw, value...)
	}
	appendField([]byte(kind))
	if kind == "ssh-rsa" {
		appendField([]byte{1, 0, 1})
		appendField(make([]byte, 256))
	} else {
		appendField(make([]byte, 32))
	}
	return kind + " " + base64.StdEncoding.EncodeToString(raw)
}
