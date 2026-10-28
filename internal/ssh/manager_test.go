package ssh

import (
	"strings"
	"testing"
)

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
	validRSA := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@domain"
	validEd25519 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@domain"
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
