//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcAddressesAndSSProcess(t *testing.T) {
	for _, test := range []struct {
		encoded, ip string
		port        int
	}{
		{"0100007F:0016", "127.0.0.1", 22}, {"00000000000000000000000001000000:1538", "::1", 5432},
		{"00000000:0050", "0.0.0.0", 80},
	} {
		ip, port, err := parseHexAddr(test.encoded)
		if err != nil || ip != test.ip || port != test.port {
			t.Fatalf("%s => %s:%d err=%v", test.encoded, ip, port, err)
		}
	}
	name, pid := parseSSProcess(`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=638,fd=3))`)
	if name != "sshd" || pid != 638 {
		t.Fatalf("%s %d", name, pid)
	}
	file := filepath.Join(t.TempDir(), "tcp")
	if err := os.WriteFile(file, []byte("sl local_address rem_address st\n0: 0100007F:0016 00000000:0000 0A\n1: 00000000:1538 00000000:0000 01\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ports := parseProcNet(file, "tcp")
	if len(ports) != 1 || ports[0].IsPublic {
		t.Fatalf("ports=%+v", ports)
	}
}
