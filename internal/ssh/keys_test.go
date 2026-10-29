package ssh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchKeysBoundary(t *testing.T) {
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	for _, test := range []struct {
		name, body string
		status     int
		networkErr bool
		wantErr    bool
	}{
		{"valid", testPublicKey("ssh-ed25519"), 200, false, false},
		{"empty", "# none\n", 200, false, true}, {"invalid", "ssh-fake garbage", 200, false, true},
		{"not-found", "", 404, false, true}, {"network", "", 0, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "github.com" || r.URL.Path != "/testuser.keys" {
					t.Fatalf("unexpected URL: %v", r.URL)
				}
				if test.networkErr {
					return nil, errors.New("unreachable")
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: http.Header{}}, nil
			})
			keys, err := FetchGitHubKeys(context.Background(), "testuser")
			if (err != nil) != test.wantErr {
				t.Fatalf("keys=%v err=%v", keys, err)
			}
		})
	}
	for _, name := range []string{"", "../x", "name/path", "name?query"} {
		if _, err := FetchGitHubKeys(context.Background(), name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
}

func TestInstallKeysAndCheckReadiness(t *testing.T) {
	dir := t.TempDir()
	key := testPublicKey("ssh-ed25519")
	added, err := installAuthorizedKeys(dir, os.Getuid(), os.Getgid(), []string{key, key})
	if err != nil || added != 1 {
		t.Fatalf("added=%d err=%v", added, err)
	}
	added, err = installAuthorizedKeys(dir, os.Getuid(), os.Getgid(), []string{key + " changed-comment"})
	if err != nil || added != 0 {
		t.Fatalf("dedup failed: added=%d err=%v", added, err)
	}
	path := filepath.Join(dir, ".ssh", "authorized_keys")
	if err := checkKeysFile(path); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, ".ssh"), path} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("unsafe permissions: %v %v", info, err)
		}
	}
	if _, err := installAuthorizedKeys(dir, os.Getuid(), os.Getgid(), []string{"ssh-ed25519 garbage"}); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := installAuthorizedKeys("", os.Getuid(), os.Getgid(), []string{key}); err == nil {
		t.Fatal("empty home accepted")
	}
	if _, err := InstallAuthorizedKeys("secctl-nonexistent-account", []string{key}); err == nil {
		t.Fatal("unknown account accepted")
	}
	if err := os.WriteFile(path, []byte("# no keys\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if checkKeysFile(path) == nil || checkKeysFile(filepath.Join(dir, "missing")) == nil {
		t.Fatal("missing keys reported ready")
	}
	if checkLoginKeys("secctl-nonexistent-account") == nil {
		t.Fatal("unknown user ready")
	}
}

func TestIncludedMatchRejected(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "included.conf")
	config := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(included, []byte("Match User alice\n PasswordAuthentication yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("Include "+included+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if rejectMatchIncludes(config, map[string]bool{}) == nil {
		t.Fatal("included Match policy ignored")
	}
}

func TestAuthorizedKeysSymlinkCannotEscapeHome(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "authorized_keys")
	if err := os.WriteFile(target, []byte("untouched\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if _, err := installAuthorizedKeys(home, os.Getuid(), os.Getgid(), []string{testPublicKey("ssh-ed25519")}); err == nil {
		t.Fatal("symlink accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "untouched\n" {
		t.Fatal("outside file changed")
	}
}
