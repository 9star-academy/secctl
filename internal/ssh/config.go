package ssh

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// HardenOptions holds parameters for hardening SSH.
type HardenOptions struct {
	ConfigPath          string
	Port                int
	DisablePassword     bool
	DisableRootLogin    bool
	PermitRootKeysOnly  bool
	TargetUser          string
	GitHubUser          string
	ManualKeys          []string
	TimeoutSeconds      int
	SkipRollbackConfirm bool
}

// Result summary of hardening
type HardenResult struct {
	BackupPath    string
	KeysAdded     int
	PortChangedTo int
	PasswordAuth  bool
	NeedsRestart  bool
}

// FetchGitHubKeys downloads public SSH keys for a GitHub user.
func FetchGitHubKeys(ctx context.Context, username string) ([]string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("GitHub 用户名不能为空")
	}

	url := fmt.Sprintf("https://github.com/%s.keys", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "secctl/1.0 (9star-academy)")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接 GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取 GitHub 公钥失败 (HTTP %d): 账号可能不存在", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var validKeys []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate key prefix (ssh-rsa, ssh-ed25519, ecdsa-*, etc.)
		if isValidSSHKey(line) {
			validKeys = append(validKeys, line)
		}
	}

	if len(validKeys) == 0 {
		return nil, fmt.Errorf("GitHub 用户 %s 未公开任何有效 SSH 公钥", username)
	}

	return validKeys, nil
}

func isValidSSHKey(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	t := fields[0]
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")
}

// InstallAuthorizedKeys appends keys into user's ~/.ssh/authorized_keys
func InstallAuthorizedKeys(targetUsername string, keys []string) (int, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	homeDir := ""
	if targetUsername == "" || targetUsername == "current" {
		homeDir = os.Getenv("HOME")
	} else {
		u, err := user.Lookup(targetUsername)
		if err != nil {
			return 0, fmt.Errorf("未找到系统用户 %s: %w", targetUsername, err)
		}
		homeDir = u.HomeDir
	}

	if homeDir == "" {
		return 0, fmt.Errorf("无法获取用户的 Home 目录")
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return 0, fmt.Errorf("创建 %s 失败: %w", sshDir, err)
	}

	akFile := filepath.Join(sshDir, "authorized_keys")
	existingMap := make(map[string]bool)

	if data, err := os.ReadFile(akFile); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			l := strings.TrimSpace(scanner.Text())
			if l != "" && !strings.HasPrefix(l, "#") {
				// Normalize key by taking key-type and base64 part
				f := strings.Fields(l)
				if len(f) >= 2 {
					existingMap[f[0]+" "+f[1]] = true
				}
			}
		}
	}

	var toAppend []string
	added := 0
	for _, k := range keys {
		f := strings.Fields(k)
		if len(f) >= 2 {
			norm := f[0] + " " + f[1]
			if !existingMap[norm] {
				toAppend = append(toAppend, k)
				existingMap[norm] = true
				added++
			}
		}
	}

	if len(toAppend) > 0 {
		f, err := os.OpenFile(akFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return 0, fmt.Errorf("写入 %s 失败: %w", akFile, err)
		}
		defer f.Close()

		for _, k := range toAppend {
			if _, err := fmt.Fprintf(f, "\n# Added by secctl on %s\n%s\n", time.Now().Format("2006-01-02 15:04:05"), k); err != nil {
				return 0, err
			}
		}
	}

	// Ensure 0600 permissions
	_ = os.Chmod(akFile, 0600)
	_ = os.Chmod(sshDir, 0700)

	return added, nil
}

// UpdateSSHDConfig modifies sshd_config in memory and returns new content and changes.
func UpdateSSHDConfig(original string, opts HardenOptions) (string, error) {
	lines := strings.Split(original, "\n")
	newLines := make([]string, 0, len(lines)+10)

	foundPort := false
	foundPasswordAuth := false
	foundKbdInteractive := false
	foundPubkeyAuth := false
	foundPermitRoot := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)

		// Check commented or active directives
		if len(fields) >= 1 {
			directive := strings.TrimPrefix(fields[0], "#")
			directive = strings.ToLower(directive)

			if directive == "port" && opts.Port > 0 {
				if !foundPort {
					newLines = append(newLines, fmt.Sprintf("Port %d", opts.Port))
					foundPort = true
				}
				continue
			}

			if directive == "passwordauthentication" && opts.DisablePassword {
				if !foundPasswordAuth {
					newLines = append(newLines, "PasswordAuthentication no")
					foundPasswordAuth = true
				}
				continue
			}

			if (directive == "kbdinteractiveauthentication" || directive == "challengeresponseauthentication") && opts.DisablePassword {
				if !foundKbdInteractive {
					newLines = append(newLines, "KbdInteractiveAuthentication no")
					foundKbdInteractive = true
				}
				continue
			}

			if directive == "pubkeyauthentication" {
				if !foundPubkeyAuth {
					newLines = append(newLines, "PubkeyAuthentication yes")
					foundPubkeyAuth = true
				}
				continue
			}

			if directive == "permitrootlogin" {
				if opts.DisableRootLogin {
					if !foundPermitRoot {
						newLines = append(newLines, "PermitRootLogin no")
						foundPermitRoot = true
					}
					continue
				} else if opts.PermitRootKeysOnly {
					if !foundPermitRoot {
						newLines = append(newLines, "PermitRootLogin prohibit-password")
						foundPermitRoot = true
					}
					continue
				}
			}
		}

		newLines = append(newLines, line)
	}

	// If directives were never present, append them at the end
	if opts.Port > 0 && !foundPort {
		newLines = append(newLines, fmt.Sprintf("Port %d", opts.Port))
	}
	if opts.DisablePassword && !foundPasswordAuth {
		newLines = append(newLines, "PasswordAuthentication no")
	}
	if opts.DisablePassword && !foundKbdInteractive {
		newLines = append(newLines, "KbdInteractiveAuthentication no")
	}
	if !foundPubkeyAuth {
		newLines = append(newLines, "PubkeyAuthentication yes")
	}
	if opts.DisableRootLogin && !foundPermitRoot {
		newLines = append(newLines, "PermitRootLogin no")
	} else if opts.PermitRootKeysOnly && !foundPermitRoot {
		newLines = append(newLines, "PermitRootLogin prohibit-password")
	}

	return strings.Join(newLines, "\n"), nil
}

// ReloadSSHD triggers ssh daemon reload safely.
func ReloadSSHD(ctx context.Context) error {
	// Try systemctl first
	if _, err := exec.LookPath("systemctl"); err == nil {
		// Ubuntu/Debian uses 'ssh', CentOS/RHEL uses 'sshd'
		for _, name := range []string{"ssh", "sshd"} {
			cmd := exec.CommandContext(ctx, "systemctl", "reload", name)
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
		// Fallback to restart if reload is unsupported
		for _, name := range []string{"ssh", "sshd"} {
			cmd := exec.CommandContext(ctx, "systemctl", "restart", name)
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
	}

	// Try service command
	if _, err := exec.LookPath("service"); err == nil {
		for _, name := range []string{"ssh", "sshd"} {
			cmd := exec.CommandContext(ctx, "service", name, "reload")
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
	}

	return nil
}
