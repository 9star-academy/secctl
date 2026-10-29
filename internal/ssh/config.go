package ssh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
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
	if username == "" || strings.ContainsAny(username, "/?#@\\ \t\r\n") {
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return validKeys, nil
}

func isValidSSHKey(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
	default:
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	take := func() ([]byte, bool) {
		if len(raw) < 4 {
			return nil, false
		}
		n := uint64(binary.BigEndian.Uint32(raw[:4]))
		raw = raw[4:]
		if n > uint64(len(raw)) {
			return nil, false
		}
		value := raw[:int(n)]
		raw = raw[int(n):]
		return value, true
	}
	kind, ok := take()
	if !ok || string(kind) != fields[0] {
		return false
	}
	value, ok := take()
	if !ok {
		return false
	}
	switch fields[0] {
	case "ssh-ed25519":
		if len(value) != 32 {
			return false
		}
	case "sk-ssh-ed25519@openssh.com":
		if len(value) != 32 {
			return false
		}
		if _, ok = take(); !ok {
			return false
		}
	case "ssh-rsa":
		if len(value) == 0 {
			return false
		}
		modulus, ok := take()
		if !ok || len(modulus) == 0 {
			return false
		}
	default:
		if string(value) != "nistp256" && string(value) != "nistp384" && string(value) != "nistp521" {
			return false
		}
		point, ok := take()
		if !ok || len(point) == 0 || point[0] != 4 {
			return false
		}
		if strings.HasPrefix(fields[0], "sk-") {
			if _, ok = take(); !ok {
				return false
			}
		}
	}
	return len(raw) == 0
}

// InstallAuthorizedKeys appends keys into user's ~/.ssh/authorized_keys
func InstallAuthorizedKeys(targetUsername string, keys []string) (int, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	var account *user.User
	var err error
	if targetUsername == "" || targetUsername == "current" {
		account, err = user.Current()
	} else {
		account, err = user.Lookup(targetUsername)
	}
	if err != nil {
		return 0, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, err
	}
	return installAuthorizedKeys(account.HomeDir, uid, gid, keys)
}

func installAuthorizedKeys(homeDir string, uid, gid int, keys []string) (int, error) {
	if homeDir == "" {
		return 0, fmt.Errorf("无法获取用户 Home 目录")
	}
	for _, key := range keys {
		if !isValidSSHKey(key) || strings.ContainsAny(key, "\r\n") {
			return 0, fmt.Errorf("无效 SSH 公钥")
		}
	}
	root, err := os.OpenRoot(homeDir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	if err := root.Mkdir(".ssh", 0700); err != nil && !os.IsExist(err) {
		return 0, err
	}
	for _, name := range []string{".ssh", ".ssh/authorized_keys"} {
		if info, err := root.Lstat(name); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return 0, fmt.Errorf("拒绝写入符号链接: %s", name)
		} else if err != nil && !os.IsNotExist(err) {
			return 0, err
		}
	}
	// Root confines every open to the account's home, including racing path changes.
	directory, err := root.Open(".ssh")
	if err != nil {
		return 0, err
	}
	defer directory.Close()
	if err := directory.Chown(uid, gid); err != nil {
		return 0, err
	}
	if err := directory.Chmod(0700); err != nil {
		return 0, err
	}
	f, err := root.OpenFile(".ssh/authorized_keys", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if err := f.Chown(uid, gid); err != nil {
		return 0, err
	}
	if err := f.Chmod(0600); err != nil {
		return 0, err
	}
	existing, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}
	known := map[string]bool{}
	for _, line := range strings.Split(string(existing), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			known[fields[0]+" "+fields[1]] = true
		}
	}
	added := 0
	for _, key := range keys {
		fields := strings.Fields(key)
		normalized := fields[0] + " " + fields[1]
		if known[normalized] {
			continue
		}
		if _, err := fmt.Fprintf(f, "\n# Added by secctl\n%s\n", key); err != nil {
			return added, err
		}
		known[normalized] = true
		added++
	}
	return added, f.Sync()
}

const managedBegin = "# secctl ssh begin"
const managedEnd = "# secctl ssh end"

func UpdateSSHDConfig(original string, opts HardenOptions) (string, error) {
	if opts.Port < 0 || opts.Port > 65535 {
		return "", fmt.Errorf("SSH 端口必须在 1-65535 之间")
	}
	// Do not silently rewrite conditional authentication policies.
	for _, line := range strings.Split(original, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "Match") {
			return "", fmt.Errorf("配置包含 Match 条件块，请先手动核对；未修改配置")
		}
	}
	var directives []string
	if opts.Port > 0 {
		directives = append(directives, fmt.Sprintf("Port %d", opts.Port))
	}
	if opts.DisablePassword {
		directives = append(directives, "PasswordAuthentication no", "KbdInteractiveAuthentication no")
	}
	directives = append(directives, "PubkeyAuthentication yes")
	if opts.DisableRootLogin {
		directives = append(directives, "PermitRootLogin no")
	} else if opts.PermitRootKeysOnly {
		directives = append(directives, "PermitRootLogin prohibit-password")
	}
	changed := map[string]bool{"pubkeyauthentication": true}
	if opts.Port > 0 {
		changed["port"] = true
	}
	if opts.DisablePassword {
		changed["passwordauthentication"] = true
		changed["kbdinteractiveauthentication"] = true
		changed["challengeresponseauthentication"] = true
	}
	if opts.DisableRootLogin || opts.PermitRootKeysOnly {
		changed["permitrootlogin"] = true
	}
	var kept []string
	// Remove only marker comments; retain prior managed directives that this run does not change.
	for _, line := range strings.Split(original, "\n") {
		if strings.TrimSpace(line) == managedBegin || strings.TrimSpace(line) == managedEnd {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && changed[strings.ToLower(fields[0])] {
			continue
		}
		kept = append(kept, line)
	}
	return managedBegin + "\n" + strings.Join(directives, "\n") + "\n" + managedEnd + "\n" + strings.Join(kept, "\n"), nil
}

var CommandRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// ReloadSSHD never claims success without a successful service command.
func ReloadSSHD(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var failures []error
	if _, err := exec.LookPath("systemctl"); err == nil {
		for _, name := range []string{"ssh", "sshd"} {
			if out, err := CommandRunner(ctx, "systemctl", "reload", name); err == nil {
				return nil
			} else {
				failures = append(failures, fmt.Errorf("reload %s: %s (%w)", name, out, err))
			}
		}
	}
	if _, err := exec.LookPath("service"); err == nil {
		for _, name := range []string{"ssh", "sshd"} {
			if out, err := CommandRunner(ctx, "service", name, "reload"); err == nil {
				return nil
			} else {
				failures = append(failures, fmt.Errorf("reload %s: %s (%w)", name, out, err))
			}
		}
	}
	if len(failures) == 0 {
		return fmt.Errorf("未找到 SSH 服务管理工具")
	}
	return errors.Join(failures...)
}
