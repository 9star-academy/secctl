package dockershield

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	UFWRulesTagBegin = "# secctl docker-shield begin"
	UFWRulesTagEnd   = "# secctl docker-shield end"
	UFWAfterRules    = "/etc/ufw/after.rules"
	chain            = "SECCTL-DOCKER"
	hook             = "-m comment --comment secctl-shield -j SECCTL-DOCKER"
)

type ShieldManager struct {
	AfterRulesPath string
	UFWConfigPath  string
	DropInPath     string
	StateDir       string
}

func NewShieldManager() *ShieldManager {
	return &ShieldManager{AfterRulesPath: UFWAfterRules, UFWConfigPath: "/etc/default/ufw", DropInPath: "/etc/systemd/system/docker.service.d/secctl-shield.conf", StateDir: "/var/lib/secctl/docker-shield"}
}

var CommandRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return cmd.CombinedOutput()
}

func liveRules() string {
	return `-A SECCTL-DOCKER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A SECCTL-DOCKER -i docker0 -j RETURN
-A SECCTL-DOCKER -i br-+ -j RETURN
-A SECCTL-DOCKER -j ufw-user-forward
-A SECCTL-DOCKER -o docker0 -j DROP
-A SECCTL-DOCKER -o br-+ -j DROP
-A SECCTL-DOCKER -j RETURN
`
}

func rulesBlock() string { return "*filter\n:SECCTL-DOCKER - [0:0]\n" + liveRules() + "COMMIT\n" }

func ufwRulesBlock() string {
	// UFW loads after.rules before user.rules has recreated its secondary chains.
	// Declare the dependency only during UFW initialization; user.rules then loads
	// its ACL. Runtime Docker restarts must never declare/flush this UFW-owned chain.
	return strings.Replace(rulesBlock(), "*filter\n", "*filter\n:ufw-user-forward - [0:0]\n", 1)
}

func (s *ShieldManager) defaults() {
	d := NewShieldManager()
	if s.AfterRulesPath == "" {
		s.AfterRulesPath = d.AfterRulesPath
	}
	if s.UFWConfigPath == "" {
		s.UFWConfigPath = d.UFWConfigPath
	}
	if s.DropInPath == "" {
		s.DropInPath = d.DropInPath
	}
	if s.StateDir == "" {
		s.StateDir = d.StateDir
	}
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := CommandRunner(ctx, name, args...)
	if err != nil {
		return out, fmt.Errorf("%s %s: %s (%w)", name, strings.Join(args, " "), out, err)
	}
	return out, nil
}

func (s *ShieldManager) preflight(ctx context.Context) error {
	s.defaults()
	for _, name := range []string{"ufw", "iptables", "iptables-restore", "docker", "systemctl"} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("Docker Shield 需要 UFW、Docker iptables 和 systemd: %w", err)
		}
	}
	if _, err := os.Stat(s.AfterRulesPath); err != nil {
		return fmt.Errorf("UFW 规则文件不可用: %w", err)
	}
	config, err := os.ReadFile(s.UFWConfigPath)
	if err != nil {
		return fmt.Errorf("无法读取 UFW 配置: %w", err)
	}
	manageBuiltins := ""
	for _, line := range strings.Split(string(config), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 && parts[0] == "MANAGE_BUILTINS" {
			manageBuiltins = strings.Trim(strings.TrimSpace(strings.SplitN(parts[1], "#", 2)[0]), "\"'")
		}
	}
	if manageBuiltins != "no" {
		return fmt.Errorf("Docker Shield 要求 /etc/default/ufw 中 MANAGE_BUILTINS=no，避免 UFW reload 清空 Docker 链路")
	}
	out, err := run(ctx, "ufw", "status")
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "Status: active") {
		return fmt.Errorf("UFW 未激活，无法启用 Docker Shield")
	}
	ids, err := run(ctx, "docker", "network", "ls", "-q")
	if err != nil {
		return err
	}
	networks := strings.Fields(string(ids))
	if len(networks) == 0 {
		return fmt.Errorf("未发现运行中的 Docker 网络")
	}
	args := append([]string{"network", "inspect", "--format", `{{.Driver}}|{{.EnableIPv6}}|{{index .Options "com.docker.network.bridge.name"}}`}, networks...)
	ipv6, err := run(ctx, "docker", args...)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(ipv6)), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 3 {
			return fmt.Errorf("无法确认 Docker 网络类型")
		}
		if fields[0] == "host" || fields[0] == "null" {
			continue
		}
		if fields[0] != "bridge" || fields[1] != "false" {
			return fmt.Errorf("当前 Docker Shield 仅支持 IPv4 bridge 网络")
		}
		name := fields[2]
		if name != "" && name != "<no value>" && name != "docker0" && !strings.HasPrefix(name, "br-") {
			return fmt.Errorf("不支持自定义网桥名称 %q；当前仅支持 docker0/br-*", name)
		}
	}

	forward, err := run(ctx, "iptables", "-S", "FORWARD")
	if err != nil {
		return err
	}
	if !strings.Contains(string(forward), "-j DOCKER-USER") {
		return fmt.Errorf("未找到 Docker iptables FORWARD → DOCKER-USER 链路；不支持原生 nftables 后端")
	}
	if _, err := run(ctx, "iptables", "-C", "FORWARD", "-j", "DOCKER-USER"); err != nil {
		return fmt.Errorf("Docker FORWARD 中没有直接的 DOCKER-USER 跳转: %w", err)
	}
	if _, err := run(ctx, "iptables", "-S", "DOCKER-USER"); err != nil {
		return err
	}
	return nil
}

func (s *ShieldManager) IsEnabled(ctx context.Context) (bool, error) {
	s.defaults()
	// A marker on disk is configuration, not evidence of active filtering.
	data, err := os.ReadFile(s.AfterRulesPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !strings.Contains(string(data), UFWRulesTagBegin) {
		return false, nil
	}
	if err := s.preflight(ctx); err != nil {
		return false, err
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return false, err
	}
	out, err := run(ctx, "ufw", "status")
	if err != nil {
		return false, err
	}
	if !strings.Contains(string(out), "Status: active") {
		return false, nil
	}
	forward, err := run(ctx, "iptables", "-S", "FORWARD")
	if err != nil {
		return false, err
	}
	if !strings.Contains(string(forward), "-j DOCKER-USER") {
		return false, nil
	}
	user, err := run(ctx, "iptables", "-S", "DOCKER-USER")
	if err != nil {
		return false, err
	}
	first := ""
	for _, line := range strings.Split(string(user), "\n") {
		if strings.HasPrefix(line, "-A DOCKER-USER ") {
			first = normalize(line)
			break
		}
	}
	if first != "-A DOCKER-USER "+hook {
		return false, nil
	}
	live, err := run(ctx, "iptables", "-S", chain)
	if err != nil {
		return false, err
	}
	var actual []string
	for _, line := range strings.Split(string(live), "\n") {
		if strings.HasPrefix(line, "-A "+chain+" ") {
			actual = append(actual, normalize(line))
		}
	}
	return strings.Join(actual, "\n") == strings.TrimSpace(liveRules()), nil
}

func normalize(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `"`, ""), "ESTABLISHED,RELATED", "RELATED,ESTABLISHED")
}

func (s *ShieldManager) locked(fn func() error) error {
	s.defaults()
	f, err := os.OpenFile(filepath.Join(filepath.Dir(s.AfterRulesPath), ".secctl-shield.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func withoutBlock(content string) (string, error) {
	start, end := strings.Index(content, UFWRulesTagBegin), strings.Index(content, UFWRulesTagEnd)
	if start < 0 && end < 0 {
		return content, nil
	}
	if start < 0 || end < start {
		return "", fmt.Errorf("Docker Shield 标记不完整，请先检查 after.rules")
	}
	return content[:start] + content[end+len(UFWRulesTagEnd):], nil
}

func (s *ShieldManager) Enable(ctx context.Context) error {
	return s.locked(func() error {
		if err := s.preflight(ctx); err != nil {
			return err
		}
		original, err := os.ReadFile(s.AfterRulesPath)
		if err != nil {
			return err
		}
		stripped, err := withoutBlock(string(original))
		if err != nil {
			return err
		}
		oldDrop, dropErr := os.ReadFile(s.DropInPath)
		if dropErr != nil && !os.IsNotExist(dropErr) {
			return dropErr
		}
		wasEnabled, _ := s.IsEnabled(ctx)
		if err := os.MkdirAll(s.StateDir, 0700); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(s.DropInPath), 0755); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		if err := copyBinary(executable, filepath.Join(s.StateDir, "secctl")); err != nil {
			return err
		}
		// Docker may start after UFW at boot. Hook it only once Docker has created its chains.
		executablePath := filepath.Join(s.StateDir, "secctl")
		escaped := strings.NewReplacer("%", "%%", "$", "$$", "\\", "\\\\", "\"", "\\\"").Replace(executablePath)
		drop := "[Service]\n# Managed by secctl Docker Shield\nExecStartPost=\"" + escaped + "\" _docker-shield-apply\n"
		rollback := func(cause error) error {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var failures []error
			if !wasEnabled {
				failures = append(failures, s.removeLive(recoveryCtx))
			}
			failures = append(failures, os.WriteFile(s.AfterRulesPath, original, 0640))
			if dropErr == nil {
				failures = append(failures, os.WriteFile(s.DropInPath, oldDrop, 0644))
			} else if err := os.Remove(s.DropInPath); err != nil && !os.IsNotExist(err) {
				failures = append(failures, err)
			}
			_, err = run(recoveryCtx, "ufw", "reload")
			failures = append(failures, err)
			_, err = run(recoveryCtx, "systemctl", "daemon-reload")
			failures = append(failures, err)
			return errors.Join(append([]error{cause}, failures...)...)
		}
		newContent := stripped + "\n" + UFWRulesTagBegin + "\n" + ufwRulesBlock() + UFWRulesTagEnd + "\n"
		if err := os.WriteFile(s.AfterRulesPath, []byte(newContent), 0640); err != nil {
			return rollback(err)
		}
		if err := os.WriteFile(s.DropInPath, []byte(drop), 0644); err != nil {
			return rollback(err)
		}
		if _, err := run(ctx, "systemctl", "daemon-reload"); err != nil {
			return rollback(err)
		}
		if _, err := run(ctx, "ufw", "reload"); err != nil {
			return rollback(err)
		}
		if err := s.applyLive(ctx); err != nil {
			return rollback(err)
		}
		if enabled, err := s.IsEnabled(ctx); err != nil || !enabled {
			return rollback(errors.Join(fmt.Errorf("Docker Shield 运行状态校验失败"), err))
		}
		return nil
	})
}

// Apply is used by Docker's systemd ExecStartPost after every daemon start.
func (s *ShieldManager) Apply(ctx context.Context) error {
	return s.locked(func() error {
		if err := s.preflight(ctx); err != nil {
			return err
		}
		data, err := os.ReadFile(s.AfterRulesPath)
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), UFWRulesTagBegin) {
			return fmt.Errorf("未配置 Docker Shield")
		}
		return s.applyLive(ctx)
	})
}

func (s *ShieldManager) applyLive(ctx context.Context) error {
	f, err := os.CreateTemp(filepath.Dir(s.AfterRulesPath), ".secctl-docker-rules-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(rulesBlock()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// --noflush flushes only chains declared here: never declare DOCKER-USER.
	if _, err := run(ctx, "iptables-restore", "--noflush", "--wait", "5", f.Name()); err != nil {
		return err
	}
	if err := s.removeHooks(ctx); err != nil {
		return err
	}
	args := append([]string{"-I", "DOCKER-USER", "1"}, strings.Fields(hook)...)
	_, err = run(ctx, "iptables", args...)
	return err
}

func (s *ShieldManager) removeHooks(ctx context.Context) error {
	out, err := run(ctx, "iptables", "-S", "DOCKER-USER")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if normalize(line) == "-A DOCKER-USER "+hook {
			args := append([]string{"-D", "DOCKER-USER"}, strings.Fields(hook)...)
			if _, err := run(ctx, "iptables", args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ShieldManager) removeLive(ctx context.Context) error {
	if err := s.removeHooks(ctx); err != nil {
		return err
	}
	if _, err := run(ctx, "iptables", "-S", chain); err != nil {
		return nil
	}
	if _, err := run(ctx, "iptables", "-F", chain); err != nil {
		return err
	}
	_, err := run(ctx, "iptables", "-X", chain)
	return err
}

func (s *ShieldManager) Disable(ctx context.Context) error {
	return s.locked(func() error {
		original, err := os.ReadFile(s.AfterRulesPath)
		if err != nil {
			return err
		}
		stripped, err := withoutBlock(string(original))
		if err != nil {
			return err
		}
		if stripped == string(original) {
			return nil
		}
		oldDrop, dropErr := os.ReadFile(s.DropInPath)
		if dropErr != nil && !os.IsNotExist(dropErr) {
			return dropErr
		}
		recoverState := func(cause error) error {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			failures := []error{cause}
			failures = append(failures, os.WriteFile(s.AfterRulesPath, original, 0640))
			if dropErr == nil {
				failures = append(failures, os.WriteFile(s.DropInPath, oldDrop, 0644))
			}
			_, err := run(recoveryCtx, "systemctl", "daemon-reload")
			failures = append(failures, err)
			_, err = run(recoveryCtx, "ufw", "reload")
			failures = append(failures, err)
			failures = append(failures, s.applyLive(recoveryCtx))
			return errors.Join(failures...)
		}
		if err := s.removeLive(ctx); err != nil {
			return recoverState(err)
		}
		if err := os.WriteFile(s.AfterRulesPath, []byte(stripped), 0640); err != nil {
			return recoverState(err)
		}
		if err := os.Remove(s.DropInPath); err != nil && !os.IsNotExist(err) {
			return recoverState(err)
		}
		if _, err := run(ctx, "systemctl", "daemon-reload"); err != nil {
			return recoverState(err)
		}
		if _, err := run(ctx, "ufw", "reload"); err != nil {
			return recoverState(err)
		}
		return os.RemoveAll(s.StateDir)
	})
}

func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	f, err := os.CreateTemp(filepath.Dir(dst), ".secctl-bin-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0700); err != nil {
		_ = f.Close()
		return err
	}
	_, copyErr := io.Copy(f, in)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	return os.Rename(f.Name(), dst)
}
