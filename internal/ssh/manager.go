package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Manager struct {
	Out io.Writer
	In  io.Reader
	// Test seams keep privileged service operations out of unit tests.
	ValidateKeys func(string) error
}

func NewManager(out io.Writer, in io.Reader) *Manager {
	if out == nil {
		out = os.Stdout
	}
	if in == nil {
		in = os.Stdin
	}
	return &Manager{Out: out, In: in, ValidateKeys: checkLoginKeys}
}

func (m *Manager) Harden(ctx context.Context, opts HardenOptions) (*HardenResult, error) {
	if opts.Port < 0 || opts.Port > 65535 {
		return nil, fmt.Errorf("SSH 端口必须在 1-65535 之间")
	}
	if opts.TimeoutSeconds <= 0 || opts.TimeoutSeconds > 3600 {
		return nil, fmt.Errorf("回滚超时必须在 1-3600 秒之间")
	}
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = "/etc/ssh/sshd_config"
	}
	if err := rejectMatchIncludes(configPath, map[string]bool{}); err != nil {
		return nil, err
	}
	info, err := os.Lstat(configPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("SSH 配置必须是普通文件: %s", configPath)
	}
	orig, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	newConfig, err := UpdateSSHDConfig(string(orig), opts)
	if err != nil {
		return nil, err
	}
	if err := validateSSHD(ctx, configPath, newConfig, opts); err != nil {
		return nil, err
	}
	if opts.DisableRootLogin && (opts.TargetUser == "root" || opts.TargetUser == "" && os.Geteuid() == 0) {
		return nil, fmt.Errorf("禁止 root 登录时必须通过 --user 指定可登录的非 root 用户")
	}
	keys := append([]string{}, opts.ManualKeys...)
	if opts.GitHubUser != "" {
		fetched, err := FetchGitHubKeys(ctx, opts.GitHubUser)
		if err != nil {
			return nil, err
		}
		keys = append(keys, fetched...)
	}
	added, err := InstallAuthorizedKeys(opts.TargetUser, keys)
	if err != nil {
		return nil, err
	}
	if opts.DisablePassword || opts.PermitRootKeysOnly {
		if err := m.ValidateKeys(opts.TargetUser); err != nil {
			return nil, err
		}
	}
	// A unique backup is retained even after confirmation or automatic recovery.
	backup, err := os.CreateTemp(filepath.Dir(configPath), "sshd_config.secctl.bak.*")
	if err != nil {
		return nil, err
	}
	backupPath := backup.Name()
	_, writeErr := backup.Write(orig)
	syncErr := backup.Sync()
	closeErr := backup.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return nil, err
	}
	guard, err := StartRollback(ctx, configPath, orig, info.Mode(), opts.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(m.Out, "✔ 已备份: %s\n✔ 独立回滚定时器: %s.timer\n", backupPath, guard.Unit)
	err = guard.Apply(func() error {
		if err := atomicConfig(configPath, []byte(newConfig), info.Mode()); err != nil {
			return err
		}
		if err := ReloadSSHD(ctx); err != nil {
			return err
		}
		if opts.Port > 0 {
			out, err := CommandRunner(ctx, "ss", "-H", "-ltnp", "sport = :"+strconv.Itoa(opts.Port))
			if err != nil || !strings.Contains(string(out), "sshd") {
				return fmt.Errorf("未确认 sshd 正在新端口监听（包括 socket 激活环境）: %s (%v)", out, err)
			}
		}
		return nil
	})
	if err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		rollbackErr := guard.Rollback(rollbackCtx)
		return nil, errors.Join(fmt.Errorf("应用 SSH 配置失败: %w", err), rollbackErr)
	}
	result := &HardenResult{BackupPath: backupPath, KeysAdded: added, PortChangedTo: opts.Port, PasswordAuth: !opts.DisablePassword}
	if opts.SkipRollbackConfirm {
		if err := guard.Confirm(ctx); err != nil {
			return nil, err
		}
		return result, nil
	}
	fmt.Fprintf(m.Out, "请新开终端验证 SSH 登录；成功后在 %d 秒内输入 confirm。\n超时、中断或会话退出后，由独立定时器恢复原配置。\n", opts.TimeoutSeconds)
	confirmed := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(m.In)
		if scanner.Scan() {
			confirmed <- strings.TrimSpace(scanner.Text()) == "confirm"
		} else {
			confirmed <- false
		}
	}()
	timer := time.NewTimer(time.Duration(opts.TimeoutSeconds) * time.Second)
	defer timer.Stop()
	var reason error
	select {
	case ok := <-confirmed:
		if ok {
			if err := guard.Confirm(ctx); err != nil {
				return nil, err
			}
			fmt.Fprintln(m.Out, "✔ 新 SSH 配置已确认")
			return result, nil
		}
		reason = fmt.Errorf("未收到 confirm，恢复原配置")
	case <-timer.C:
		reason = fmt.Errorf("确认超时，恢复原配置")
	case <-ctx.Done():
		reason = ctx.Err()
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := guard.Rollback(rollbackCtx); err != nil {
		return nil, errors.Join(reason, err)
	}
	fmt.Fprintln(m.Out, "✔ 已恢复原 SSH 配置并成功重载服务")
	return nil, reason
}

func validateSSHD(ctx context.Context, configPath, config string, opts HardenOptions) error {
	binary, err := exec.LookPath("sshd")
	if err != nil {
		return fmt.Errorf("未找到 sshd，无法验证配置: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(configPath), ".secctl-sshd-test-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(config); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	for _, flag := range []string{"-t", "-T"} {
		out, err := CommandRunner(ctx, binary, flag, "-f", f.Name())
		if err != nil {
			return fmt.Errorf("sshd %s 校验失败，未写入配置: %s (%w)", flag, out, err)
		}
		if flag == "-T" {
			values := map[string][]string{}
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					values[fields[0]] = append(values[fields[0]], fields[1])
				}
			}
			if opts.DisablePassword || opts.PermitRootKeysOnly {
				if len(values["authorizedkeysfile"]) == 0 || values["authorizedkeysfile"][0] != ".ssh/authorized_keys" {
					return fmt.Errorf("仅支持默认 AuthorizedKeysFile .ssh/authorized_keys，请手工核对自定义认证路径")
				}
			}
			wanted := map[string]string{"pubkeyauthentication": "yes"}
			if opts.DisablePassword {
				wanted["passwordauthentication"] = "no"
				wanted["kbdinteractiveauthentication"] = "no"
			}
			if opts.DisableRootLogin {
				wanted["permitrootlogin"] = "no"
			} else if opts.PermitRootKeysOnly {
				wanted["permitrootlogin"] = "without-password"
			}
			for key, want := range wanted {
				got := values[key]
				if key == "permitrootlogin" && want == "without-password" && len(got) == 1 && got[0] == "prohibit-password" {
					continue
				}
				if len(got) != 1 || got[0] != want {
					return fmt.Errorf("实际 SSH 配置 %s=%v，预期 %s；未修改配置", key, got, want)
				}
			}
			if opts.Port > 0 && (len(values["port"]) != 1 || values["port"][0] != strconv.Itoa(opts.Port)) {
				return fmt.Errorf("Include 中的 Port 与目标端口冲突: %v；请先手动整理端口配置", values["port"])
			}
		}
	}
	return nil
}

func rejectMatchIncludes(path string, seen map[string]bool) error {
	if seen[path] {
		return nil
	}
	seen[path] = true
	if len(seen) > 128 {
		return fmt.Errorf("SSH Include 文件过多")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if strings.EqualFold(fields[0], "Match") {
			return fmt.Errorf("%s 包含 Match 条件块，自动加固已停止；请手动核对条件策略", path)
		}
		if strings.EqualFold(fields[0], "Include") {
			if strings.ContainsAny(line, "\"'\\%") {
				return fmt.Errorf("%s 包含带引号、转义或动态标记的 Include，自动加固已停止；请手动整理配置", path)
			}
			for _, pattern := range fields[1:] {
				if strings.HasPrefix(pattern, "#") {
					break
				}
				pattern = strings.Trim(pattern, "\"")
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join("/etc/ssh", pattern)
				}
				paths, err := filepath.Glob(pattern)
				if err != nil {
					return err
				}
				for _, include := range paths {
					if err := rejectMatchIncludes(include, seen); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func checkLoginKeys(target string) error {
	var account *user.User
	var err error
	if target == "" || target == "current" {
		account, err = user.Current()
	} else {
		account, err = user.Lookup(target)
	}
	if err != nil {
		return err
	}
	return checkKeysFile(filepath.Join(account.HomeDir, ".ssh", "authorized_keys"))
}

func checkKeysFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("目标用户没有可读取的 authorized_keys，未禁用密码: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if isValidSSHKey(strings.TrimSpace(line)) {
			return nil
		}
	}
	return fmt.Errorf("目标用户没有有效公钥；请先用 --github 或 --key 配置并验证密钥登录")
}
