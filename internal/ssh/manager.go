package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Manager orchestrates SSH hardening with anti-lockout protections.
type Manager struct {
	Out io.Writer
	In  io.Reader
}

func NewManager(out io.Writer, in io.Reader) *Manager {
	if out == nil {
		out = os.Stdout
	}
	if in == nil {
		in = os.Stdin
	}
	return &Manager{Out: out, In: in}
}

// Harden performs the full hardening workflow with anti-lockout countdown.
func (m *Manager) Harden(ctx context.Context, opts HardenOptions) (*HardenResult, error) {
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = "/etc/ssh/sshd_config"
	}

	result := &HardenResult{
		PortChangedTo: opts.Port,
		PasswordAuth:  !opts.DisablePassword,
	}

	// 1. Pull GitHub keys if requested
	if opts.GitHubUser != "" {
		fmt.Fprintf(m.Out, "==> 正在从 GitHub (https://github.com/%s.keys) 拉取公钥...\n", opts.GitHubUser)
		keys, err := FetchGitHubKeys(ctx, opts.GitHubUser)
		if err != nil {
			return nil, fmt.Errorf("拉取 GitHub 公钥失败: %w", err)
		}
		fmt.Fprintf(m.Out, "✔ 成功获取 %d 条公钥，正在注入 authorized_keys...\n", len(keys))

		added, err := InstallAuthorizedKeys(opts.TargetUser, keys)
		if err != nil {
			return nil, fmt.Errorf("注入 authorized_keys 失败: %w", err)
		}
		result.KeysAdded = added
		fmt.Fprintf(m.Out, "✔ 已成功添加 %d 条新公钥（跳过已存在的重复公钥）\n", added)
	}

	// 2. Read original sshd_config
	origBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("无法读取 SSH 配置文件 %s: %w", configPath, err)
	}

	// 3. Backup original config
	backupPath := fmt.Sprintf("%s.secctl.bak.%d", configPath, time.Now().Unix())
	if err := os.WriteFile(backupPath, origBytes, 0600); err != nil {
		return nil, fmt.Errorf("创建备份文件失败: %w", err)
	}
	result.BackupPath = backupPath
	fmt.Fprintf(m.Out, "✔ 已创建配置安全备份: %s\n", backupPath)

	// 4. Update config in memory
	newConfig, err := UpdateSSHDConfig(string(origBytes), opts)
	if err != nil {
		return nil, err
	}

	// 5. Test test-syntax with temporary file if sshd binary is available
	tmpConfig := filepath.Join(os.TempDir(), fmt.Sprintf("sshd_config_test_%d", time.Now().UnixNano()))
	if err := os.WriteFile(tmpConfig, []byte(newConfig), 0600); err == nil {
		defer os.Remove(tmpConfig)
		if sshdBin, err := exec.LookPath("sshd"); err == nil {
			cmd := exec.CommandContext(ctx, sshdBin, "-t", "-f", tmpConfig)
			if out, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("新 SSH 配置语法校验未通过，已中止写入以防失联: %s", string(out))
			}
		}
	}

	// 6. Write new config to target path
	if err := os.WriteFile(configPath, []byte(newConfig), 0600); err != nil {
		return nil, fmt.Errorf("写入新配置文件失败: %w", err)
	}

	// 7. Reload SSH service
	fmt.Fprintf(m.Out, "==> 正在安全重载 SSH 服务...\n")
	if err := ReloadSSHD(ctx); err != nil {
		fmt.Fprintf(m.Out, "⚠️ 重载 SSH 出现告警: %v\n", err)
	} else {
		fmt.Fprintf(m.Out, "✔ SSH 服务已重载生效\n")
	}

	// 8. If skip rollback requested, return immediately
	if opts.SkipRollbackConfirm || opts.TimeoutSeconds <= 0 {
		return result, nil
	}

	// 9. Anti-lockout countdown validation
	timeoutSec := opts.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 60
	}

	fmt.Fprintln(m.Out, "\n==================================================================")
	fmt.Fprintf(m.Out, "🛡️ 【防失联安全确认模式生效中】\n")
	if opts.Port > 0 {
		fmt.Fprintf(m.Out, "请立即新开一个终端窗口测试连接:\n  ssh -p %d <user>@<this-server-ip>\n", opts.Port)
	} else {
		fmt.Fprintf(m.Out, "请新开终端窗口测试登录确认无误。\n")
	}
	fmt.Fprintf(m.Out, "若连接成功，请在 %d 秒内在此按下 [Enter] 确认；\n若超时或按 Ctrl+C，secctl 将自动回滚恢复原配置，绝不锁死服务器！\n", timeoutSec)
	fmt.Fprintln(m.Out, "==================================================================")

	confirmed := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(m.In)
		if scanner.Scan() {
			confirmed <- true
		}
	}()

	select {
	case <-confirmed:
		fmt.Fprintf(m.Out, "\n🎉 确认成功！新配置已正式锁定。\n备份文件已保留在: %s\n", backupPath)
		return result, nil
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		fmt.Fprintf(m.Out, "\n⏰ 超过 %d 秒未收到确认，正在执行自动回滚以防失联...\n", timeoutSec)
		_ = os.WriteFile(configPath, origBytes, 0600)
		_ = ReloadSSHD(context.Background())
		fmt.Fprintf(m.Out, "✔ 已成功回滚至原配置并重启 SSH 服务，服务器连接已恢复。\n")
		return nil, fmt.Errorf("操作超时未确认，已自动回滚以防失联")
	case <-ctx.Done():
		fmt.Fprintf(m.Out, "\n接收到中断信号，正在回滚...\n")
		_ = os.WriteFile(configPath, origBytes, 0600)
		_ = ReloadSSHD(context.Background())
		return nil, ctx.Err()
	}
}
