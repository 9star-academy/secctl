package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/9star-academy/secctl/internal/audit"
	"github.com/9star-academy/secctl/internal/dockershield"
	"github.com/9star-academy/secctl/internal/firewall"
	"github.com/9star-academy/secctl/internal/ssh"
)

const helpText = `secctl — 一行命令搞定 Linux 裸机安全加固与防火墙管理

用法:
  secctl audit                          公网暴露面与安全状态全面审计
  secctl ssh harden [选项]              SSH 一键加固（带 60s 防失联自动回滚）
  secctl allow <端口[/协议]> [选项]     开放端口 (如 80, 443/tcp, 5432/tcp --from 10.0.0.0/8)
  secctl deny <端口[/协议]>             关闭/拒绝端口
  secctl status                         查看当前防火墙激活状态与放行规则
  secctl docker-shield <enable|disable|status>  修复 Docker 绕过防火墙暴露公网端口漏洞
  secctl --version                      查看版本信息

示例:
  sudo secctl audit
  sudo secctl ssh harden --github reedtang666 --port 22022 --disable-password
  sudo secctl allow 80,443/tcp
  sudo secctl allow 5432/tcp --from 192.168.1.0/24 --comment "内网PG库"
  sudo secctl deny 8080/tcp
  sudo secctl docker-shield enable

设计哲学:
  1. 防失联第一: SSH 修改带倒计时验证与自动回滚机制。
  2. 零外部依赖: 单二进制分发，无额外运行时负担。
  3. 彻底修补 Docker 穿透漏洞: 拒绝容器端口在不知情下对全网裸奔。
`

type App struct {
	Version string
	Out     io.Writer
	Err     io.Writer
	In      io.Reader
	Auditor audit.Auditor
	FW      firewall.Firewall
	Shield  *dockershield.ShieldManager
	SSH     *ssh.Manager
}

func New(version string, out, errOut io.Writer, in io.Reader) *App {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	if in == nil {
		in = os.Stdin
	}
	return &App{
		Version: version,
		Out:     out,
		Err:     errOut,
		In:      in,
		Auditor: audit.NewAuditor(),
		FW:      firewall.DetectFirewall(),
		Shield:  dockershield.NewShieldManager(),
		SSH:     ssh.NewManager(out, in),
	}
}

func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Out, helpText)
		return 0
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "audit":
		return a.runAudit(ctx)
	case "ssh":
		return a.runSSH(ctx, subArgs)
	case "allow":
		return a.runAllow(ctx, subArgs)
	case "deny":
		return a.runDeny(ctx, subArgs)
	case "status":
		return a.runStatus(ctx)
	case "docker-shield":
		return a.runDockerShield(ctx, subArgs)
	case "-v", "--version", "version":
		fmt.Fprintf(a.Out, "secctl version %s\n", a.Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(a.Out, helpText)
		return 0
	default:
		fmt.Fprintf(a.Err, "未知命令: %s\n运行 'secctl --help' 查看使用帮助\n", cmd)
		return 1
	}
}

func (a *App) runAudit(ctx context.Context) int {
	fmt.Fprintf(a.Out, "🔍 正在扫描系统端口暴露面与安全状态...\n\n")

	report, err := a.Auditor.Audit(ctx)
	if err != nil {
		fmt.Fprintf(a.Err, "审计失败: %v\n", err)
		return 1
	}

	fmt.Fprintln(a.Out, "================================================================================")
	fmt.Fprintf(a.Out, "🛡️  服务器安全审计报告 (健康评分: %d/100)\n", report.Score)
	fmt.Fprintln(a.Out, "================================================================================")

	fmt.Fprintf(a.Out, "%-8s %-18s %-8s %-16s %-8s %s\n", "协议", "监听地址", "端口", "服务/进程", "风险", "说明")
	fmt.Fprintln(a.Out, "--------------------------------------------------------------------------------")

	for _, p := range report.Ports {
		riskStr := string(p.Risk)
		fmt.Fprintf(a.Out, "%-8s %-18s %-8d %-16s %-8s %s\n",
			strings.ToUpper(p.Protocol),
			p.Address,
			p.Port,
			p.Process,
			riskStr,
			p.Description,
		)
	}

	fmt.Fprintln(a.Out, "--------------------------------------------------------------------------------")
	fwStatus := "已启用 (" + report.FirewallType + ")"
	if !report.FirewallActive {
		fwStatus = "❌ 未激活/未安装"
	}
	fmt.Fprintf(a.Out, "防火墙状态: %s\n", fwStatus)

	if report.DockerInstalled {
		shieldStatus := "✔ 已受保护"
		if !report.DockerShieldEnabled {
			shieldStatus = "⚠️ 未开启防穿透 (端口可能裸奔)"
		}
		fmt.Fprintf(a.Out, "Docker 穿透防御: %s\n", shieldStatus)
	}

	if len(report.Suggestions) > 0 {
		fmt.Fprintln(a.Out, "\n💡 优化与安全建议:")
		for i, s := range report.Suggestions {
			fmt.Fprintf(a.Out, "  %d. %s\n", i+1, s)
		}
	}
	fmt.Fprintln(a.Out, "================================================================================")

	return 0
}

func (a *App) runSSH(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Err, "用法: secctl ssh harden [选项]")
		return 1
	}

	sub := args[0]
	if sub != "harden" {
		fmt.Fprintf(a.Err, "未知子命令: %s (可用: harden)\n", sub)
		return 1
	}

	fs := flag.NewFlagSet("ssh harden", flag.ContinueOnError)
	fs.SetOutput(a.Err)

	githubUser := fs.String("github", "", "从 GitHub 账号自动拉取 SSH 公钥")
	port := fs.Int("port", 0, "修改 SSH 端口 (如 22022)")
	disablePassword := fs.Bool("disable-password", false, "禁用密码登录 (强制密钥认证)")
	disableRoot := fs.Bool("disable-root", false, "完全禁止 root 登录")
	permitRootKeysOnly := fs.Bool("permit-root-keys-only", true, "仅允许 root 通过密钥登录")
	timeoutSec := fs.Int("timeout", 60, "防失联自动回滚超时时间 (秒)")
	skipConfirm := fs.Bool("skip-confirm", false, "跳过防失联交互确认")
	targetUser := fs.String("user", "", "目标系统用户名 (默认当前用户)")

	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}

	opts := ssh.HardenOptions{
		GitHubUser:          *githubUser,
		Port:                *port,
		DisablePassword:     *disablePassword,
		DisableRootLogin:    *disableRoot,
		PermitRootKeysOnly:  *permitRootKeysOnly,
		TimeoutSeconds:      *timeoutSec,
		SkipRollbackConfirm: *skipConfirm,
		TargetUser:          *targetUser,
	}

	// If changing port, automatically ensure the new port is allowed in firewall!
	if *port > 0 {
		fmt.Fprintf(a.Out, "==> 自动在防火墙中放行新 SSH 端口 %d/tcp 以防失联...\n", *port)
		_ = a.FW.Allow(ctx, firewall.Rule{Port: strconv.Itoa(*port), Protocol: "tcp", Comment: "SSH-New-Port"})
	}

	_, err := a.SSH.Harden(ctx, opts)
	if err != nil {
		fmt.Fprintf(a.Err, "❌ SSH 加固失败: %v\n", err)
		return 1
	}

	return 0
}

func (a *App) runAllow(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Err, "用法: secctl allow <端口[/协议]> [--from <IP>] [--comment <备注>]")
		return 1
	}

	portSpec := args[0]
	fromIP := ""
	comment := ""

	for i := 1; i < len(args); i++ {
		if args[i] == "--from" && i+1 < len(args) {
			fromIP = args[i+1]
			i++
		} else if args[i] == "--comment" && i+1 < len(args) {
			comment = args[i+1]
			i++
		}
	}

	// Support comma-separated ports like "80,443/tcp"
	specs := strings.Split(portSpec, ",")
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		port, proto, err := firewall.ParsePortProto(spec)
		if err != nil {
			fmt.Fprintf(a.Err, "❌ 参数错误: %v\n", err)
			return 1
		}

		err = a.FW.Allow(ctx, firewall.Rule{
			Port:     port,
			Protocol: proto,
			FromIP:   fromIP,
			Comment:  comment,
		})
		if err != nil {
			fmt.Fprintf(a.Err, "❌ 放行端口 %s 失败: %v\n", spec, err)
			return 1
		}
		fmt.Fprintf(a.Out, "✔ 已成功放行端口: %s/%s", port, proto)
		if fromIP != "" {
			fmt.Fprintf(a.Out, " (仅限来源: %s)", fromIP)
		}
		fmt.Fprintln(a.Out)
	}

	return 0
}

func (a *App) runDeny(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Err, "用法: secctl deny <端口[/协议]>")
		return 1
	}

	specs := strings.Split(args[0], ",")
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		port, proto, err := firewall.ParsePortProto(spec)
		if err != nil {
			fmt.Fprintf(a.Err, "❌ 参数错误: %v\n", err)
			return 1
		}

		err = a.FW.Deny(ctx, firewall.Rule{
			Port:     port,
			Protocol: proto,
		})
		if err != nil {
			fmt.Fprintf(a.Err, "❌ 拒绝/关闭端口 %s 失败: %v\n", spec, err)
			return 1
		}
		fmt.Fprintf(a.Out, "✔ 已成功关闭端口: %s/%s\n", port, proto)
	}

	return 0
}

func (a *App) runStatus(ctx context.Context) int {
	rules, active, err := a.FW.Status(ctx)
	if err != nil {
		fmt.Fprintf(a.Err, "获取防火墙状态失败: %v\n", err)
		return 1
	}

	statusStr := "活跃 (Active)"
	if !active {
		statusStr = "未激活 (Inactive)"
	}

	fmt.Fprintf(a.Out, "防火墙后端: %s | 状态: %s\n\n", a.FW.Name(), statusStr)
	if len(rules) == 0 {
		fmt.Fprintln(a.Out, "当前暂无自定义放行规则。")
		return 0
	}

	fmt.Fprintf(a.Out, "%-6s %-12s %-8s %-10s %-20s %s\n", "#", "端口", "协议", "动作", "允许来源", "备注")
	fmt.Fprintln(a.Out, "--------------------------------------------------------------------------------")
	for i, r := range rules {
		num := r.Number
		if num == 0 {
			num = i + 1
		}
		fmt.Fprintf(a.Out, "%-6d %-12s %-8s %-10s %-20s %s\n",
			num,
			r.Port,
			strings.ToUpper(r.Protocol),
			r.Action,
			r.FromIP,
			r.Comment,
		)
	}

	return 0
}

func (a *App) runDockerShield(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Err, "用法: secctl docker-shield <enable|disable|status>")
		return 1
	}

	action := args[0]
	switch action {
	case "enable":
		fmt.Fprintln(a.Out, "==> 正在配置 Docker 防穿透规则 (接入 DOCKER-USER 链)...")
		if err := a.Shield.Enable(ctx); err != nil {
			fmt.Fprintf(a.Err, "❌ 配置失败: %v\n", err)
			return 1
		}
		fmt.Fprintln(a.Out, "✔ Docker Shield 已成功启用！容器映射端口将严格受控于防火墙规则。")
		return 0
	case "disable":
		fmt.Fprintln(a.Out, "==> 正在移除 Docker 防穿透规则...")
		if err := a.Shield.Disable(ctx); err != nil {
			fmt.Fprintf(a.Err, "❌ 移除失败: %v\n", err)
			return 1
		}
		fmt.Fprintln(a.Out, "✔ Docker Shield 已禁用，恢复默认模式。")
		return 0
	case "status":
		enabled, err := a.Shield.IsEnabled(ctx)
		if err != nil {
			fmt.Fprintf(a.Err, "检查状态失败: %v\n", err)
			return 1
		}
		if enabled {
			fmt.Fprintln(a.Out, "Docker Shield: ✔ 已启用 (已受防火墙保护)")
		} else {
			fmt.Fprintln(a.Out, "Docker Shield: ⚠️ 未启用 (容器端口可能绕过防火墙暴露公网)")
		}
		return 0
	default:
		fmt.Fprintf(a.Err, "未知操作: %s (可用: enable, disable, status)\n", action)
		return 1
	}
}
