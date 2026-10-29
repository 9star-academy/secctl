//go:build darwin

package audit

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type SystemAuditor struct{}

func NewAuditor() *SystemAuditor {
	return &SystemAuditor{}
}

func (a *SystemAuditor) Audit(ctx context.Context) (*AuditReport, error) {
	ports, err := a.scanPorts(ctx)
	if err != nil {
		return nil, err
	}

	report := &AuditReport{
		Ports:               ports,
		FirewallError:       "macOS 防火墙状态未检测；安全加固功能仅支持 Linux",
		FirewallActive:      false,
		FirewallType:        "unknown",
		DockerInstalled:     false,
		DockerShieldEnabled: false,
		SSH: SSHSummary{
			Port:         22,
			PasswordAuth: "unknown",
			PermitRoot:   "unknown",
		},
		Score: 85,
	}

	report.Evaluate()
	return report, nil
}

func (a *SystemAuditor) scanPorts(ctx context.Context) ([]PortItem, error) {
	cmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var items []PortItem
	scanner := bufio.NewScanner(bytes.NewReader(out))

	// Example lsof header: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
	// Example row: sshd 123 root 3u IPv4 0x... 0t0 TCP *:22 (LISTEN)
	// Example row: node 456 user 19u IPv6 0x... 0t0 TCP 127.0.0.1:3000 (LISTEN)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "COMMAND") || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		proc := fields[0]
		pid, _ := strconv.Atoi(fields[1])
		addrPort := fields[8]

		// Format: 127.0.0.1:3000 or *:22 or [::1]:8080 or *:80
		lastColon := strings.LastIndex(addrPort, ":")
		if lastColon == -1 {
			continue
		}

		addr := addrPort[:lastColon]
		portStr := addrPort[lastColon+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		isPublic := isPublicAddr(addr)
		risk, desc := AssessRisk(port, isPublic, proc)

		items = append(items, PortItem{
			Protocol:    "tcp",
			Address:     addr,
			Port:        port,
			PID:         pid,
			Process:     proc,
			IsPublic:    isPublic,
			Risk:        risk,
			Description: desc,
		})
	}

	return items, nil
}

func isPublicAddr(addr string) bool {
	addr = strings.Trim(addr, "[]")
	if i := strings.Index(addr, "%"); i >= 0 {
		addr = addr[:i]
	}
	ip := net.ParseIP(addr)
	return addr != "localhost" && (ip == nil || !ip.IsLoopback())
}

func (r *AuditReport) Evaluate() {
	var suggestions []string
	score := 100

	hasExposedDB := false
	hasDefaultSSH := false

	for _, p := range r.Ports {
		if p.Risk == RiskDanger {
			hasExposedDB = true
			score -= 30
			suggestions = append(suggestions, "【高危】高风险服务 "+p.Process+"（端口 "+strconv.Itoa(p.Port)+"）在非回环地址监听，请核对防火墙和外部可达性")
		} else if p.Risk == RiskWarn && p.Port == 22 {
			hasDefaultSSH = true
			score -= 10
			suggestions = append(suggestions, "【建议】SSH 仍在使用默认 22 端口，建议使用 `secctl ssh harden` 修改为非标端口")
		}
	}

	if r.FirewallError != "" {
		suggestions = append(suggestions, "防火墙状态无法确认："+r.FirewallError)
	} else if !r.FirewallActive {
		score -= 25
		suggestions = append(suggestions, "【警告】服务器系统防火墙未启用！建议启用 UFW 或 iptables 防火墙")
	}

	if r.DockerInstalled && r.DockerShieldError != "" {
		suggestions = append(suggestions, "Docker 防护状态无法确认："+r.DockerShieldError)
	} else if r.DockerInstalled && !r.DockerShieldEnabled {
		score -= 20
		suggestions = append(suggestions, "【警告】检测到 Docker 运行中但未开启 Docker Shield，容器端口可能会绕过防火墙暴露！运行 `secctl docker-shield enable` 修复")
	}

	if score < 0 {
		score = 0
	}
	r.Score = score
	r.Suggestions = suggestions
	_ = hasExposedDB
	_ = hasDefaultSSH
}
