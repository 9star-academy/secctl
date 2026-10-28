//go:build linux

package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type SystemAuditor struct{}

func NewAuditor() *SystemAuditor {
	return &SystemAuditor{}
}

func (a *SystemAuditor) Audit(ctx context.Context) (*AuditReport, error) {
	ports := a.scanPorts(ctx)
	fwActive, fwType := a.detectFirewall(ctx)
	sshSummary := a.inspectSSH()
	dockerInstalled, shieldEnabled := a.detectDocker(ctx)

	report := &AuditReport{
		Ports:               ports,
		FirewallActive:      fwActive,
		FirewallType:        fwType,
		SSH:                 sshSummary,
		DockerInstalled:     dockerInstalled,
		DockerShieldEnabled: shieldEnabled,
		Score:               100,
	}

	report.Evaluate()
	return report, nil
}

func (a *SystemAuditor) scanPorts(ctx context.Context) []PortItem {
	// Try `ss -tulpn` first (fastest and includes PID/process)
	if items, err := a.scanPortsSS(ctx); err == nil && len(items) > 0 {
		return items
	}
	// Fallback to /proc/net/tcp & /proc/net/tcp6
	return a.scanPortsProc()
}

func (a *SystemAuditor) scanPortsSS(ctx context.Context) ([]PortItem, error) {
	cmd := exec.CommandContext(ctx, "ss", "-tulpn")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var items []PortItem
	scanner := bufio.NewScanner(bytes.NewReader(out))

	// Example ss header: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
	// Example row: tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=638,fd=3))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Netid") || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}

		// State must be LISTEN for TCP
		if strings.HasPrefix(proto, "tcp") && len(fields) > 1 && fields[1] != "LISTEN" {
			continue
		}

		addrPort := fields[4]
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

		proc, pid := parseSSProcess(line)
		isPublic := isPublicAddr(addr)
		risk, desc := AssessRisk(port, isPublic, proc)

		items = append(items, PortItem{
			Protocol:    proto,
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

func parseSSProcess(line string) (string, int) {
	// users:(("sshd",pid=638,fd=3))
	idx := strings.Index(line, `users:(("`)
	if idx == -1 {
		idx = strings.Index(line, `users:((`)
	}
	if idx == -1 {
		return "unknown", 0
	}

	sub := line[idx:]
	name := "unknown"
	pid := 0

	// Extract name
	if start := strings.Index(sub, `"`); start != -1 {
		if end := strings.Index(sub[start+1:], `"`); end != -1 {
			name = sub[start+1 : start+1+end]
		}
	}

	// Extract pid
	if pidIdx := strings.Index(sub, "pid="); pidIdx != -1 {
		pidStr := sub[pidIdx+4:]
		for i, ch := range pidStr {
			if ch < '0' || ch > '9' {
				pidStr = pidStr[:i]
				break
			}
		}
		pid, _ = strconv.Atoi(pidStr)
	}

	return name, pid
}

func (a *SystemAuditor) scanPortsProc() []PortItem {
	var items []PortItem
	tcpItems := parseProcNet("/proc/net/tcp", "tcp")
	tcp6Items := parseProcNet("/proc/net/tcp6", "tcp6")
	items = append(items, tcpItems...)
	items = append(items, tcp6Items...)
	return items
}

func parseProcNet(filePath, proto string) []PortItem {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var items []PortItem
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "sl") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// 0A is LISTEN state in TCP
		if proto == "tcp" || proto == "tcp6" {
			if fields[3] != "0A" {
				continue
			}
		}

		ip, port, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}

		isPublic := isPublicAddr(ip)
		risk, desc := AssessRisk(port, isPublic, "service")

		items = append(items, PortItem{
			Protocol:    proto,
			Address:     ip,
			Port:        port,
			IsPublic:    isPublic,
			Risk:        risk,
			Description: desc,
		})
	}
	return items
}

func parseHexAddr(hexAddr string) (string, int, error) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format")
	}

	portBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(portBytes) < 2 {
		return "", 0, fmt.Errorf("invalid port")
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, fmt.Errorf("invalid ip")
	}

	// IPv4 in proc is little-endian
	if len(ipBytes) == 4 {
		ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()
		return ip, port, nil
	}

	return parts[0], port, nil
}

func isPublicAddr(addr string) bool {
	if addr == "*" || addr == "0.0.0.0" || addr == "::" || addr == "" {
		return true
	}
	if addr == "127.0.0.1" || addr == "localhost" || addr == "::1" || strings.HasPrefix(addr, "127.") {
		return false
	}
	return true
}

func (a *SystemAuditor) detectFirewall(ctx context.Context) (bool, string) {
	// 1. Check UFW
	if _, err := exec.LookPath("ufw"); err == nil {
		cmd := exec.CommandContext(ctx, "ufw", "status")
		out, err := cmd.Output()
		if err == nil && strings.Contains(string(out), "Status: active") {
			return true, "ufw"
		}
		if err == nil {
			return false, "ufw (inactive)"
		}
	}

	// 2. Check iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		cmd := exec.CommandContext(ctx, "iptables", "-L", "-n")
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			// Check if there are non-default rules
			if strings.Contains(string(out), "REJECT") || strings.Contains(string(out), "DROP") {
				return true, "iptables"
			}
		}
	}

	return false, "none"
}

func (a *SystemAuditor) inspectSSH() SSHSummary {
	summary := SSHSummary{
		Port:         22,
		PasswordAuth: "yes", // default in openssh
		PermitRoot:   "prohibit-password",
	}

	configPaths := []string{"/etc/ssh/sshd_config", "/etc/sshd_config"}
	for _, p := range configPaths {
		file, err := os.Open(p)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			key := strings.ToLower(parts[0])
			val := strings.ToLower(parts[1])

			switch key {
			case "port":
				if pt, err := strconv.Atoi(val); err == nil {
					summary.Port = pt
				}
			case "passwordauthentication":
				summary.PasswordAuth = val
			case "permitrootlogin":
				summary.PermitRoot = val
			}
		}
		break
	}

	// Count authorized_keys
	home := os.Getenv("HOME")
	if home != "" {
		akPath := filepath.Join(home, ".ssh", "authorized_keys")
		if data, err := os.ReadFile(akPath); err == nil {
			lines := strings.Split(string(data), "\n")
			count := 0
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" && !strings.HasPrefix(l, "#") {
					count++
				}
			}
			summary.AuthorizedKeys = count
		}
	}

	return summary
}

func (a *SystemAuditor) detectDocker(ctx context.Context) (bool, bool) {
	if _, err := exec.LookPath("docker"); err != nil {
		return false, false
	}

	// Check if docker shield rule exists in after.rules or iptables
	data, err := os.ReadFile("/etc/ufw/after.rules")
	if err == nil && strings.Contains(string(data), "DOCKER-USER") {
		return true, true
	}

	cmd := exec.CommandContext(ctx, "iptables", "-L", "DOCKER-USER", "-n")
	out, err := cmd.Output()
	if err == nil && strings.Contains(string(out), "secctl") {
		return true, true
	}

	return true, false
}

func (r *AuditReport) Evaluate() {
	var suggestions []string
	score := 100

	for _, p := range r.Ports {
		if p.Risk == RiskDanger {
			score -= 30
			suggestions = append(suggestions, fmt.Sprintf("【高危】高风险服务 %s（端口 %d）直接暴露于公网！极易遭到字典爆破与勒索，建议关闭公网暴露", p.Process, p.Port))
		} else if p.Risk == RiskWarn && p.Port == 22 {
			score -= 10
			suggestions = append(suggestions, "【建议】SSH 仍在使用默认 22 端口，常年承受全球全网扫描，建议使用 `secctl ssh harden` 换用非标端口")
		}
	}

	if r.SSH.PasswordAuth == "yes" {
		score -= 15
		suggestions = append(suggestions, "【警告】SSH 仍开启密码登录，建议配置 SSH 密钥后使用 `secctl ssh harden --disable-password` 禁用密码登录")
	}

	if !r.FirewallActive {
		score -= 25
		suggestions = append(suggestions, "【警告】服务器系统防火墙未启用！所有暴露端口完全裸奔，建议立即配置防火墙")
	}

	if r.DockerInstalled && !r.DockerShieldEnabled {
		score -= 20
		suggestions = append(suggestions, "【警告】检测到 Docker 正在运行，但未开启 Docker Shield 防穿透！容器端口可能会直接绕过 UFW 暴露公网")
	}

	if score < 0 {
		score = 0
	}
	r.Score = score
	r.Suggestions = suggestions
}
