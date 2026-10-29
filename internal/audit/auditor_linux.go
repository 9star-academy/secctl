//go:build linux

package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/9star-academy/secctl/internal/dockershield"
	"github.com/9star-academy/secctl/internal/firewall"
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
	fw := firewall.DetectFirewall()
	_, fwActive, fwErr := fw.Status(ctx)
	fwType := fw.Name()
	sshSummary := a.inspectSSH(ctx)
	_, dockerErr := exec.LookPath("docker")
	dockerInstalled := dockerErr == nil
	shieldEnabled, shieldErr := false, error(nil)
	if dockerInstalled {
		shieldEnabled, shieldErr = dockershield.NewShieldManager().IsEnabled(ctx)
	}

	report := &AuditReport{
		Ports:               ports,
		FirewallActive:      fwActive,
		FirewallType:        fwType,
		SSH:                 sshSummary,
		DockerInstalled:     dockerInstalled,
		DockerShieldEnabled: shieldEnabled,
		Score:               100,
	}

	if fwErr != nil {
		report.FirewallError = fwErr.Error()
	}
	if shieldErr != nil {
		report.DockerShieldError = shieldErr.Error()
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
	items = append(items, parseProcNet("/proc/net/udp", "udp")...)
	items = append(items, parseProcNet("/proc/net/udp6", "udp6")...)
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

	if len(ipBytes) == 16 {
		for start := 0; start < 16; start += 4 {
			ipBytes[start], ipBytes[start+3] = ipBytes[start+3], ipBytes[start]
			ipBytes[start+1], ipBytes[start+2] = ipBytes[start+2], ipBytes[start+1]
		}
		return net.IP(ipBytes).String(), port, nil
	}
	return "", 0, fmt.Errorf("invalid IP length")
}

func isPublicAddr(addr string) bool {
	addr = strings.Trim(addr, "[]")
	if i := strings.Index(addr, "%"); i >= 0 {
		addr = addr[:i]
	}
	ip := net.ParseIP(addr)
	return addr != "localhost" && (ip == nil || !ip.IsLoopback())
}

func (a *SystemAuditor) inspectSSH(ctx context.Context) SSHSummary {
	summary := SSHSummary{PasswordAuth: "unknown", PermitRoot: "unknown"}
	out, err := exec.CommandContext(ctx, "sshd", "-T").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			switch parts[0] {
			case "port":
				summary.Port, _ = strconv.Atoi(parts[1])
			case "passwordauthentication":
				summary.PasswordAuth = parts[1]
			case "permitrootlogin":
				summary.PermitRoot = parts[1]
			}
		}
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

func (r *AuditReport) Evaluate() {
	var suggestions []string
	score := 100

	for _, p := range r.Ports {
		if p.Risk == RiskDanger {
			score -= 30
			suggestions = append(suggestions, fmt.Sprintf("【高危】高风险服务 %s（端口 %d）在非回环地址监听；请核对系统防火墙、云安全组与外部可达性", p.Process, p.Port))
		} else if p.Risk == RiskWarn && p.Port == 22 {
			score -= 10
			suggestions = append(suggestions, "【建议】SSH 仍在使用默认 22 端口，常年承受全球全网扫描，建议使用 `secctl ssh harden` 换用非标端口")
		}
	}

	if r.SSH.PasswordAuth == "yes" {
		score -= 15
		suggestions = append(suggestions, "【警告】SSH 仍开启密码登录，建议配置 SSH 密钥后使用 `secctl ssh harden --disable-password` 禁用密码登录")
	}

	if r.FirewallError != "" {
		suggestions = append(suggestions, "防火墙状态无法确认："+r.FirewallError)
	} else if !r.FirewallActive {
		score -= 25
		suggestions = append(suggestions, "【警告】服务器系统防火墙未启用！当前防护状态需要核对，请检查系统防火墙及云安全组")
	}

	if r.DockerInstalled && r.DockerShieldError != "" {
		suggestions = append(suggestions, "Docker 防护状态无法确认："+r.DockerShieldError)
	} else if r.DockerInstalled && !r.DockerShieldEnabled {
		score -= 20
		suggestions = append(suggestions, "【警告】检测到 Docker 正在运行，但未开启 Docker Shield 防穿透！容器端口可能会直接绕过 UFW 暴露公网")
	}

	if score < 0 {
		score = 0
	}
	r.Score = score
	r.Suggestions = suggestions
}
