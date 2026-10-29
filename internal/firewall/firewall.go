package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Rule represents a firewall rule.
type Rule struct {
	Number   int    `json:"number,omitempty"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"` // "tcp", "udp", "any"
	FromIP   string `json:"from_ip,omitempty"`
	Action   string `json:"action"` // "ALLOW", "DENY"
	Comment  string `json:"comment,omitempty"`
	Routed   bool   `json:"routed,omitempty"` // UFW forwarding rules for container traffic.
	scoped   bool   // Interface/destination-specific rules are not replaced by generic decisions.
	ipv6     bool
}

// Firewall manages system firewall rules.
type Firewall interface {
	Name() string
	IsAvailable() bool
	Status(ctx context.Context) ([]Rule, bool, error)
	Allow(ctx context.Context, rule Rule) error
	Deny(ctx context.Context, rule Rule) error
	Enable(ctx context.Context) error
}

// ParsePortProto parses port strings like "80", "443/tcp", "53/udp", "8080-8090/tcp"
func ParsePortProto(arg string) (port string, proto string, err error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", fmt.Errorf("端口不能为空")
	}

	parts := strings.Split(arg, "/")
	if len(parts) == 1 {
		// Just port
		p := parts[0]
		if err := validatePortSpec(p); err != nil {
			return "", "", err
		}
		return p, "tcp", nil // default to tcp
	}

	if len(parts) == 2 {
		p := parts[0]
		pr := strings.ToLower(parts[1])
		if pr != "tcp" && pr != "udp" && pr != "any" {
			return "", "", fmt.Errorf("不支持的协议: %s (仅支持 tcp 或 udp)", pr)
		}
		if err := validatePortSpec(p); err != nil {
			return "", "", err
		}
		return p, pr, nil
	}

	return "", "", fmt.Errorf("非法端口格式: %s", arg)
}

func validatePortSpec(spec string) error {
	if strings.Contains(spec, "-") || strings.Contains(spec, ":") {
		// Port range like 8000-8080 or 8000:8080
		rangeParts := strings.Split(strings.ReplaceAll(spec, "-", ":"), ":")
		if len(rangeParts) != 2 {
			return fmt.Errorf("非法端口段范围: %s", spec)
		}
		p1, err1 := strconv.Atoi(rangeParts[0])
		p2, err2 := strconv.Atoi(rangeParts[1])
		if err1 != nil || err2 != nil || p1 < 1 || p2 > 65535 || p1 > p2 {
			return fmt.Errorf("非法端口段数值: %s", spec)
		}
		return nil
	}

	portNum, err := strconv.Atoi(spec)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("非法端口号: %s (必须在 1-65535 之间)", spec)
	}
	return nil
}

// DetectFirewall auto-detects the active firewall provider.
func DetectFirewall() Firewall {
	ufw := &UFWBackend{}
	if ufw.IsAvailable() {
		return ufw
	}
	ipt := &IptablesBackend{}
	if ipt.IsAvailable() {
		return ipt
	}
	return &UnavailableBackend{}
}

// ValidateRule validates values crossing the system-command boundary.
func ValidateRule(rule Rule) error {
	if _, _, err := ParsePortProto(rule.Port + "/" + rule.Protocol); err != nil {
		return err
	}
	if rule.FromIP != "" {
		if _, err := netip.ParseAddr(rule.FromIP); err != nil {
			if _, err := netip.ParsePrefix(rule.FromIP); err != nil {
				return fmt.Errorf("非法来源 IP/CIDR: %s", rule.FromIP)
			}
		}
	}
	return nil
}

type UnavailableBackend struct{}

func (*UnavailableBackend) Name() string      { return "unavailable" }
func (*UnavailableBackend) IsAvailable() bool { return false }
func (*UnavailableBackend) Status(context.Context) ([]Rule, bool, error) {
	return nil, false, fmt.Errorf("未找到 UFW/iptables，无法管理或确认防火墙")
}
func (*UnavailableBackend) Allow(context.Context, Rule) error {
	return fmt.Errorf("未找到 UFW/iptables，端口未放行")
}
func (*UnavailableBackend) Deny(context.Context, Rule) error {
	return fmt.Errorf("未找到 UFW/iptables，端口未封禁")
}
func (*UnavailableBackend) Enable(context.Context) error { return fmt.Errorf("未找到 UFW/iptables") }

// MockBackend fallback for testing or non-Linux systems
type MockBackend struct {
	Rules []Rule
}

func (m *MockBackend) Name() string      { return "mock" }
func (m *MockBackend) IsAvailable() bool { return true }
func (m *MockBackend) Status(ctx context.Context) ([]Rule, bool, error) {
	return m.Rules, true, nil
}
func (m *MockBackend) Allow(ctx context.Context, rule Rule) error {
	rule.Action = "ALLOW"
	m.Rules = append(m.Rules, rule)
	return nil
}
func (m *MockBackend) Deny(ctx context.Context, rule Rule) error {
	rule.Action = "DENY"
	m.Rules = append(m.Rules, rule)
	return nil
}
func (m *MockBackend) Enable(ctx context.Context) error { return nil }

// CommandRunner executes shell commands
var CommandRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return cmd.CombinedOutput()
}
