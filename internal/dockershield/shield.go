package dockershield

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	UFWRulesTagBegin = "# secctl docker-shield begin"
	UFWRulesTagEnd   = "# secctl docker-shield end"
	UFWAfterRules    = "/etc/ufw/after.rules"
)

// ShieldManager manages Docker firewall isolation.
type ShieldManager struct {
	AfterRulesPath string
}

func NewShieldManager() *ShieldManager {
	return &ShieldManager{AfterRulesPath: UFWAfterRules}
}

// IsEnabled checks if docker-shield is active.
func (s *ShieldManager) IsEnabled(ctx context.Context) (bool, error) {
	// Check UFW after.rules
	if data, err := os.ReadFile(s.AfterRulesPath); err == nil {
		if strings.Contains(string(data), UFWRulesTagBegin) {
			return true, nil
		}
	}

	// Check iptables DOCKER-USER chain
	if _, err := exec.LookPath("iptables"); err == nil {
		cmd := exec.CommandContext(ctx, "iptables", "-L", "DOCKER-USER", "-n")
		out, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(out), "secctl") {
			return true, nil
		}
	}

	return false, nil
}

// Enable injects docker isolation rules.
func (s *ShieldManager) Enable(ctx context.Context) error {
	// 1. Try UFW configuration if UFW rules file exists
	if _, err := os.Stat(s.AfterRulesPath); err == nil {
		return s.enableUFW(ctx)
	}

	// 2. Fallback to direct iptables DOCKER-USER rule
	return s.enableIptables(ctx)
}

func (s *ShieldManager) enableUFW(ctx context.Context) error {
	content, err := os.ReadFile(s.AfterRulesPath)
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", s.AfterRulesPath, err)
	}

	strContent := string(content)
	if strings.Contains(strContent, UFWRulesTagBegin) {
		return nil // Already enabled
	}

	rulesBlock := fmt.Sprintf(`
%s
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-USER -i docker0 -j ACCEPT
-A DOCKER-USER -i br-+ -j ACCEPT
-A DOCKER-USER -j RETURN
COMMIT
%s
`, UFWRulesTagBegin, UFWRulesTagEnd)

	newContent := strContent + rulesBlock
	if err := os.WriteFile(s.AfterRulesPath, []byte(newContent), 0640); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", s.AfterRulesPath, err)
	}

	// Reload UFW
	if _, err := exec.LookPath("ufw"); err == nil {
		cmd := exec.CommandContext(ctx, "ufw", "reload")
		_ = cmd.Run()
	}

	return nil
}

func (s *ShieldManager) enableIptables(ctx context.Context) error {
	// Check if DOCKER-USER exists
	cmd := exec.CommandContext(ctx, "iptables", "-N", "DOCKER-USER")
	_ = cmd.Run() // Ignore error if chain already exists

	cmds := [][]string{
		{"iptables", "-I", "DOCKER-USER", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT", "-m", "comment", "--comment", "secctl-shield"},
		{"iptables", "-A", "DOCKER-USER", "-i", "docker0", "-j", "ACCEPT", "-m", "comment", "--comment", "secctl-shield"},
		{"iptables", "-A", "DOCKER-USER", "-j", "RETURN", "-m", "comment", "--comment", "secctl-shield"},
	}

	for _, c := range cmds {
		cmd := exec.CommandContext(ctx, c[0], c[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("执行 %s 失败: %s (%w)", strings.Join(c, " "), string(out), err)
		}
	}

	return nil
}

// Disable removes docker isolation rules.
func (s *ShieldManager) Disable(ctx context.Context) error {
	if content, err := os.ReadFile(s.AfterRulesPath); err == nil {
		strContent := string(content)
		startIdx := strings.Index(strContent, UFWRulesTagBegin)
		endIdx := strings.Index(strContent, UFWRulesTagEnd)

		if startIdx != -1 && endIdx != -1 {
			newContent := strContent[:startIdx] + strContent[endIdx+len(UFWRulesTagEnd):]
			_ = os.WriteFile(s.AfterRulesPath, []byte(strings.TrimSpace(newContent)+"\n"), 0640)
			if _, err := exec.LookPath("ufw"); err == nil {
				_ = exec.CommandContext(ctx, "ufw", "reload").Run()
			}
		}
	}

	return nil
}
