package firewall

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// IptablesBackend manages firewall rules via direct iptables.
type IptablesBackend struct{}

func (i *IptablesBackend) Name() string { return "iptables" }

func (i *IptablesBackend) IsAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func (i *IptablesBackend) Enable(ctx context.Context) error {
	return fmt.Errorf("请显式配置 iptables 默认策略；secctl 不会自动更改全局策略")
}

func (i *IptablesBackend) Allow(ctx context.Context, rule Rule) error {
	return i.apply(ctx, rule, "ACCEPT")
}

func (i *IptablesBackend) Deny(ctx context.Context, rule Rule) error {
	return i.apply(ctx, rule, "DROP")
}

func (i *IptablesBackend) apply(ctx context.Context, rule Rule, action string) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}
	if rule.Routed {
		return fmt.Errorf("--docker 转发规则仅支持 UFW 后端")
	}
	if strings.Contains(rule.FromIP, ":") {
		return fmt.Errorf("iptables 后端仅管理 IPv4；IPv6 请使用 UFW")
	}
	protocols := []string{rule.Protocol}
	if rule.Protocol == "any" {
		protocols = []string{"tcp", "udp"}
	}
	for _, proto := range protocols {
		args := []string{"-I", "INPUT", "-p", proto, "--dport", strings.ReplaceAll(rule.Port, "-", ":")}
		if rule.FromIP != "" {
			args = append(args, "-s", rule.FromIP)
		}
		args = append(args, "-j", action)
		if rule.Comment != "" {
			args = append(args, "-m", "comment", "--comment", rule.Comment)
		}
		if out, err := CommandRunner(ctx, "iptables", args...); err != nil {
			return fmt.Errorf("执行 iptables %s 失败（可能已部分应用）: %s (%w)", action, out, err)
		}
	}
	return nil
}

func (i *IptablesBackend) Status(ctx context.Context) ([]Rule, bool, error) {
	out, err := CommandRunner(ctx, "iptables", "-S", "INPUT")
	if err != nil {
		return nil, false, err
	}

	var rules []Rule
	active := false
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] == "-P" {
			active = fields[2] == "DROP"
			continue
		}
		if fields[0] != "-A" {
			continue
		}
		rule := Rule{Number: len(rules) + 1, Port: "all", Protocol: "any", FromIP: "Anywhere"}
		for j := 2; j+1 < len(fields); j++ {
			switch fields[j] {
			case "-p":
				rule.Protocol = fields[j+1]
			case "-s":
				rule.FromIP = fields[j+1]
			case "--dport":
				rule.Port = fields[j+1]
			case "-j":
				rule.Action = fields[j+1]
			}
		}
		if rule.Action == "DROP" || rule.Action == "REJECT" {
			active = true
		}
		rules = append(rules, rule)
	}
	return rules, active, scanner.Err()
}
