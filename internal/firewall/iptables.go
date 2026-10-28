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
	// Usually iptables is already kernel level, ensure default policy
	return nil
}

func (i *IptablesBackend) Allow(ctx context.Context, rule Rule) error {
	args := []string{"-I", "INPUT", "-p", rule.Protocol, "--dport", rule.Port}
	if rule.FromIP != "" && rule.FromIP != "Anywhere" {
		args = append(args, "-s", rule.FromIP)
	}
	args = append(args, "-j", "ACCEPT")

	out, err := CommandRunner(ctx, "iptables", args...)
	if err != nil {
		return fmt.Errorf("执行 iptables allow 失败: %s (%w)", string(out), err)
	}
	return nil
}

func (i *IptablesBackend) Deny(ctx context.Context, rule Rule) error {
	args := []string{"-D", "INPUT", "-p", rule.Protocol, "--dport", rule.Port, "-j", "ACCEPT"}
	out, err := CommandRunner(ctx, "iptables", args...)
	if err != nil {
		return fmt.Errorf("执行 iptables 删除规则失败: %s (%w)", string(out), err)
	}
	return nil
}

func (i *IptablesBackend) Status(ctx context.Context) ([]Rule, bool, error) {
	out, err := CommandRunner(ctx, "iptables", "-L", "INPUT", "-n", "--line-numbers")
	if err != nil {
		return nil, false, err
	}

	var rules []Rule
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "num") || strings.HasPrefix(line, "Chain") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			rules = append(rules, Rule{
				Port:     "rule",
				Action:   fields[1],
				Protocol: fields[2],
				FromIP:   fields[4],
			})
		}
	}
	return rules, true, nil
}
