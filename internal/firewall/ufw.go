package firewall

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// UFWBackend interacts with Ubuntu/Debian UFW.
type UFWBackend struct{}

func (u *UFWBackend) Name() string { return "ufw" }

func (u *UFWBackend) IsAvailable() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

func (u *UFWBackend) Enable(ctx context.Context) error {
	out, err := CommandRunner(ctx, "ufw", "--force", "enable")
	if err != nil {
		return fmt.Errorf("启用 UFW 失败: %s (%w)", string(out), err)
	}
	return nil
}

func (u *UFWBackend) Allow(ctx context.Context, rule Rule) error {
	return u.apply(ctx, rule, "allow")
}

func (u *UFWBackend) Deny(ctx context.Context, rule Rule) error {
	return u.apply(ctx, rule, "deny")
}

func (u *UFWBackend) apply(ctx context.Context, rule Rule, action string) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}
	existing, active, err := u.Status(ctx)
	if err != nil {
		return fmt.Errorf("检查 UFW 状态失败: %w", err)
	}
	if !active {
		return fmt.Errorf("UFW 未激活；请先保留当前 SSH 放行规则并手动启用 UFW")
	}
	// UFW skips duplicate insertions, including matching rules with another action.
	// Delete by exact rule specification, never by a stale numbered-list position.
	actions := map[string]bool{}
	for _, old := range existing {
		if old.scoped || old.Routed != rule.Routed || old.Protocol != rule.Protocol || strings.ReplaceAll(old.Port, "-", ":") != strings.ReplaceAll(rule.Port, "-", ":") || sourceKey(old.FromIP) != sourceKey(rule.FromIP) {
			continue
		}
		if rule.FromIP != "" && old.ipv6 != strings.Contains(rule.FromIP, ":") {
			continue
		}
		action := strings.ToLower(old.Action)
		if actions[action] {
			continue
		}
		actions[action] = true
		args := ufwRuleArgs(rule, action, false)
		if out, err := CommandRunner(ctx, "ufw", args...); err != nil {
			return fmt.Errorf("替换旧 UFW 决策失败（可能已部分更新）: %s (%w)", out, err)
		}
	}
	args := ufwRuleArgs(rule, action, true)
	out, err := CommandRunner(ctx, "ufw", args...)
	if err != nil {
		return fmt.Errorf("执行 UFW %s 失败（旧同类规则可能已移除，请检查状态）: %s (%w)", action, out, err)
	}
	if strings.Contains(string(out), "Skipping inserting existing rule") || strings.Contains(string(out), "Skipping adding existing rule") {
		return fmt.Errorf("UFW 跳过了规则插入，无法确认优先级；请检查现有冲突规则: %s", out)
	}
	return nil
}

func ufwRuleArgs(rule Rule, action string, insert bool) []string {
	args := []string{}
	if rule.Routed {
		args = append(args, "route")
	}
	if insert {
		args = append(args, "insert", "1")
	} else {
		args = append(args, "delete")
	}
	args = append(args, action)
	port := strings.ReplaceAll(rule.Port, "-", ":")
	if rule.FromIP != "" || rule.Routed {
		source := rule.FromIP
		if source == "" {
			source = "any"
		}
		args = append(args, "from", source, "to", "any", "port", port)
		if rule.Protocol != "any" {
			args = append(args, "proto", rule.Protocol)
		}
	} else {
		if rule.Protocol != "any" {
			port += "/" + rule.Protocol
		}
		args = append(args, port)
	}
	if insert && rule.Comment != "" {
		args = append(args, "comment", rule.Comment)
	}
	return args
}

func sourceKey(source string) string {
	source = strings.TrimSpace(strings.TrimSuffix(source, "(v6)"))
	if source == "Anywhere" || source == "any" {
		return ""
	}
	if prefix, err := netip.ParsePrefix(source); err == nil {
		if prefix.Bits() == 0 {
			return ""
		}
		if prefix.Bits() == prefix.Addr().BitLen() {
			return prefix.Addr().String()
		}
		return prefix.Masked().String()
	}
	if addr, err := netip.ParseAddr(source); err == nil {
		return addr.String()
	}
	return source
}

func (u *UFWBackend) Status(ctx context.Context) ([]Rule, bool, error) {
	out, err := CommandRunner(ctx, "ufw", "status", "numbered")
	if err != nil {
		return nil, false, err
	}

	active := strings.Contains(string(out), "Status: active")
	var rules []Rule

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inTable := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			inTable = true
		}
		if !inTable {
			continue
		}

		// Example: [ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
		r, err := parseUFWRuleLine(line)
		if err == nil {
			rules = append(rules, r)
		}
	}

	return rules, active, scanner.Err()
}

func parseUFWRuleLine(line string) (Rule, error) {
	closeBracket := strings.Index(line, "]")
	if closeBracket <= 1 || !strings.HasPrefix(line, "[") {
		return Rule{}, fmt.Errorf("invalid rule line")
	}

	numStr := strings.TrimSpace(line[1:closeBracket])
	num, err := strconv.Atoi(numStr)
	if err != nil || num < 1 {
		return Rule{}, fmt.Errorf("invalid rule number")
	}

	rest := strings.TrimSpace(line[closeBracket+1:])
	comment := ""
	if hashIdx := strings.Index(rest, "#"); hashIdx != -1 {
		comment = strings.TrimSpace(rest[hashIdx+1:])
		rest = strings.TrimSpace(rest[:hashIdx])
	}

	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return Rule{}, fmt.Errorf("not enough fields")
	}

	toSpec := fields[0]
	actionAt := -1
	for i, f := range fields {
		if f == "ALLOW" || f == "DENY" || f == "REJECT" || f == "LIMIT" {
			actionAt = i
			break
		}
	}
	if actionAt <= 0 {
		return Rule{}, fmt.Errorf("unknown UFW action")
	}
	port, proto, err := ParsePortProto(toSpec)
	if err != nil {
		port, proto = toSpec, "any"
	}
	if !strings.Contains(toSpec, "/") {
		proto = "any"
	}
	scoped := false
	for _, field := range fields[1:actionAt] {
		if field != "(v6)" {
			scoped = true
		}
	}
	sourceAt := actionAt + 1
	routed := false
	if sourceAt < len(fields) && (fields[sourceAt] == "IN" || fields[sourceAt] == "OUT" || fields[sourceAt] == "FWD") {
		routed = fields[sourceAt] == "FWD"
		if fields[sourceAt] == "OUT" {
			scoped = true
		}
		sourceAt++
	}
	fromIP := strings.Join(fields[sourceAt:], " ")
	if strings.Contains(fromIP, " on ") {
		scoped = true
	}
	if fromIP == "" {
		fromIP = "Anywhere"
	}
	action := fields[actionAt]

	return Rule{
		Number:   num,
		Port:     port,
		Protocol: proto,
		Action:   action,
		FromIP:   fromIP,
		Comment:  comment,
		Routed:   routed,
		scoped:   scoped,
		ipv6:     strings.Contains(rest, "(v6)"),
	}, nil
}
