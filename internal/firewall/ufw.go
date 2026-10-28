package firewall

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
	args := []string{"allow"}
	if rule.Protocol != "" && rule.Protocol != "any" {
		if rule.FromIP != "" {
			args = append(args, "from", rule.FromIP, "to", "any", "port", rule.Port, "proto", rule.Protocol)
		} else {
			args = append(args, rule.Port+"/"+rule.Protocol)
		}
	} else {
		if rule.FromIP != "" {
			args = append(args, "from", rule.FromIP, "to", "any", "port", rule.Port)
		} else {
			args = append(args, rule.Port)
		}
	}

	if rule.Comment != "" {
		args = append(args, "comment", rule.Comment)
	}

	out, err := CommandRunner(ctx, "ufw", args...)
	if err != nil {
		return fmt.Errorf("执行 ufw allow 失败: %s (%w)", string(out), err)
	}
	return nil
}

func (u *UFWBackend) Deny(ctx context.Context, rule Rule) error {
	args := []string{"deny"}
	if rule.Protocol != "" && rule.Protocol != "any" {
		args = append(args, rule.Port+"/"+rule.Protocol)
	} else {
		args = append(args, rule.Port)
	}

	out, err := CommandRunner(ctx, "ufw", args...)
	if err != nil {
		return fmt.Errorf("执行 ufw deny 失败: %s (%w)", string(out), err)
	}
	return nil
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

	return rules, active, nil
}

func parseUFWRuleLine(line string) (Rule, error) {
	closeBracket := strings.Index(line, "]")
	if closeBracket == -1 {
		return Rule{}, fmt.Errorf("invalid rule line")
	}

	numStr := strings.TrimSpace(line[1:closeBracket])
	num, _ := strconv.Atoi(numStr)

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

	toSpec := fields[0] // e.g. 22/tcp or 80
	action := fields[1] // e.g. ALLOW

	port, proto, _ := ParsePortProto(toSpec)

	fromIP := "Anywhere"
	if len(fields) >= 4 {
		fromIP = fields[len(fields)-1]
	}

	return Rule{
		Number:   num,
		Port:     port,
		Protocol: proto,
		Action:   action,
		FromIP:   fromIP,
		Comment:  comment,
	}, nil
}
