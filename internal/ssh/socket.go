package ssh

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// socketState is persisted before changing sshd_config. Recovery must not infer
// activation mode from a socket which a failed switch may already have stopped.
type socketState struct {
	Listeners []string `json:"listeners"`
}

func captureSSHSocket(ctx context.Context) (*socketState, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, nil
	}
	out, err := sshSystemctl(ctx, "show", "ssh.socket", "--property=LoadState", "--property=ActiveState", "--property=Accept", "--property=Triggers", "--property=Listen")
	if err != nil {
		return nil, err
	}
	properties := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			properties[key] = value
		}
	}
	if properties["LoadState"] == "not-found" || properties["ActiveState"] == "inactive" || properties["ActiveState"] == "failed" {
		return nil, nil
	}
	if properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" || properties["Accept"] != "no" || properties["Triggers"] != "ssh.service" {
		return nil, fmt.Errorf("无法安全确认 ssh.socket 的监听模式，请先核对 systemctl status ssh.socket")
	}
	if _, err := parseSocketListeners(properties["Listen"]); err != nil {
		return nil, err
	}
	// Snapshot the generator model, not the active fd representation. Ubuntu can
	// display a dual-stack wildcard differently before and after daemon-reload.
	// Refreshing the model here does not stop or replace the active listener.
	listeners, err := regenerateSocketListeners(ctx)
	if err != nil {
		return nil, err
	}
	killMode, err := sshSystemctl(ctx, "show", "ssh.service", "--property=KillMode", "--value")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(killMode)) != "process" {
		return nil, fmt.Errorf("socket 端口切换要求 ssh.service KillMode=process，避免停止当前 SSH 会话；未修改 SSH 配置")
	}
	return &socketState{Listeners: listeners}, nil
}

func sshSystemctl(ctx context.Context, args ...string) ([]byte, error) {
	out, err := CommandRunner(ctx, "systemctl", args...)
	if err != nil {
		return out, fmt.Errorf("systemctl %s: %s (%w)", strings.Join(args, " "), out, err)
	}
	return out, nil
}

func parseSocketListeners(value string) ([]string, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 || len(fields)%2 != 0 {
		return nil, fmt.Errorf("无法读取 ssh.socket TCP 监听地址: %q", value)
	}
	var listeners []string
	for i := 0; i < len(fields); i += 2 {
		host, port, err := net.SplitHostPort(fields[i])
		p, portErr := strconv.Atoi(port)
		if err != nil || fields[i+1] != "(Stream)" || net.ParseIP(strings.SplitN(host, "%", 2)[0]) == nil || portErr != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("不支持的 ssh.socket 监听地址: %q", fields[i])
		}
		listeners = append(listeners, fields[i])
	}
	slices.Sort(listeners)
	return listeners, nil
}

// regenerateSocketListeners refreshes configuration without restarting listeners.
func regenerateSocketListeners(ctx context.Context) ([]string, error) {
	if _, err := sshSystemctl(ctx, "daemon-reload"); err != nil {
		return nil, err
	}
	out, err := sshSystemctl(ctx, "show", "ssh.socket", "--property=Listen", "--value")
	if err != nil {
		return nil, err
	}
	return parseSocketListeners(string(out))
}

// applySSHSocket uses Ubuntu's generator rather than overriding administrator
// units. A stale/custom ListenStream is rejected before stopping the old listener.
// port == 0 restores the exact original generated listener set.
func applySSHSocket(ctx context.Context, state *socketState, port int) error {
	listeners, err := regenerateSocketListeners(ctx)
	if err != nil {
		return err
	}
	if port == 0 {
		if !slices.Equal(listeners, state.Listeners) {
			return fmt.Errorf("ssh.socket 原监听地址未恢复：实际 %v，预期 %v", listeners, state.Listeners)
		}
	} else {
		for _, listener := range listeners {
			_, actual, _ := net.SplitHostPort(listener)
			if actual != strconv.Itoa(port) {
				return fmt.Errorf("ssh.socket 生成的监听地址 %v 与目标端口 %d 不符；请核对生成器或自定义 ListenStream", listeners, port)
			}
		}
	}
	// KillMode=process was checked before the transaction. Stop the old daemon as
	// well as the socket so inherited descriptors cannot retain the old port.
	if _, err := sshSystemctl(ctx, "stop", "ssh.service", "ssh.socket"); err != nil {
		return err
	}
	if _, err := sshSystemctl(ctx, "start", "ssh.socket", "ssh.service"); err != nil {
		return err
	}
	for _, listener := range listeners {
		_, p, _ := net.SplitHostPort(listener)
		if err := verifySSHListener(ctx, p, true); err != nil {
			return err
		}
	}
	return nil
}

func verifySSHListener(ctx context.Context, port string, socket bool) error {
	var last []byte
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		last, lastErr = CommandRunner(ctx, "ss", "-H", "-ltnp", "sport = :"+port)
		if lastErr == nil && (strings.Contains(string(last), `"sshd"`) || socket && strings.Contains(string(last), `"systemd"`)) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("未确认 SSH 正在端口 %s 监听: %s (%v)", port, last, lastErr)
}
