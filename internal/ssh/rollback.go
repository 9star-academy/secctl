package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// RollbackGuard is stored beside sshd_config and is independent of the terminal.
type RollbackGuard struct {
	Dir  string
	Unit string
	lock *os.File
}

type rollbackState struct {
	Config string      `json:"config"`
	Mode   os.FileMode `json:"mode"`
}

func StartRollback(ctx context.Context, config string, original []byte, mode os.FileMode, seconds int) (*RollbackGuard, error) {
	if seconds < 1 {
		return nil, fmt.Errorf("回滚超时必须大于 0")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return nil, fmt.Errorf("防失联保护需要 systemd-run；未修改 SSH 配置: %w", err)
	}
	config, err := filepath.Abs(config)
	if err != nil {
		return nil, err
	}
	transactionLock, err := os.OpenFile(config+".secctl.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(transactionLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = transactionLock.Close()
		return nil, fmt.Errorf("另一 SSH 加固操作仍在运行: %w", err)
	}
	retainLock := false
	defer func() {
		if !retainLock {
			_ = transactionLock.Close()
		}
	}()
	dir := config + ".secctl.pending"
	if _, err := os.Stat(filepath.Join(dir, "pending")); os.IsNotExist(err) {
		if unit, err := os.ReadFile(filepath.Join(dir, "unit")); err == nil {
			if out, err := CommandRunner(ctx, "systemctl", "stop", string(unit)+".timer", string(unit)+".service"); err != nil {
				return nil, fmt.Errorf("清理上次回滚定时器失败: %s (%w)", out, err)
			}
			if err := os.RemoveAll(dir); err != nil {
				return nil, err
			}
		}
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, fmt.Errorf("已有待确认操作或无法创建回滚状态 %s: %w", dir, err)
	}
	g := &RollbackGuard{Dir: dir, lock: transactionLock}
	// A random suffix keeps old transient units from colliding with a later operation.
	suffix, err := os.CreateTemp(dir, "id-")
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	_ = suffix.Close()
	g.Unit = "secctl-rollback-" + strings.TrimPrefix(filepath.Base(suffix.Name()), "id-")
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}()
	data, err := json.Marshal(rollbackState{Config: config, Mode: mode.Perm()})
	if err != nil {
		return nil, err
	}
	for name, body := range map[string][]byte{"state.json": data, "original": original, "pending": {}, "unit": []byte(g.Unit)} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			return nil, err
		}
	}
	// Keep a private copy: upgrades or go run cleanup cannot remove the recovery executable.
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	src, err := os.Open(executable)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, "secctl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return nil, err
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return nil, err
	}
	// systemd expands dollars in arguments; escaping preserves literal filesystem paths.
	escape := func(s string) string { return strings.ReplaceAll(s, "$", "$$") }
	out, err := CommandRunner(ctx, "systemd-run", "--quiet", "--unit="+g.Unit, "--on-active="+fmt.Sprintf("%ds", seconds), "--timer-property=AccuracySec=1s", "--property=Restart=on-failure", "--property=RestartSec=5s", escape(filepath.Join(dir, "secctl")), "_ssh-rollback", escape(dir))
	if err != nil {
		return nil, fmt.Errorf("创建独立回滚定时器失败: %s (%w)", out, err)
	}
	ok = true
	retainLock = true
	return g, nil
}

// withLock serializes config writes, confirmation and the independent timer.
func (g *RollbackGuard) withLock(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(g.Dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func (g *RollbackGuard) Apply(fn func() error) error {
	return g.withLock(func() error {
		if _, err := os.Stat(filepath.Join(g.Dir, "pending")); err != nil {
			return fmt.Errorf("回滚已开始，停止应用 SSH 修改: %w", err)
		}
		return fn()
	})
}

func (g *RollbackGuard) Confirm(ctx context.Context) error {
	defer g.release()
	if err := g.withLock(func() error { return os.Remove(filepath.Join(g.Dir, "pending")) }); err != nil {
		return fmt.Errorf("无法确认（可能已回滚）: %w", err)
	}
	out, err := CommandRunner(ctx, "systemctl", "stop", g.Unit+".timer", g.Unit+".service")
	if err != nil {
		return fmt.Errorf("配置已确认，但停止定时器失败（回滚标记已撤销）: %s (%w)", out, err)
	}
	return os.RemoveAll(g.Dir)
}

func (g *RollbackGuard) release() {
	if g.lock != nil {
		_ = g.lock.Close()
		g.lock = nil
	}
}
func (g *RollbackGuard) Rollback(ctx context.Context) error {
	defer g.release()
	return RunRollback(ctx, g.Dir)
}

// RunRollback is called by the private recovery command or the foreground process.
func RunRollback(ctx context.Context, dir string) error {
	g := &RollbackGuard{Dir: dir}
	return g.withLock(func() error {
		pending := filepath.Join(dir, "pending")
		if _, err := os.Stat(pending); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(dir, "state.json"))
		if err != nil {
			return err
		}
		var state rollbackState
		if err := json.Unmarshal(data, &state); err != nil {
			return err
		}
		original, err := os.ReadFile(filepath.Join(dir, "original"))
		if err != nil {
			return err
		}
		if err := atomicConfig(state.Config, original, state.Mode); err != nil {
			return fmt.Errorf("恢复 SSH 配置失败: %w", err)
		}
		if err := ReloadSSHD(ctx); err != nil {
			return fmt.Errorf("原配置已恢复，但 SSH 重载失败: %w", err)
		}
		// Keep the pending marker until reload succeeds so systemd can retry a failure.
		if err := os.Rename(pending, filepath.Join(dir, "restored")); err != nil {
			return err
		}
		return nil
	})
}

func atomicConfig(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".secctl-config-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if info, err := os.Stat(path); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if err := f.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
				_ = f.Close()
				return err
			}
		}
	}
	if err := f.Chmod(mode.Perm()); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
