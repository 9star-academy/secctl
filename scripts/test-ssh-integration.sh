#!/usr/bin/env bash
set -euo pipefail

# This changes real SSH listeners and authentication on an explicitly disposable VM.
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ] || [ "${SECCTL_TEST_DISPOSABLE_VM:-}" != 1 ]; then
  echo '仅在空白 Linux systemd 虚拟机以 root 执行，并设置 SECCTL_TEST_DISPOSABLE_VM=1。' >&2
  exit 2
fi
export LC_ALL=C
SECCTL_BIN="${SECCTL_BIN:-$(command -v secctl)}"
for tool in ssh sshd ssh-keygen systemctl ss ufw; do command -v "$tool" >/dev/null; done
ufw status | grep -q 'Status: active'
if ss -H -ltn 'sport = :22022' | grep -q .; then echo '测试端口 22022 已占用'; exit 2; fi
if [ -e /etc/ssh/sshd_config.secctl.pending/pending ]; then echo '已有待确认的 SSH 操作'; exit 2; fi
sshd -T | grep -x 'port 22' >/dev/null
TEST_DIR=$(mktemp -d)
cp -a /etc/ssh/sshd_config "$TEST_DIR/original"
ROOT_HOME=$(getent passwd root | cut -d: -f6)
KEYS="$ROOT_HOME/.ssh/authorized_keys"
if [ -f "$KEYS" ]; then cp -a "$KEYS" "$TEST_DIR/authorized_keys"; fi
SOCKET_MODE=0
if systemctl is-active --quiet ssh.socket; then SOCKET_MODE=1; fi
SSH_PID=''
SSH_OPTIONS=(-F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3
  -i "$TEST_DIR/key")
reload_original() {
  cp -a "$TEST_DIR/original" /etc/ssh/sshd_config
  sshd -t
  if [ "$SOCKET_MODE" -eq 1 ]; then
    systemctl daemon-reload
    systemctl stop ssh.service ssh.socket
    systemctl start ssh.socket ssh.service
  else
    systemctl reload ssh
  fi
}
cleanup() {
  if [ -f "$TEST_DIR/ssh.log" ]; then cat "$TEST_DIR/ssh.log"; fi
  if [ -n "$SSH_PID" ]; then kill -INT "$SSH_PID" 2>/dev/null || true; wait "$SSH_PID" 2>/dev/null || true; fi
  ssh "${SSH_OPTIONS[@]}" -S "$TEST_DIR/control" -O exit -p 22 root@127.0.0.1 >/dev/null 2>&1 || true
  if [ -e /etc/ssh/sshd_config.secctl.pending/pending ]; then
    echo "待确认操作尚未恢复，保留 $TEST_DIR；请检查独立回滚服务。" >&2
    return
  fi
  if ! reload_original; then echo "原 SSH 配置恢复失败，保留 $TEST_DIR" >&2; return; fi
  if [ -f "$TEST_DIR/authorized_keys" ]; then cp -a "$TEST_DIR/authorized_keys" "$KEYS"; else rm -f "$KEYS"; fi
  ufw --force delete allow 22022/tcp >/dev/null 2>&1 || true
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N '' -f "$TEST_DIR/key"
install -d -m 700 "$ROOT_HOME/.ssh"
printf '\n' >> "$KEYS"
cat "$TEST_DIR/key.pub" >> "$KEYS"
chmod 600 "$KEYS"
ssh "${SSH_OPTIONS[@]}" -M -S "$TEST_DIR/control" -fN -p 22 root@127.0.0.1

login() { ssh "${SSH_OPTIONS[@]}" -p "$1" root@127.0.0.1 'printf KEY_LOGIN_OK' | grep -qx KEY_LOGIN_OK; }
start_change() {
  local port=$1 timeout=$2
  rm -f "$TEST_DIR/input"
  mkfifo "$TEST_DIR/input"
  exec 3<>"$TEST_DIR/input"
  "$SECCTL_BIN" ssh harden --user root --key "$TEST_DIR/key.pub" --port "$port" \
    --disable-password --timeout "$timeout" <&3 3>&- >"$TEST_DIR/ssh.log" 2>&1 &
  SSH_PID=$!
  for _ in $(seq 1 100); do
    if grep -q '请新开终端验证 SSH 登录' "$TEST_DIR/ssh.log"; then return 0; fi
    if ! kill -0 "$SSH_PID" 2>/dev/null; then cat "$TEST_DIR/ssh.log"; return 1; fi
    sleep 0.1
  done
  cat "$TEST_DIR/ssh.log"
  return 1
}
for port in 22022 22; do
  start_change "$port" 30
  login "$port"
  # The connection accepted before restarting the listener must remain usable.
  ssh "${SSH_OPTIONS[@]}" -S "$TEST_DIR/control" -p 22 root@127.0.0.1 'printf EXISTING_SESSION_OK' | grep -qx EXISTING_SESSION_OK
  printf 'confirm\n' >&3
  if ! wait "$SSH_PID"; then cat "$TEST_DIR/ssh.log"; exit 1; fi
  SSH_PID=''
  exec 3>&-
  test ! -e /etc/ssh/sshd_config.secctl.pending
  login "$port"
  old_port=22
  if [ "$port" -eq 22 ]; then old_port=22022; fi
  if ss -H -ltn "sport = :$old_port" | grep -q .; then echo 'FAIL: 确认后旧端口仍监听'; exit 1; fi
  if [ "$SOCKET_MODE" -eq 1 ]; then systemctl is-active --quiet ssh.socket; fi
done
echo 'PASS: SSH 新端口公钥登录、confirm 保留配置、原会话存活、切回 22'

for scenario in timeout interrupt hangup; do
  cp /etc/ssh/sshd_config "$TEST_DIR/before"
  start_change 22022 15
  login 22022
  case "$scenario" in interrupt) kill -INT "$SSH_PID" ;; hangup) kill -HUP "$SSH_PID" ;; esac
  if wait "$SSH_PID"; then echo "FAIL: $scenario 未确认却返回成功"; exit 1; fi
  SSH_PID=''
  exec 3>&-
  RESTORED=0
  for _ in $(seq 1 90); do
    if [ ! -e /etc/ssh/sshd_config.secctl.pending/pending ] && cmp -s /etc/ssh/sshd_config "$TEST_DIR/before" && login 22; then
      RESTORED=1
      break
    fi
    sleep 0.5
  done
  if [ "$RESTORED" -ne 1 ]; then cat "$TEST_DIR/ssh.log"; echo "FAIL: $scenario 未恢复原监听"; exit 1; fi
  if ss -H -ltn 'sport = :22022' | grep -q .; then echo 'FAIL: 回滚后新端口仍监听'; exit 1; fi
  if [ "$SOCKET_MODE" -eq 1 ]; then systemctl is-active --quiet ssh.socket; fi
  echo "PASS: SSH $scenario 恢复原配置、22 端口及新公钥登录"
done
