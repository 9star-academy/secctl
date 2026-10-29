#!/usr/bin/env bash
set -euo pipefail

# Runs only after explicit opt-in, on a disposable Linux systemd VM without containers.
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ] || [ "${SECCTL_TEST_DISPOSABLE_VM:-}" != 1 ]; then
  echo "仅在空白 Linux systemd 虚拟机以 root 执行，并设置 SECCTL_TEST_DISPOSABLE_VM=1。" >&2
  exit 2
fi
SECCTL_BIN="${SECCTL_BIN:-$(command -v secctl)}"
for tool in ip curl docker ufw systemctl ss sshd python3; do command -v "$tool" >/dev/null; done
systemctl is-active --quiet docker
systemctl is-active --quiet ssh || systemctl is-active --quiet sshd
ufw status | grep -q 'Status: active'
if [ -n "$(docker ps -aq)" ] || [ -e /etc/systemd/system/docker.service.d/secctl-shield.conf ]; then
  echo "验收需要无容器且尚未安装 Docker Shield 的空白虚拟机。" >&2
  exit 2
fi

TEST_DIR="$(mktemp -d)"
NS="secctl-test-$$"
HOST_VETH="sc-host-$$"
CLIENT_VETH="sc-cli-$$"
CONTAINER="secctl-test-$$"
SHIELD_STARTED=0
HTTP_PID=""
SSH_PID=""
cleanup() {
  if [ -n "$SSH_PID" ]; then kill "$SSH_PID" 2>/dev/null || true; fi
  if [ -n "$HTTP_PID" ]; then kill "$HTTP_PID" 2>/dev/null || true; fi
  if [ "$SHIELD_STARTED" -eq 1 ]; then "$SECCTL_BIN" docker-shield disable || true; fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$HOST_VETH" 2>/dev/null || true
  ufw --force delete allow 18081/tcp >/dev/null 2>&1 || true
  ufw --force delete deny 18081/tcp >/dev/null 2>&1 || true
  ufw --force delete allow 22022/tcp >/dev/null 2>&1 || true
  ufw --force route delete allow from 198.18.0.2 to any port 80 proto tcp >/dev/null 2>&1 || true
  ufw --force route delete deny from 198.18.0.2 to any port 80 proto tcp >/dev/null 2>&1 || true
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT

ip netns add "$NS"
ip link add "$HOST_VETH" type veth peer name "$CLIENT_VETH"
ip link set "$CLIENT_VETH" netns "$NS"
ip addr add 198.18.0.1/24 dev "$HOST_VETH"
ip link set "$HOST_VETH" up
ip netns exec "$NS" ip addr add 198.18.0.2/24 dev "$CLIENT_VETH"
ip netns exec "$NS" ip link set "$CLIENT_VETH" up
ip netns exec "$NS" ip link set lo up
probe() { ip netns exec "$NS" curl -fsS --connect-timeout 2 --max-time 3 "$1" >/dev/null 2>&1; }
wait_open() { for _ in $(seq 1 30); do if probe "$1"; then return 0; fi; sleep 0.5; done; return 1; }

python3 -m http.server 18081 --bind 198.18.0.1 >"$TEST_DIR/http.log" 2>&1 &
HTTP_PID=$!
"$SECCTL_BIN" allow 18081/tcp
wait_open http://198.18.0.1:18081
"$SECCTL_BIN" deny 18081/tcp
if probe http://198.18.0.1:18081; then echo "FAIL: host deny 未阻断新连接"; exit 1; fi
echo "PASS: 宿主机 allow → deny"

docker run -d --name "$CONTAINER" --restart unless-stopped -p 18080:80 nginx:alpine >/dev/null
wait_open http://198.18.0.1:18080
"$SECCTL_BIN" docker-shield enable
SHIELD_STARTED=1
if probe http://198.18.0.1:18080; then echo "FAIL: Shield 未拒绝未授权容器连接"; exit 1; fi
"$SECCTL_BIN" allow 80/tcp --docker --from 198.18.0.2
wait_open http://198.18.0.1:18080
ufw reload
wait_open http://198.18.0.1:18080
systemctl restart docker
wait_open http://198.18.0.1:18080
"$SECCTL_BIN" deny 80/tcp --docker --from 198.18.0.2
if probe http://198.18.0.1:18080; then echo "FAIL: 重启后容器 deny 未生效"; exit 1; fi
echo "PASS: Docker 默认拒绝、授权放行、UFW reload、Docker restart、再次拒绝"

cp /etc/ssh/sshd_config "$TEST_DIR/sshd_config.original"
mkfifo "$TEST_DIR/input"
exec 3<>"$TEST_DIR/input"
"$SECCTL_BIN" ssh harden --port 22022 --timeout 10 --permit-root-keys-only=false <&3 >"$TEST_DIR/ssh.log" 2>&1 &
SSH_PID=$!
READY=0
for _ in $(seq 1 80); do
  if grep -q '请新开终端验证 SSH 登录' "$TEST_DIR/ssh.log" && ss -H -ltnp 'sport = :22022' | grep -Eq 'sshd|systemd'; then READY=1; break; fi
  if ! kill -0 "$SSH_PID" 2>/dev/null; then cat "$TEST_DIR/ssh.log"; exit 1; fi
  sleep 0.1
done
if [ "$READY" -ne 1 ]; then cat "$TEST_DIR/ssh.log"; exit 1; fi
kill -HUP "$SSH_PID"
wait "$SSH_PID" 2>/dev/null || true
SSH_PID=""
RESTORED=0
for _ in $(seq 1 50); do
  if cmp -s /etc/ssh/sshd_config "$TEST_DIR/sshd_config.original"; then RESTORED=1; break; fi
  sleep 0.5
done
if [ "$RESTORED" -ne 1 ]; then cat "$TEST_DIR/ssh.log"; echo "FAIL: 挂断后未自动恢复 SSH 配置"; exit 1; fi
systemctl is-active --quiet ssh || systemctl is-active --quiet sshd
if ss -H -ltn 'sport = :22022' | grep -q .; then echo 'FAIL: 回滚后新端口仍监听'; exit 1; fi
echo "PASS: SSH SIGHUP 后独立定时器恢复原配置"
echo "全部集成验收通过。整机 reboot 持久化仍需按文档单独验证。"
