# Ubuntu 26.04 / SSH 22 验收：v1.0.2-rc.2

当前已经发布可安装的预发布版，适合在空白测试虚拟机体验。下面列的是待执行的命令和预期结果；尚未收到这台服务器的实测结果，不能据此宣布正式稳定。

## 0. 执行范围

- 服务器终端 A：保留当前 SSH 连接，先执行 `sudo -i`，后续服务器命令以 root 运行。
- 本机终端 B：用于从外部验证连接和新公钥登录。
- 需要无业务、无容器（包括已停止容器）的测试虚拟机，以及可用的云控制台。先做虚拟机快照，方便完整还原。
- 测试会启用 UFW、修改 SSH 配置、重启 Docker，并在单独步骤重启服务器。已有业务或容器时停止，不运行这些修改步骤。
- 各节按顺序执行，出现未说明的失败就停止，保留输出。不要整篇一次性粘贴。

本指南从 SSH 22 开始，验收 `ssh.socket` 模式下切到 22022、确认、回滚与重启持久化；保留系统原有 socket 启动方式。要求 Ubuntu 的 SSH socket 生成器正常工作、ssh.service 使用 `KillMode=process`；自定义固定 ListenStream 或其他不兼容配置会明确拒绝切换。自动 IP 封禁、独立白名单管理、IPv6 容器和 Docker 原生 nftables 后端也不属于本版已完成功能。

## 1. 检查环境并安装验收版本

终端 A，先只检查：

```bash
cat /etc/os-release
ps -p 1 -o comm=
systemctl is-active ssh.socket || true
systemctl is-active ssh.service || true
ss -ltnp 'sport = :22'
if command -v docker >/dev/null; then
  docker info >/dev/null && docker ps -a
fi
```

预期系统是 Ubuntu 26.04，PID 1 是 systemd，22 有监听；`ssh.socket` 是否 active 以实际输出为准。若 Docker 已有容器，停止此流程；若 Docker 查询报错，先排除服务问题。

确认是空白测试机后执行：

```bash
bash <<'BASH'
set -euo pipefail
export LC_ALL=C
apt-get update
apt-get install -y ca-certificates curl ufw iptables iproute2 python3
if ! command -v docker >/dev/null; then
  apt-get install -y docker.io
fi
systemctl enable --now docker
docker info >/dev/null
if [ -n "$(docker ps -aq)" ] || [ -e /etc/systemd/system/docker.service.d/secctl-shield.conf ]; then
  echo '停止：验收要求无容器且尚未启用 Docker Shield。' >&2
  exit 1
fi
curl -fsSL https://raw.githubusercontent.com/9star-academy/secctl/v1.0.2-rc.2/scripts/install.sh \
  -o /tmp/secctl-v1.0.2-rc.2-install.sh
SECCTL_VERSION=v1.0.2-rc.2 bash /tmp/secctl-v1.0.2-rc.2-install.sh
secctl --version
docker pull nginx:alpine
BASH
```

预期安装器校验 SHA256 后成功，版本准确显示：

```text
secctl version v1.0.2-rc.2
```

镜像下载失败是验收准备未完成，不能继续当作防火墙失败。不要覆盖现有 Docker 安装来强行更换后端。

## 2. 备份并准备 UFW

终端 A：

```bash
bash <<'BASH'
set -euo pipefail
export LC_ALL=C
DIR=$(mktemp -d /root/secctl-acceptance.XXXXXX)
chmod 700 "$DIR"
printf '%s\n' "$DIR" > /root/secctl-acceptance.path
cp -a /etc/ssh/sshd_config "$DIR/sshd_config.original"
cp -a /etc/default/ufw "$DIR/ufw.default.original"
tar -C /etc -czf "$DIR/ufw.original.tar.gz" ufw
ufw status > "$DIR/ufw.status.original"
ufw status numbered
python3 - <<'PY'
from pathlib import Path
import re
p = Path('/etc/default/ufw')
s = p.read_text()
if re.search(r'^\s*MANAGE_BUILTINS=', s, re.M):
    s = re.sub(r'^\s*MANAGE_BUILTINS=.*$', 'MANAGE_BUILTINS=no', s, flags=re.M)
else:
    s += '\nMANAGE_BUILTINS=no\n'
p.write_text(s)
PY
ufw allow 22/tcp
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose
sshd -t
printf '备份目录：%s\n' "$DIR"
BASH
```

预期 `Status: active`、22/tcp ALLOW，`sshd -t` 无输出且退出码 0。终端 B 此时重新登录一次 SSH 22，确认能建立新连接；原连接仍存在不足以证明放行正确。

## 3. 基础命令及无效参数

终端 A：

```bash
secctl --help
secctl audit
secctl status
secctl docker-shield status
```

预期帮助正常；audit 列出实际监听端口、进程及风险提示；status 显示已启用的 UFW；Shield 尚未开启。审计分数随机器变化，不要求固定分数，也不等同于公网连通性测试。

```bash
bash <<'BASH'
set -euo pipefail
export LC_ALL=C
DIR=$(cat /root/secctl-acceptance.path)
ufw status numbered > "$DIR/ufw.before-invalid"
for args in '99999/tcp' '18081,invalid'; do
  if secctl allow "$args"; then echo "FAIL: 无效参数被接受：$args"; exit 1; fi
done
if secctl allow 18081/tcp --form 10.0.0.0/8; then
  echo 'FAIL: 拼错的参数被接受'; exit 1
fi
if env PATH=/__secctl_no_tools__ /usr/local/bin/secctl deny 18081/tcp; then
  echo 'FAIL: 缺少后端却返回成功'; exit 1
fi
ufw status numbered > "$DIR/ufw.after-invalid"
cmp "$DIR/ufw.before-invalid" "$DIR/ufw.after-invalid"
echo 'PASS: 无效输入及缺少后端返回失败，未部分添加规则'
BASH
```

预期四次被测命令均报错；最后 `cmp` 无输出，打印 PASS。这里被测命令返回非零是通过条件。

## 4. 网络、Docker 重载与 SSH 挂断回滚

固定版本的原始脚本现在直接测试 22 → 22022 → 挂断进程 → 恢复 22，不需要修改测试副本。

终端 A：

```bash
bash <<'BASH'
set -euo pipefail
export LC_ALL=C
DIR=$(cat /root/secctl-acceptance.path)
curl -fsSL https://raw.githubusercontent.com/9star-academy/secctl/v1.0.2-rc.2/scripts/test-linux-integration.sh \
  -o "$DIR/integration.sh"
bash -n "$DIR/integration.sh"
SECCTL_TEST_DISPOSABLE_VM=1 SECCTL_BIN=/usr/local/bin/secctl \
  bash "$DIR/integration.sh" 2>&1 | tee "$DIR/integration.log"
echo 'PASS: 集成脚本退出码 0'
BASH
```

预期依次包含：

```text
PASS: 宿主机 allow → deny
PASS: Docker 默认拒绝、授权放行、UFW reload、Docker restart、再次拒绝
PASS: SSH SIGHUP 后独立定时器恢复原配置
全部集成验收通过。整机 reboot 持久化仍需按文档单独验证。
PASS: 集成脚本退出码 0
```

脚本从独立网络命名空间发起连接，不用服务器 localhost 判断防护。它会重启 Docker，结束时清理自身容器、网络、规则，并关闭本次开启的 Shield。SSH 项在观察到确认提示及新端口监听后才挂断进程；随后检查恢复原配置且 22022 不再监听。终端 B 还需验证 SSH 22 能新建连接。

失败后停止，记录上面的错误和 `/root/secctl-acceptance.path` 所指目录内的 `integration.log`。不要因为文件里存在防护规则就认定网络验证成功。

## 5. 新公钥登录、禁止密码、人工确认

终端 B（你自己的电脑），填入服务器 IP 和实际登录用户，例如 `ubuntu` 或 `root`。以下私钥始终保留在本机：

```bash
SERVER='替换为服务器IP'
SSHUSER='替换为实际登录用户'
KEY_DIR=$(mktemp -d "${TMPDIR:-/tmp}/secctl-key.XXXXXX")
ssh-keygen -t ed25519 -N '' -C secctl-acceptance -f "$KEY_DIR/key"
scp -P 22 "$KEY_DIR/key.pub" "$SSHUSER@$SERVER:secctl-acceptance.pub"
```

预期只上传 `.pub` 公钥。终端 A 填入同一个用户并备份其原有公钥文件：

```bash
SSHUSER='替换为实际登录用户'
DIR=$(cat /root/secctl-acceptance.path)
TARGET_HOME=$(getent passwd "$SSHUSER" | cut -d: -f6)
test -n "$TARGET_HOME" && test -f "$TARGET_HOME/secctl-acceptance.pub"
printf '%s\n' "$TARGET_HOME" > "$DIR/key-target-home"
if [ -f "$TARGET_HOME/.ssh/authorized_keys" ]; then
  cp -a "$TARGET_HOME/.ssh/authorized_keys" "$DIR/authorized_keys.original"
else
  touch "$DIR/authorized_keys.was-absent"
fi
secctl ssh harden --user "$SSHUSER" --key "$TARGET_HOME/secctl-acceptance.pub" \
  --disable-password --timeout 180
```

出现确认提示后，先别输入 `confirm`。终端 B 验证只能使用这把新私钥登录：

```bash
ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -i "$KEY_DIR/key" -p 22 "$SSHUSER@$SERVER" 'echo KEY_LOGIN_OK'
```

必须输出 `KEY_LOGIN_OK` 且退出码 0，然后回终端 A 输入 `confirm` 并回车。预期显示“新 SSH 配置已确认”。失败时不确认，等待回滚。

终端 A：

```bash
sshd -t
sshd -T | grep -E '^(pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|port) '
test ! -e /etc/ssh/sshd_config.secctl.pending
```

预期 `pubkeyauthentication yes`、`passwordauthentication no`、`kbdinteractiveauthentication no`、`port 22`，pending 目录已清理。

终端 B 再做一次密码方式的负向验证：

```bash
ssh -F /dev/null -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password,keyboard-interactive \
  -o NumberOfPasswordPrompts=1 -p 22 "$SSHUSER@$SERVER" true
echo "退出码=$?"
```

预期直接 Permission denied，退出码 255，不应出现密码输入提示。出现提示则 Ctrl+C，并记录失败；不使用 `BatchMode=yes` 代替本项。

GitHub 导入是另一种公钥来源；若也要验收，使用你自己控制且已登记公钥的账号运行 `secctl ssh harden --user "$SSHUSER" --github 你的GitHub账号 --disable-password --timeout 180`，按相同步骤验证对应私钥登录后再确认。不要填写示例中的他人账号。

## 5b. SSH 22 → 22022 → 22，确认新端口生效

先在云安全组允许你电脑的公网 IP 访问 TCP 22022，保留 22 规则。终端 A：

```bash
secctl ssh harden --user "$SSHUSER" --port 22022 --timeout 180
```

出现确认提示后，终端 B 使用第 5 节的新私钥建立新连接：

```bash
ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none \
  -i "$KEY_DIR/key" -p 22022 "$SSHUSER@$SERVER" 'echo NEW_PORT_OK'
```

必须输出 `NEW_PORT_OK`，再回终端 A 输入 `confirm`。终端 A 的原连接应保持可用；新开终端运行 `ss -ltnp 'sport = :22022'` 可见监听，`ss -ltn 'sport = :22'` 应无数据行。初始 socket 模式下 `systemctl is-active ssh.socket` 仍为 active。

随后终端 A 切回 22，使用终端 B 在 22 验证 `KEY_LOGIN_OK` 后再确认：

```bash
secctl ssh harden --user "$SSHUSER" --port 22 --timeout 180
```

预期切回成功、22022 不再监听，供后续回滚测试使用。UFW 的旧端口放行规则会保留，不影响监听判断。第 7 节会在已确认的 22022 上重启，验证非默认端口持久化。

## 6. 超时和 Ctrl+C 恢复

终端 A，每次测试前单独备份：

```bash
DIR=$(cat /root/secctl-acceptance.path)
cp /etc/ssh/sshd_config "$DIR/sshd.before-timeout"
secctl ssh harden --port 22022 --permit-root-keys-only=false --timeout 15
echo "退出码=$?"
cmp /etc/ssh/sshd_config "$DIR/sshd.before-timeout"
sshd -t
```

确认提示出现后，不输入任何内容，等待约 15 秒。预期恢复原配置和 22 监听、22022 关闭、命令退出码 1、`cmp` 和 `sshd -t` 无输出且退出码 0。再执行一次同样流程，在确认提示出现后按 Ctrl+C；也应恢复，命令非零退出。从终端 B 用新密钥确认 SSH 22 仍可建立新连接。

自动回滚恢复 SSH 配置及原来的 socket 监听；已经导入的公钥、已经放行的新端口规则不会随之撤销。临时回滚定时器不保证跨整机重启恢复。

## 7. 整机重启后容器规则仍生效

终端 A，确认前面的 SSH 操作已经确认或恢复，再创建专用测试容器：

```bash
bash <<'BASH'
set -euo pipefail
DIR=$(cat /root/secctl-acceptance.path)
test ! -e /etc/ssh/sshd_config.secctl.pending/pending
cat > "$DIR/nginx.conf" <<'NGINX'
events {}
http {
  server { listen 80; location / { return 200 "secctl-allow\n"; } }
  server { listen 81; location / { return 200 "secctl-deny\n"; } }
}
NGINX
docker run -d --name secctl-accept-reboot --restart unless-stopped \
  -p 18080:80 -p 18081:81 \
  -v "$DIR/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:alpine
BASH
```

在云安全组临时允许你电脑的公网 IP 访问 TCP 18080、18081。终端 B，先确认未开启 Shield 时两个端口都能访问：

```bash
curl --noproxy '*' -4 -fsS --connect-timeout 3 --max-time 5 "http://$SERVER:18080"
curl --noproxy '*' -4 -fsS --connect-timeout 3 --max-time 5 "http://$SERVER:18081"
```

预期分别返回 `secctl-allow` 和 `secctl-deny`；若基线不通，先处理容器、路由或云安全组，不能据此判定 Shield 生效。必须使用 IPv4 直连服务器地址。

终端 A：

```bash
secctl docker-shield enable
secctl allow 80/tcp --docker --comment secctl-acceptance
secctl deny 81/tcp --docker --comment secctl-acceptance
secctl docker-shield status
```

终端 B 再次运行上面的两个 curl：18080 返回 `secctl-allow`；18081 无法得到 HTTP 响应且 curl 非零退出。这里匹配的是两个不同的**容器端口** 80、81，不是宿主机端口 18080、18081。

两个结果均正确后，再把 SSH 切到非默认端口，一起验证持久化。终端 A 运行：

```bash
secctl ssh harden --user "$SSHUSER" --port 22022 --timeout 180
```

终端 B 用新密钥连接 22022，确认输出 `KEY_LOGIN_OK` 后，终端 A 输入 `confirm`。必须先完成确认，再在终端 A 执行重启：

```bash
test ! -e /etc/ssh/sshd_config.secctl.pending/pending && reboot
```

重启会断开 SSH。系统恢复后用已验证的新密钥连接 SSH 22022；应仍能登录，22 应无监听，初始 socket 模式仍为 active。在服务器执行：

```bash
sudo secctl docker-shield status
sudo docker ps --filter name=secctl-accept-reboot
sudo iptables -S DOCKER-USER
sudo iptables -S SECCTL-DOCKER
sudo ufw status numbered
```

预期容器 Up、Shield 已启用、DOCKER-USER 第一条跳转 SECCTL-DOCKER，私有链包含 UFW 转发授权及 docker0/br-* 的 DROP。终端 B 两个 curl 仍应一通一拒；仅 systemd active 或规则存在不算本项通过。

可补充容器出站测试（依赖这台服务器正常外网和 DNS）：

```bash
sudo docker exec secctl-accept-reboot sh -c 'nslookup example.com && wget -qO /dev/null http://example.com'
```

预期能解析并请求成功；若不通，记录输出和开启 Shield 前的相同测试结果。

## 8. 清理和恢复

推荐验收完恢复虚拟机快照。若手工恢复，先在终端 A 以 root 执行以下步骤；保留原连接，不提前删除本机验收私钥：

```bash
bash <<'BASH'
set -euo pipefail
DIR=$(cat /root/secctl-acceptance.path)
test ! -e /etc/ssh/sshd_config.secctl.pending/pending
secctl docker-shield disable
docker rm -f secctl-accept-reboot
cp -a "$DIR/sshd_config.original" /etc/ssh/sshd_config
sshd -t
if systemctl is-active --quiet ssh.socket; then
  systemctl daemon-reload
  systemctl stop ssh.service ssh.socket
  systemctl start ssh.socket ssh.service
else
  systemctl reload ssh
fi
echo '先从另一个终端验证验收前的 SSH 登录方式，再继续恢复公钥和 UFW。'
BASH
```

用验收前的身份重新建立 SSH 22 连接成功后，终端 A 执行：

```bash
bash <<'BASH'
set -euo pipefail
export LC_ALL=C
DIR=$(cat /root/secctl-acceptance.path)
TARGET_HOME=$(cat "$DIR/key-target-home")
if [ -f "$DIR/authorized_keys.original" ]; then
  cp -a "$DIR/authorized_keys.original" "$TARGET_HOME/.ssh/authorized_keys"
elif [ -f "$DIR/authorized_keys.was-absent" ]; then
  rm -f "$TARGET_HOME/.ssh/authorized_keys"
fi
rm -f "$TARGET_HOME/secctl-acceptance.pub"
ufw --force disable
tar -C /etc -xzf "$DIR/ufw.original.tar.gz"
cp -a "$DIR/ufw.default.original" /etc/default/ufw
if grep -q '^Status: active' "$DIR/ufw.status.original"; then
  ufw --force enable
fi
ufw status
sshd -t
BASH
```

预期恢复验收前的 SSH 主配置、目标账号公钥文件和 UFW 配置/启用状态；不卸载新安装的软件包，不删除日志和 secctl 留存的 SSH 备份。该步骤仅适用于本指南的空白测试机，验收期间若另有配置改动不要整体覆盖。删除云安全组的两个临时规则。确认原身份仍能登录后，可在终端 B 删除本次新建的 `$KEY_DIR`。

若中途失败，先从云控制台查看错误；不要越过失败步骤直接粘贴完整清理块。收集这些输出即可，不要发送私钥：

```bash
sudo secctl --version
sudo systemctl status ssh.service ssh.socket docker --no-pager
sudo ufw status numbered
sudo journalctl -u docker -n 80 --no-pager
sudo journalctl --since '-30 min' -u 'secctl-rollback-*' --no-pager
sudo cat /root/secctl-acceptance.path
```

## 验收记录

| 项目 | 通过依据 |
| --- | --- |
| 发布安装 | SHA256 校验成功，准确显示 rc.1 版本 |
| 参数与错误传播 | 无效输入、缺少后端均失败且不部分写入规则 |
| 宿主机防火墙 | 独立命名空间连接先通后拒 |
| Docker 生命周期 | 默认拒绝、授权、UFW reload、Docker restart、再次拒绝均符合预期 |
| SSH 确认 | 新私钥能登录，密码不能登录，confirm 后配置保留 |
| SSH 恢复 | 超时、Ctrl+C、SIGHUP 后原配置及新连接恢复 |
| 整机重启 | 重启前后外部连接保持一通一拒 |
| Ubuntu socket 模式修改 SSH 端口 | 22022 新密钥登录、原会话保留、确认、切回、挂断恢复及重启持久化 |

发行页：[v1.0.2-rc.2](https://github.com/9star-academy/secctl/releases/tag/v1.0.2-rc.2)。环境参考：[Ubuntu OpenSSH](https://ubuntu.com/server/docs/how-to/security/openssh-server/)、[Ubuntu Docker 安装](https://ubuntu.com/server/docs/how-to/containers/docker-for-system-admins/)、[Docker iptables 与 DOCKER-USER](https://docs.docker.com/engine/network/firewall-iptables/)。
