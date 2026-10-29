# Linux 集成验收

开发机单元测试不会修改真实 SSH、防火墙或 Docker。它们验证命令失败传播、规则优先级、独立回滚状态、有效配置检查和 CLI 参数校验，不能替代内核转发、系统服务重启和外部访问验证。

Ubuntu 26.04、SSH 22 的 v1.0.2-rc.2 发布版验收请使用 [逐步命令与预期结果](acceptance-ubuntu-26.04.md)。该流程包含 socket 模式的端口切换、确认、独立回滚和重启后新端口登录。

## 准备

使用一台无业务、无容器的 Ubuntu/Debian systemd 虚拟机，准备云控制台/虚拟机控制台。需要 OpenSSH server、UFW、Docker 的 iptables 后端、iproute2、curl 和 Python 3。UFW 配置 `/etc/default/ufw` 必须使用 `MANAGE_BUILTINS=no`。SSH 配置不能包含 Match 块或 Include 中的额外 Port。不要在生产机运行验收脚本。

从源码构建当前 secctl；保留真实 SSH 端口的 UFW 规则并启用 UFW，再执行：

```bash
go build -o /tmp/secctl ./cmd/secctl
sudo env SECCTL_TEST_DISPOSABLE_VM=1 SECCTL_BIN=/tmp/secctl bash scripts/test-linux-integration.sh
```

脚本会创建测试网络命名空间、一个 nginx 容器，短暂修改虚拟机 SSH 监听端口，并重启 Docker。测试后删除自身测试规则、容器和网络，禁用本次启用的 Shield。SSH 失败时优先通过控制台检查输出中的独立回滚服务日志；回滚状态和备份会保留。

预期输出依次包含 `PASS: 宿主机 allow → deny`、Docker 流程 PASS、SSH SIGHUP 回滚 PASS，最后显示全部集成验收通过。任一步失败退出非零。nginx 镜像首次运行需要访问镜像仓库。

## 整机重启

单独启用 Shield 并为测试容器添加 `--docker` 授权；创建另一个未授权发布端口。从另一台机器确认前者可访问、后者不可访问，重启虚拟机后重复验证。检查：

```bash
sudo secctl docker-shield status
sudo iptables -S DOCKER-USER
sudo iptables -S SECCTL-DOCKER
sudo systemctl status docker
sudo ufw status numbered
```

预期 DOCKER-USER 的第一条规则跳转 SECCTL-DOCKER，链中存在 UFW 转发授权和对 docker0/br-* 新入站流量的 DROP。容器出站 DNS/HTTP、已建立连接以及现有非 secctl 防火墙规则应保持可用。修改默认网桥名、IPv6 容器或原生 nftables 的环境不在本版本支持范围。

SSH 确认完成前不要重启整机；systemd 临时回滚定时器不跨整机重启。原生 iptables 后端的宿主机规则也不自动持久化。

## SSH 服务生命周期 CI

`scripts/test-ssh-integration.sh` 在明确设置 `SECCTL_TEST_DISPOSABLE_VM=1` 的空白虚拟机上，使用临时 root 公钥验证 22 → 22022 → 22 的真实登录和 confirm，保留切换前已连接的 SSH 会话，并验证超时、SIGINT、SIGHUP 恢复监听。CI 分别在 Ubuntu 26.04 socket 模式和 Ubuntu 22.04 普通服务模式执行；测试会修改 root authorized_keys 和 SSH 主配置，结束后恢复。

该脚本要求初始 SSH 22 已允许 root 公钥登录，不适合为了测试去放宽已有服务器的认证策略。真实服务器请使用上方发布版验收文档，选择实际登录账号。
