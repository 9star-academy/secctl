# secctl

<p align="center">
  <b>一行命令搞定 Linux 裸机安全加固与防火墙管理</b><br>
  SSH 加固与独立回滚、端口规则管理、UFW 下的 Docker IPv4 bridge 访问控制。
</p>

<p align="center">
  <a href="https://github.com/9star-academy/secctl/releases"><img src="https://img.shields.io/github/v/release/9star-academy/secctl?style=flat-square" alt="Release"></a>
  <a href="https://github.com/9star-academy/secctl/blob/main/LICENSE"><img src="https://img.shields.io/github/license/9star-academy/secctl?style=flat-square" alt="License"></a>
</p>

---

## 为什么做 secctl？

新买一台云服务器，跑完 [`ShellReady`](https://github.com/9star-academy/ShellReady) 配好顺手的终端后，往往马上要面对三大安全痛点：
1. **公网暴力扫描**：默认 22 端口每秒都在被肉鸡字典爆破，手改 `sshd_config` 稍有不慎就把自己锁在服务器外面。
2. **Docker 端口裸奔陷阱**：很多开发者不知道 `docker run -p 5432:5432` 会直接修改 `iptables`，**完全绕过 `ufw` 防火墙**，导致数据库在不知情下对全网开放。
3. **防火墙状态散乱**：搞不清机器上到底有哪些端口真正暴露在公网、是由哪个进程监听的。

**`secctl` 提供了一套人类友好、带防失联保护的服务器安全加固 CLI。**

## 当前功能与边界

- **SSH 加固**：GitHub / 本地公钥导入、修改端口、禁用密码登录。先用 `sshd -t/-T` 校验，再由 systemd 独立定时器提供回滚；默认 60 秒内输入 `confirm` 确认。终端退出不会取消定时器。原配置备份会保留。
- **防火墙**：使用已启用的 UFW，或原生 iptables。缺少后端、UFW 未启用或命令执行失败时返回非零退出码。同一访问元组的旧 UFW 决策会先删除再插入首位，不同来源或接口规则会保留；`deny` 影响新连接，已有连接可能受系统连接跟踪规则放行。
- **Docker Shield**：支持 Linux systemd、已启用 UFW（`MANAGE_BUILTINS=no`）、Docker iptables 后端的 IPv4 bridge 网络。使用独立 `SECCTL-DOCKER` 链；未显式放行的外部新连接被拒绝，保留已建立连接和容器出站流量。通过 UFW after.rules 和 Docker systemd drop-in 在重启时恢复。
- **监听与配置审计**：列出监听端口、进程和基础风险提示，检查可读取的 SSH 实际配置及防火墙状态。非回环监听不代表公网一定可达，评分不替代外部连接验证。

自动 IP 封禁、白名单管理、Docker 原生 nftables 后端和 IPv6 容器网络尚不支持。原生 iptables 后端仅管理 IPv4 内存规则，重启持久化由系统管理员配置；推荐使用 UFW。macOS 仅提供监听审计，防火墙状态显示为未知。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/9star-academy/secctl/main/scripts/install.sh | sudo bash
```

安装器校验发布包的 `SHA256SUMS`；没有校验文件的旧发布版本会拒绝安装。可通过 `SECCTL_VERSION=vX.Y.Z` 固定已发布版本。本地源码修复须发布新版本后才能通过安装器获取。

本地构建：

```bash
go build -o secctl ./cmd/secctl
./secctl --help
```

## 使用

先保留当前 SSH 连接和云平台控制台入口，确认云安全组也允许目标端口。UFW 未启用时，请先手动保留当前 SSH 端口规则再启用，secctl 不会自动启用全局防火墙。

```bash
sudo secctl audit
sudo secctl status

# --user 是目标系统账号；sudo 默认仍是 root，普通账号请显式指定。
sudo secctl ssh harden --user ubuntu --github reedtang666 --port 22022 --disable-password
# 或使用本地公钥
sudo secctl ssh harden --user ubuntu --key ./id_ed25519.pub --disable-password
# 立即另开终端确认能登录，然后在原终端输入 confirm。

# 宿主机端口：可带端口段、协议、来源和备注。
sudo secctl allow 80,443/tcp
sudo secctl allow 8000-8010/tcp --from 10.0.0.0/8
sudo secctl deny 8080/tcp

# Docker Shield 开启后，使用独立的转发规则管理容器端口。
sudo secctl docker-shield enable
sudo secctl docker-shield status
# 假设映射为 -p 15432:5432，这里填写容器端口 5432。
sudo secctl allow 5432/tcp --docker --from 10.0.0.0/8 --comment "内网数据库"
sudo secctl deny 5432/tcp --docker
sudo secctl docker-shield disable
```

SSH 自动加固会拒绝 `Match` 条件块（包括 Include 中的 Match），避免改变条件认证策略；带引号、转义或动态标记的 Include，以及 Include 中的额外 Port 也会停止，要求先手工整理。使用自定义 AuthorizedKeysFile、证书或动态公钥命令的环境，应手动加固。端口切换会核对 `sshd` 的新监听端口；socket 激活环境若未切换监听，会恢复原配置并报错。`--skip-confirm` 会立即确认配置，仅适用于已验证的自动化环境。

回滚状态位于 `/etc/ssh/sshd_config.secctl.pending/`，日志可通过输出的 `secctl-rollback-*.service` 查看。回滚失败会保留状态和原配置，并由 systemd 重试；应从云控制台检查。定时器是临时 systemd 单元，不能跨整机重启保证回滚；确认操作前不要重启服务器。SSH 端口的新增放行规则会保留，不自动删除已有规则。

Docker Shield 当前针对默认 `docker0` 和 `br-*` 网桥；自定义网桥名称、host/macvlan/overlay、IPv6 容器及原生 nftables 不在保护范围。UFW 的转发 ALLOW 是授权来源；已有宽泛转发放行规则仍会放行，应先检查 `ufw status numbered`。禁用 Shield 会恢复 Docker 默认转发行为，容器发布端口可能重新对外可达。

## 验证

```bash
go test -race -coverprofile=coverage.out ./...
go vet ./...
bash -n scripts/install.sh scripts/test-linux-integration.sh
```

真实连接、Docker 重启和 SSH 挂断回滚请在无业务的 Linux 虚拟机验证，参见 [Linux 集成验收](docs/testing.md)。单元测试以隔离的配置文件和命令替身运行，不修改开发机的 SSH、防火墙或 Docker。

## 9star-academy 裸机轻量运维矩阵

| 工具 | 定位 |
| :--- | :--- |
| [**ShellReady**](https://github.com/9star-academy/ShellReady) | 一条命令配好新 Linux 服务器（BBR、trzsz、Starship、Atuin、zoxide） |
| [**secctl**](https://github.com/9star-academy/secctl) | 一行命令搞定裸机 SSH 加固、防火墙管理与 Docker 端口防泄漏 |
| [**servctl**](https://github.com/9star-academy/servctl) | 一行命令将任意可执行程序托管为 `systemd` 系统自启服务 |
| [**proxctl**](https://github.com/9star-academy/proxctl) | 一行命令搞定反向代理、静态站点托管与自动 HTTPS 证书 |
| [**bakctl**](https://github.com/9star-academy/bakctl) | 一行命令将数据库与目录定时加密备份至 S3 / R2 / OSS / WebDAV |

## License

MIT License
