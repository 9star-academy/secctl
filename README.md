<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme/logo-light.svg">
  <img src="docs/assets/readme/logo-light.svg" alt="secctl" width="288" height="90">
</picture>

<p><strong>把 SSH、端口与 Docker 访问规则管清楚。</strong></p>

<p>SSH 加固与回滚 · 防火墙规则管理 · Docker IPv4 bridge 防护</p>

<p>
  <a href="https://github.com/9star-academy/secctl/releases/tag/v1.0.2-rc.2"><img src="https://img.shields.io/badge/preview-v1.0.2--rc.2-0f766e?style=flat-square" alt="验收版本 v1.0.2-rc.2"></a>
  <a href="https://github.com/9star-academy/secctl/actions/workflows/ci.yml"><img src="https://github.com/9star-academy/secctl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/Go-1.24%2B-2563eb?style=flat-square" alt="Go 1.24+"></a>
  <a href="#支持范围"><img src="https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-475569?style=flat-square" alt="Linux amd64 / arm64"></a>
</p>

<p>
  <a href="#快速开始">快速开始</a> ·
  <a href="#ssh-加固">SSH 加固</a> ·
  <a href="#防火墙规则">防火墙规则</a> ·
  <a href="#docker-防护">Docker 防护</a> ·
  <a href="#验收与开发">验收与开发</a>
</p>

</div>

---

**secctl 是一个面向 Linux 服务器的安全管理命令行工具。** 查看谁在监听端口、调整访问规则、收紧 SSH 登录方式，并管理 Docker 发布端口的转发访问。

使用 Go 编写，无第三方 Go 依赖，单个二进制分发；服务器无需安装 Go。

## 能力概览

| 能力 | 用途 | 命令入口 |
| --- | --- | --- |
| 端口审计 | 监听端口、进程、PID 与基础风险提示 | `secctl audit` |
| SSH 加固 | 导入公钥、修改端口、禁用密码，未确认自动回滚 | `secctl ssh harden` |
| 端口规则 | 按端口、协议、来源设置放行或拒绝 | `secctl allow` / `deny` |
| Docker 防护 | 将 Docker IPv4 bridge 流量接入 UFW 转发授权 | `secctl docker-shield` |

## 快速开始

> [!NOTE]
> 本页使用已发布的 **v1.0.2-rc.2 验收版**。Ubuntu 26.04 的 `ssh.socket` 端口切换已纳入实机 CI；正式使用前，请按 [完整验收步骤](docs/acceptance-ubuntu-26.04.md) 验证自己的服务器。

在测试服务器安装或升级：

```bash
curl -fsSL https://raw.githubusercontent.com/9star-academy/secctl/v1.0.2-rc.2/scripts/install.sh \
  | sudo env SECCTL_VERSION=v1.0.2-rc.2 bash

secctl --version
```

预期显示 `secctl version v1.0.2-rc.2`。安装器自动识别系统与 CPU 架构，校验 `SHA256SUMS`，安装到 `/usr/local/bin/secctl`。

先看看服务器当前的状态：

```bash
sudo secctl audit
sudo secctl status
secctl --help
```

**审计展示的是监听与配置情况。** 某个端口监听在非回环地址上，不代表公网一定能访问；云安全组、路由和实际连接需要另外验证。

<details>
<summary>版本选择与安装说明</summary>

- 预发布版本需要显式设置 `SECCTL_VERSION`；不指定版本时，安装器选择 GitHub 的最新正式 Release。
- 安装器拒绝缺少校验文件或 SHA256 不匹配的发布包。
- 安装依赖 `curl` 和 `sha256sum`，或 macOS 的 `shasum`。Linux 加固功能还需要相应系统工具，见 [支持范围](#支持范围)。
- 源码推送到 `main` 不会更新已安装的二进制；需要安装对应的已发布版本。
- 查看 [发布记录](https://github.com/9star-academy/secctl/releases) 和 [rc.2 变更说明](docs/releases/v1.0.2-rc.2.md)。

</details>

## SSH 加固

修改 SSH 前，保留当前连接和云控制台入口，并确认云安全组允许目标端口。使用 UFW 时，先保留当前 SSH 端口的规则并启用 UFW；secctl 不会自动启用全局防火墙。

下面以已有系统账号 `ubuntu`、目标端口 `22022` 为例。把用户名换成自己的登录账号，公钥文件放在服务器当前目录：

```bash
sudo secctl ssh harden \
  --user ubuntu \
  --key ./id_ed25519.pub \
  --port 22022 \
  --disable-password \
  --timeout 180
```

也支持通过 `--github` 导入自己的 GitHub 公钥。先设置 `GITHUB_USER` 为你自己的账号，再执行：

```bash
GITHUB_USER='替换为你自己的GitHub用户名'
sudo secctl ssh harden --user ubuntu --github "$GITHUB_USER" --disable-password
```

`--user` 指定要配置公钥的系统账号；使用 `sudo` 时默认目标仍是 `root`，普通账号请显式指定。这里只上传 `.pub` 公钥，私钥保留在你自己的电脑。

**先验证，再确认：**

1. 保持原终端打开，从另一个终端用对应私钥连接新端口。
2. 确认能正常登录后，回到原终端输入 `confirm` 并回车。
3. 未确认、超时、中断或会话挂断时，独立 systemd 定时器负责恢复原配置与相应监听。

默认确认时间为 60 秒，上面的示例用 `--timeout 180` 留出验证时间。**确认完成前不要重启服务器**，临时回滚定时器不保证跨整机重启恢复。

<details>
<summary>配置兼容、备份与回滚细节</summary>

- 修改前使用 `sshd -t` / `sshd -T` 检查配置及实际生效结果。
- Ubuntu 26.04 的 `ssh.socket` 模式会刷新系统生成器并切换 socket 与服务，保留原启动方式。要求 `ssh.service` 使用 `KillMode=process`，以保留已有会话；固定 `ListenStream` 等自定义配置若未生成目标端口，会拒绝切换并恢复。
- `Match` 条件块、带引号/转义/动态标记的 Include，以及 Include 中冲突的额外 Port 会停止自动加固，需要先手工核对。
- 自定义 `AuthorizedKeysFile`、证书或动态公钥命令的认证环境，应手动加固。
- 原配置备份保留在 `/etc/ssh/sshd_config.secctl.bak.*`；回滚状态位于 `/etc/ssh/sshd_config.secctl.pending/`。
- 回滚失败会保留状态，并由 systemd 重试。可按命令输出的 `secctl-rollback-*.service` 名称查看日志，必要时从云控制台处理。
- 已导入的公钥和新 SSH 端口放行规则会保留，不随 SSH 配置回滚自动撤销。
- `--skip-confirm` 会立即确认配置，仅用于已经验证的自动化环境。

</details>

## 防火墙规则

推荐使用**已启用的 UFW**。也支持原生 iptables，具体限制见 [支持范围](#支持范围)。

```bash
# 开放 Web 端口
sudo secctl allow 80,443/tcp

# 仅允许指定网段访问端口范围
sudo secctl allow 8000-8010/tcp --from 10.0.0.0/8 --comment "内网服务"

# 开放 UDP 端口
sudo secctl allow 53/udp

# 拒绝端口的新连接
sudo secctl deny 8080/tcp

# 查看状态与规则
sudo secctl status
```

| 选项 | 用途 | 示例 |
| --- | --- | --- |
| `--from` | 限制来源 IP 或 CIDR 网段 | `--from 10.0.0.0/8` |
| `--comment` | 给规则添加备注 | `--comment "内网数据库"` |
| `--docker` | 管理 UFW 转发规则，填写容器端口 | `allow 5432/tcp --docker` |

同一端口、协议和来源的旧 UFW 决策会更新，其他来源或接口范围的规则保留。`deny` 针对新连接；已建立的连接可能继续被系统连接跟踪规则放行。

缺少真实防火墙后端、UFW 未激活或执行失败时，命令会返回非零退出码。

## Docker 防护

Docker 的发布端口会经过独立的转发规则。Docker Shield 使用 `SECCTL-DOCKER` 链，将支持范围内的流量交给 UFW 转发规则授权：**未获授权的外部新连接被拒绝**，保留已建立连接和容器出站流量。

启用前需要：

- Linux + systemd，已启用 UFW。
- `/etc/default/ufw` 中设置 `MANAGE_BUILTINS=no`。
- Docker 使用 iptables 后端，网络为默认 IPv4 bridge（`docker0` / `br-*`）。

先运行 `sudo ufw status numbered` 检查已有转发规则；已有宽泛的转发 ALLOW 仍然属于授权。

```bash
sudo secctl docker-shield enable
sudo secctl docker-shield status
```

假设容器已经通过 `-p 15432:5432` 发布 PostgreSQL，规则里填写**容器端口 `5432`**：

```bash
sudo secctl allow 5432/tcp --docker --from 10.0.0.0/8 --comment "内网数据库"
sudo secctl deny 5432/tcp --docker
```

规则通过 UFW 配置和 Docker systemd 启动挂接恢复，覆盖 UFW reload 与 Docker restart。整机重启后的外部访问结果请按 [验收文档](docs/acceptance-ubuntu-26.04.md) 实测。

停用防护：

```bash
sudo secctl docker-shield disable
```

停用后恢复 Docker 默认转发行为，容器发布端口可能重新对外可达。

## 支持范围

| 环境或能力 | 范围 |
| --- | --- |
| Linux 发布包 | amd64 / arm64；加固功能依赖系统已有工具 |
| SSH 加固 | OpenSSH + systemd；支持普通服务和上述 Ubuntu socket 模式 |
| UFW | 推荐后端；使用前需手动启用 |
| 原生 iptables | 仅 IPv4 内存规则，重启持久化由系统管理员配置 |
| Docker Shield | UFW + Docker iptables + 默认 IPv4 bridge |
| macOS 发布包 | amd64 / arm64；仅提供监听审计，防火墙状态显示为未知 |

自动 IP 封禁、独立白名单管理、Docker 原生 nftables 后端和 IPv6 容器尚未支持。自定义网桥名称、host / macvlan / overlay 不在 Docker Shield 保护范围。

## 验收与开发

**先在空白测试虚拟机验收，再用于实际服务器。**

- [Ubuntu 26.04 完整验收](docs/acceptance-ubuntu-26.04.md)：安装、端口放行/拒绝、SSH 登录与回滚、Docker、整机重启、清理恢复。
- [Linux 集成测试说明](docs/testing.md)：测试条件、脚本与验证边界。
- [GitHub Actions](https://github.com/9star-academy/secctl/actions/workflows/ci.yml)：Ubuntu 26.04 socket、Ubuntu 22.04 普通服务模式，以及 UFW/Docker 生命周期检查。

本地开发需要 Go 1.24+：

```bash
go build -o secctl ./cmd/secctl
./secctl --help

go test -race -coverprofile=coverage.out ./...
go vet ./...
bash -n scripts/install.sh scripts/test-linux-integration.sh scripts/test-ssh-integration.sh
bash scripts/test-install.sh
```

Go 单元测试使用隔离配置和命令替身，不修改开发机的 SSH、防火墙或 Docker。实机集成脚本会修改系统配置，只能在明确允许的空白测试虚拟机执行；实际网络和整机重启验收不能由单元测试替代。

## 相关工具

[9star-academy](https://github.com/9star-academy) 的轻量服务器工具：

| 工具 | 用途 |
| --- | --- |
| [ShellReady](https://github.com/9star-academy/ShellReady) | 服务器终端与常用环境初始化 |
| **secctl** | SSH 加固、防火墙规则与 Docker 转发防护 |
| [servctl](https://github.com/9star-academy/servctl) | 将可执行程序托管为 systemd 服务 |
| [proxctl](https://github.com/9star-academy/proxctl) | 反向代理、静态站点与自动 HTTPS |
| [bakctl](https://github.com/9star-academy/bakctl) | 目录、文件与数据库备份 |

## License

MIT License
