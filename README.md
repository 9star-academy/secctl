# secctl

<p align="center">
  <b>一行命令搞定 Linux 裸机安全加固与防火墙管理</b><br>
  防失联 SSH 硬化、语义化端口管控、一键修复 Docker 绕过防火墙直接暴露公网端口的经典大坑。
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

## 核心特性

- **防失联 SSH 一键加固**：支持从 GitHub 账号或本地公钥一键注入 SSH Key、修改 SSH 端口、禁用密码登录；内置**连接确认回滚机制**（若新配置未在 60 秒内确认连通，自动恢复原配置，绝不锁死自己）。
- **Docker 防火墙防泄漏修复**：一键修复 Docker 绕过 `ufw` / `nftables` 的问题，确保容器端口同样受控于统一防火墙规则。
- **透明的公网暴露面审计**：`secctl audit` 一眼看清当前机器所有监听在 `0.0.0.0` 的端口、对应进程 PID/服务名，以及防火墙实际放行状态。
- **轻量防爆破保护**：无需复杂配置即可开启 SSH 恶意 IP 自动封禁与白名单管理。

## 快速开始

### 1. 安装

```bash
curl -fsSL https://raw.githubusercontent.com/9star-academy/secctl/main/install.sh | sudo bash
```

### 2. 常用命令示例

```bash
# 1. 安全审计：查看当前服务器暴露在公网的所有端口、所属进程及安全隐患评分
sudo secctl audit

# 2. SSH 一键加固：拉取 GitHub 用户的公钥、改端口为 22022、禁用密码登录（带 60s 防失联自动回滚）
sudo secctl ssh harden --github reedtang666 --port 22022 --disable-password

# 3. 修复 Docker 绕过防火墙直接暴露公网端口的漏洞
sudo secctl docker-shield enable

# 4. 直观的端口开放与关闭（支持单个端口、端口段、指定来源 IP）
sudo secctl allow 80,443/tcp
sudo secctl allow 5432/tcp --from 10.0.0.0/8 --comment "内网数据库访问"
sudo secctl deny 8080/tcp

# 5. 查看当前防火墙规则与被封禁的恶意爆破 IP
sudo secctl status
```

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
