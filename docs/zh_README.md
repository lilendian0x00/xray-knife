<div align="center">

# xray-knife 🔪

**Xray 和 Sing-box 的瑞士军刀**

一款功能强大的命令行工具，自带安全可靠的WebUI，专为管理、测试和使用代理而设计，并支持 `xray-core` 和 `sing-box` 这两款核心。

</div>

<p align="center">
  <img src="https://img.shields.io/github/v/release/lilendian0x00/xray-knife?style=for-the-badge" alt="Release Version">
  <img src="https://img.shields.io/github/actions/workflow/status/lilendian0x00/xray-knife/build.yaml?branch=master&style=for-the-badge" alt="Build Status">
  <img src="https://img.shields.io/github/go-mod/go-version/lilendian0x00/xray-knife?style=for-the-badge" alt="Go Version">
  <img src="https://img.shields.io/github/license/lilendian0x00/xray-knife?style=for-the-badge" alt="License">
</p>

---

[English](https://github.com/lilendian0x00/xray-knife/blob/master/README.md) [**简体中文**](https://github.com/lilendian0x00/xray-knife/blob/master/docs/zh_README.md)

`xray-knife` 是一款功能强大的多功能工具，可以简化代理配置流程。凭借其持久性数据库，它可以成为您所有代理需求的中心枢纽，从管理订阅链接到查找最快速、最可靠的连接，都能轻松搞定。

## ✨ 核心功能

- **🛡️ Secure Web UI**: 所有功能均可通过直观的浏览器界面进行管理，并由安全的 JWT 身份验证机制提供保护。首次运行时，系统会自动生成一个密码随机的名为 `root` 的用户。

- **🗄️ 持久化存储**: 所有数据，包括订阅链接、配置信息和扫描结果，都存储在持久化的 SQLite 数据库中。 (`~/.xray-knife/xray-knife.db`).

- **📚 完整的订阅管理**: `subs` 命令可以添加、获取、列出和删除订阅链接。

- **🚀 双内核支持**: 无缝使用 `xray-core` 和 `sing-box`, 根据代理协议可自动选择正确的内核。 (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, etc.)

- **🔬 多线程支持**: 同时测出数百代理的真延迟、速度和落地位置。你可以从文件中导入配置进行测试，也可以使用强大的筛选器直接从数据库中提取数据进行测试。

- **🔄 Failover 支持**: 运行一个本地 SOCKS/HTTP 代理，该代理会自动从您的数据库中找到速度最快且可用的出站代理，并定时或按需进行轮换。

- **🌐 CF 优选**: 扫描整个CIDR地址段，发现最佳的 Cloudflare IP，并根据延迟和速度进行评估。结果将保存到数据库中以供将来使用。

- **🔎 解析多种代理分享链接**: 将任何配置链接解码，生成完整、简洁且与 `xray-core` 兼容的 JSON 文件。

## 📦 安装

### 从 GitHub Releases

你可以从 [**GitHub Releases**](https://github.com/lilendian0x00/xray-knife/releases) 下载适用于您操作系统的最新预编译二进制文件。

**Linux:**
```bash
wget https://github.com/lilendian0x00/xray-knife/releases/latest/download/Xray-knife-linux-64.zip
unzip Xray-knife*.zip
cd Xray-knife-linux
chmod +x xray-knife
./xray-knife --help
```

### 或使用 `go install`

如果你装了 Go (1.25), 你也可以通过以下命令一键安装 `xray-knife`:
```bash
go install github.com/lilendian0x00/xray-knife/v9@latest
```

### Arch linux aur
你可以手动从 [AUR](https://aur.archlinux.org/packages/xray-knife-bin) 或使用以下命令行下载:
```bash
yay -S xray-knife-bin ||
paru -S xray-knife-bin ||
pikaur -S xray-knife-bin
```

## 🛠️ 使用

`xray-knife` 遵从严格的命令顺序: `xray-knife [command] [flags]`

### 🖥️ 启动 Web UI (`webui`)

在本地启动一个服务器，在浏览器中通过 Web UI 访问 `xray-knife` 的所有功能。

**1. 启动 Web UI 服务器 (首次运行)**

首次运行时, `xray-knife` 会自动生成用户名密码，在 SSH / Console 中显示，并自动保存至 `~/.xray-knife/webui.conf`。

```bash
xray-knife webui
```
*首次运行 Console 示例输出:*
```
...
[ℹ️] Generating new credentials for Web UI...
[✅] Credentials saved to /home/user/.xray-knife/webui.conf
[+] Starting Web UI server on http://127.0.0.1:8080

--- Please use the following credentials to log in ---
Username: root
Password: a_very_secure_random_password
-----------------------------------------------------

[i] Press CTRL+C to stop the server.
```
你可以在浏览器中打开 `http://127.0.0.1:8080` 并登入。

**2. 改用手动用户名或密码**

你可以使用命令行参数或环境变量来覆盖配置文件中的设置。通常用于服务器部署。
```bash
xray-knife webui --auth.user myadmin --auth.password 's3cur3p@ss' --auth.secret 'a_very_long_and_random_string'
```
> 关于凭据优先级，你可以通过 `xray-knife webui --help` 查看。

---

### 📚 管理订阅 (`subs`)

**1. 导入订阅**
```bash
# 添加一个名为 My Subs 的订阅
xray-knife subs add --url "YOUR_SUBSCRIPTION_URL" --remark "My Subs"

# 列出所有订阅
xray-knife subs show

# 列出订阅 ID 为 1 的所有代理
xray-knife subs fetch --id 1
```

---

### 🧪 测试代理 (`http`)

**1. 基于 HTTP 真延迟的代理测试**

如题，它也可以直接从你使用 `subs` 命令添加的订阅中提取并测试代理。

```bash
# 从文件中导入代理并测速
xray-knife http -f ./configs.txt --speedtest

# 从代理库中提取 100 个 VLESS 代理，并测速。
xray-knife http --from-db --limit 100 --protocol vless --speedtest

# 测试订阅 ID 1 的所有代理
xray-knife http --from-db --sub-id 1
```

**2. 列出测试结果**
列出上次代理测试的概要。
```bash
xray-knife http list-results --limit 20
```

---

### 🔄 自动轮换代理 (`proxy`)

**1. 监听一个 HTTP 或 SOCKS5 代理，自动轮换出口至表现最好的代理。**
监听一个 `9999` SOCKS 5 端口，从代理库中加载所有已启用的代理，并每 5 分钟（300 秒）自动切换到最佳的代理。 

```bash
# 从文件导入
xray-knife proxy --inbound socks -f ./configs.txt --port 9999 --rotate 300

# 从程序自带的 SQLite 数据库中导入
xray-knife proxy --inbound socks --port 9999 --rotate 300
```
> **提醒:** 其运行时如果你在 SSH / Console 中 `Enter` 将强制立即切换到当前最快的出口。

---

### 🌐 CF (Cloudflare) 优选 (`cfscanner`)

**1. 扫描 CIDR(s) 并测速**

从文件中导入 CIDR(s) 并测速，然后导出前十最快的 IP。
```bash
xray-knife cfscanner -s subnets.txt --speedtest --speedtest-top 10
```

**2. 恢复进度**
```bash
# 继续上次中断的扫描
xray-knife cfscanner -s subnets.txt --resume

# 列出以往所有扫描结果并筛选出前 25 个表现最好的 IP
xray-knife cfscanner list-results --limit 25
```

---

### 🔎 解析一个分享链接 (`parse`)

**1. 解析分享链接并给出概要**
```bash
xray-knife parse -c "trojan://..."
```

**2. 解析分享链接并生成 json 格式的出口配置**
```bash
xray-knife parse -c "vless://..." --json > my_config.json
```

---

## 🏗️ 从源码编译

```bash
git clone https://github.com/lilendian0x00/xray-knife.git
cd xray-knife

# 编译所有支持的平台和架构 (Linux, Windows, macOS)
./build.sh all

# 只编译当前平台
go build -o xray-knife .
```
编译出来的二进制文件将会默认保存至 `build` 目录。

## 🤝 贡献

欢迎对此项目开 PR 做出贡献，如果有任何问题或建议请创建 issue 。

## 📄 开源许可

这个项目使用 [MIT LICENSE](LICENSE) 。
