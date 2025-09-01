<div align="center">

# xray-knife 🔪

**The Ultimate Swiss Army Knife for Xray and Sing-box**

A powerful command-line utility and secure web UI designed for managing, testing, and utilizing proxy configurations with dual-core support for both `xray-core` and `sing-box`.

</div>

<p align="center">
  <img src="https://img.shields.io/github/v/release/lilendian0x00/xray-knife?style=for-the-badge" alt="Release Version">
  <img src="https://img.shields.io/github/actions/workflow/status/lilendian0x00/xray-knife/build.yaml?branch=master&style=for-the-badge" alt="Build Status">
  <img src="https://img.shields.io/github/go-mod/go-version/lilendian0x00/xray-knife?style=for-the-badge" alt="Go Version">
  <img src="https://img.shields.io/github/license/lilendian0x00/xray-knife?style=for-the-badge" alt="License">
</p>

---

`xray-knife` is a versatile multi-tool that streamlines the process of working with proxy configurations. With its persistent database, it serves as a central hub for all your proxy needs, from managing subscription links to finding the fastest and most reliable connections.

## ✨ Key Features

- **🛡️ Secure Web UI**: Manage all features through an intuitive, browser-based interface protected by secure JWT authentication. On first run, it automatically generates a `root` user with a secure random password.

- **🗄️ Centralized Database**: All data, including subscription links, configurations, and scan results, is now stored in a persistent SQLite database (`~/.xray-knife/xray-knife.db`).

- **📚 Full Subscription Management**: A new `subs` command allows you to add, fetch, list, and remove subscription links, populating your central configuration library.

- **🚀 Dual-Core Engine**: Seamlessly works with both `xray-core` and `sing-box`, automatically selecting the right core for each configuration type (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, etc.).

- **🔬 Advanced Proxy Tester**: Concurrently test hundreds of configs for real latency, speed, and IP location. Test from a file or pull directly from your database using powerful filters.

- **🔄 Auto-Rotating Proxy**: Run a local SOCKS/HTTP proxy that automatically finds the fastest, working outbound from your database and rotates it on a schedule or on-demand.

- **🌐 Powerful IP Scanner**: Discover optimal Cloudflare edge IPs by scanning entire CIDR ranges for latency and speed. Results are saved to the database for future use.

- **🔎 Universal Config Parser**: Decode any configuration link into a human-readable breakdown or generate a full, clean `xray-core` compatible JSON file.

## 📦 Installation

### From GitHub Releases (Recommended)

You can download the latest pre-compiled binary for your operating system from the [**GitHub Releases**](https://github.com/lilendian0x00/xray-knife/releases) page.

**Example for Linux:**
```bash
wget https://github.com/lilendian0x00/xray-knife/releases/latest/download/Xray-knife-linux-64.zip
unzip Xray-knife-linux.zip
cd Xray-knife-linux
chmod +x xray-knife
./xray-knife --help
```

### Using `go install`

If you have Go (1.25) installed, you can build and install `xray-knife` with a single command:
```bash
go install github.com/lilendian0x00/xray-knife/v7@latest
```

### Arch linux aur
you can find package in [AUR](https://aur.archlinux.org/packages/xray-knife-bin) or use command bellow te get the latest version on Arch linux
```bash
yay -S xray-knife-bin ||
paru -S xray-knife-bin ||
pikaur -S xray-knife-bin
```

## 🛠️ Usage

`xray-knife` is a command-line tool with a clear and consistent command structure:
`xray-knife [command] [flags]`

Here are some practical examples for the main commands.

---

### 🖥️ Using the Web UI (`webui`)

Launch a local web server to access all of `xray-knife`'s features through a modern, secure graphical user interface.

**1. Start the Web UI Server (First Run)**
On its first run, `xray-knife` will automatically generate secure credentials and save them to `~/.xray-knife/webui.conf`. The password will be printed to the console.

```bash
xray-knife webui
```
*Console Output on first run:*
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
Open `http://127.0.0.1:8080` in your browser and log in with the generated credentials.

**2. Run with Custom Credentials**
You can override the config file using flags or environment variables. This is useful for server deployments.
```bash
xray-knife webui --auth.user myadmin --auth.password 's3cur3p@ss' --auth.secret 'a_very_long_and_random_string'
```
> For more details on credential priority, see the `xray-knife webui --help` command.

---

### 📚 Managing Subscriptions (`subs`)

Build your central configuration library using subscription links.

**1. Add and Fetch Subscriptions**
```bash
# Add a subscription with a custom name
xray-knife subs add --url "YOUR_SUBSCRIPTION_URL" --remark "My Subs"

# List all your subscriptions
xray-knife subs show

# Fetch all configs from the subscription with ID 1
xray-knife subs fetch --id 1
```

---

### 🧪 Testing Configs (`http`)

Test proxy configurations for latency, speed, and more.

**1. Test**
This is the new, powerful way to test configs. It pulls directly from the library you built with the `subs` command.

```bash
# Test configs from a file, with a speed test
xray-knife http -f ./configs.txt --speedtest

# Test up to 100 'vless' configs from your database, with a speed test
xray-knife http --from-db --limit 100 --protocol vless --speedtest

# Test all configs belonging to subscription ID 1
xray-knife http --from-db --sub-id 1
```

**2. List Results**
View a summary of the results from the most recent test run.
```bash
xray-knife http list-results --limit 20
```

---

### 🔄 Auto-Rotating Proxy (`proxy`)

Run a local proxy that intelligently manages and rotates your outbound connections.

**1. Run a Rotating SOCKS5 Proxy from the Database**
Start a local SOCKS5 proxy on port `9999`. It will load all enabled configs from your database and automatically rotate to the best-performing one every 5 minutes (300 seconds).

```bash
# Proxy to configs from a file
xray-knife proxy --inbound socks -f ./configs.txt --port 9999 --rotate 300

# Proxy to configs from your database
xray-knife proxy --inbound socks --port 9999 --rotate 300
```
> **Pro Tip:** While the proxy is running, simply press `Enter` in the terminal to force an immediate rotation to the next available fast configuration.

---

### 🌐 Scanning for Cloudflare IPs (`cfscanner`)

Find the fastest Cloudflare edge IPs for your location. Results are automatically saved to the database.

**1. Scan Subnets with a Speed Test**
Scan subnets from a file, perform a speed test on the top 10 fastest IPs, and save results.
```bash
xray-knife cfscanner -s subnets.txt --speedtest --speedtest-top 10
```

**2. Resume and View Results**
```bash
# Continue a previous scan, skipping already tested IPs
xray-knife cfscanner -s subnets.txt --resume

# View the best IPs from all previous scans, sorted by performance
xray-knife cfscanner list-results --limit 25
```

---

### 🔎 Parsing a Config Link (`parse`)

Decode and inspect any configuration link.

**1. Get a Human-Readable Breakdown**
Display a detailed summary of a configuration link.
```bash
xray-knife parse -c "trojan://..."
```

**2. Generate Full JSON Config**
Generate a complete, clean, and ready-to-use `xray-core` compatible JSON configuration.
```bash
xray-knife parse -c "vless://..." --json > my_config.json
```

---

## 🏗️ Build from Source

To build `xray-knife` from the source code, clone the repository and build the main package.

```bash
git clone https://github.com/lilendian0x00/xray-knife.git
cd xray-knife

# Build for all supported platforms (Linux, Windows, macOS)
./build.sh all

# Or build for your current platform
go build -o xray-knife .
```
The compiled binary will be placed in `build` or the current directory based on your choice.

## 🤝 Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue. If you'd like to contribute code, please open a pull request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.