<div align="center">

# xray-knife 🔪

**The Ultimate Swiss Army Knife for Xray and Sing-box**

A powerful command-line utility designed for testing, managing, and utilizing proxy configurations with dual-core support for both `xray-core` and `sing-box`.

</div>

<p align="center">
  <img src="https://img.shields.io/github/v/release/lilendian0x00/xray-knife?style=for-the-badge" alt="Release Version">
  <img src="https://img.shields.io/github/actions/workflow/status/lilendian0x00/xray-knife/build.yaml?branch=master&style=for-the-badge" alt="Build Status">
  <img src="https://img.shields.io/github/go-mod/go-version/lilendian0x00/xray-knife?style=for-the-badge" alt="Go Version">
  <img src="https://img.shields.io/github/license/lilendian0x00/xray-knife?style=for-the-badge" alt="License">
</p>

---

`xray-knife` is a versatile multi-tool that streamlines the process of working with proxy configurations. Whether you need to test a list of servers for latency and speed, run a local proxy that automatically rotates to the fastest outbound, or scan for optimal edge IPs, `xray-knife` provides a robust and efficient solution.

## ✨ Key Features

- **🚀 Dual-Core Engine**: Seamlessly works with both `xray-core` and `sing-box`, automatically selecting the right core for each configuration type (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, etc.).

- **🔬 Advanced Proxy Tester**: Concurrently test thousands of configs for real latency, download/upload speed, and real IP information. Output results in clean `txt` or `csv` formats.

- **🔄 Auto-Rotating Proxy**: Run a local SOCKS/HTTP proxy that automatically finds the fastest, working outbound from your list and rotates it on a schedule or on-demand.

- **🌐 Powerful IP Scanner**: Discover optimal Cloudflare edge IPs (or other providers) by scanning entire CIDR ranges for latency and speed, helping you find the best connection points.

- **🔎 Universal Config Parser**: Decode any configuration link into a human-readable breakdown or generate a full, clean `xray-core` compatible JSON file for debugging or manual use.

- **📚 Subscription Manager**: Fetch, update, and manage configurations from remote subscription links with a single command.

- **💻 Cross-Platform**: A single, dependency-free binary available for Linux, Windows, macOS, and Android.

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

If you have Go installed, you can build and install `xray-knife` with a single command:
```bash
go install github.com/lilendian0x00/xray-knife/v5@latest
```

## 🛠️ Usage

`xray-knife` is a command-line tool with a clear and consistent command structure:
`xray-knife [command] [flags]`

Here are some practical examples for the main commands.

---

### 🧪 Testing Configs (`http`)

Test a list of proxy configurations for latency, speed, and more.

**1. Basic Latency Test**
Test all configs from a file, using 50 concurrent threads, and save the working ones to `valid.txt`.
```bash
xray-knife http -f configs.txt -t 50 -o valid.txt
```

**2. Speed Test and CSV Output**
Perform a speed test, sort results by the fastest latency, and save a detailed report to a CSV file.
```bash
xray-knife http -f configs.txt --speedtest --sort --type csv -o results.csv
```

---

### 🔄 Auto-Rotating Proxy (`proxy`)

Run a local proxy that intelligently manages and rotates your outbound connections.

**1. Run a Rotating SOCKS5 Proxy**
Start a local SOCKS5 proxy on port `9999`. It will test configs from `configs.txt` and automatically rotate to the best-performing one every 5 minutes (300 seconds).
```bash
xray-knife proxy -f configs.txt --port 9999 --rotate 300
```
> **Pro Tip:** While the proxy is running, simply press `Enter` to force an immediate rotation to the next available fast configuration.

**2. Use a Single, Static Config**
Run the proxy using just one configuration link without rotation.
```bash
xray-knife proxy -c "vless://..." --port 9999
```

---

### 🌐 Scanning for Cloudflare IPs (`scan cfscanner`)

Find the fastest Cloudflare edge IPs for your location.

**1. Scan a Subnet with Speed Test**
Scan a CIDR subnet with 100 threads, including a speed test for each IP, and save the sorted results.
```bash
xray-knife scan cfscanner -s "104.16.0.0/16" -t 100 -p -o cf_results.txt
```

**2. Scan from a File with Live Output**
Scan multiple subnets from a file (`subnets.txt`) and save results to `live_results.txt` as they are found (unsorted), in addition to the final sorted file.
```bash
xray-knife scan cfscanner -s subnets.txt -t 200 -l live_results.txt -o final_results.txt
```

---

### 🔎 Parsing a Config Link (`parse`)

Decode and inspect any configuration link.

**1. Get a Human-Readable Breakdown**
Display a detailed, easy-to-read summary of a configuration link.
```bash
xray-knife parse -c "trojan://..."
```

**2. Generate Full JSON Config**
Generate a complete, clean, and ready-to-use `xray-core` compatible JSON configuration. This is perfect for debugging or use with other tools.
```bash
xray-knife parse -c "vless://..." --json > my_config.json
```

---

### 📚 Fetching Subscriptions (`subs fetch`)

Download and save all configurations from a subscription link.
```bash
xray-knife subs fetch -u "https://example.com/sub/link" -o my_configs.txt
```

## 🏗️ Build from Source

To build `xray-knife` from the source code, clone the repository and use the provided build script.

```bash
git clone https://github.com/lilendian0x00/xray-knife.git
cd xray-knife

# Build for all supported platforms (Linux, Windows, macOS)
./build.sh all

# Or build for your current platform
go build -o xray-knife main.go
```
The compiled binaries will be placed in the `build` directory.

## 🤝 Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue. If you'd like to contribute code, please open a pull request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.