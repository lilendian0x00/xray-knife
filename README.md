# 🔪 xray-knife
Swiss army knife tool (cli) for [xray-core](https://github.com/XTLS/Xray-core).

**I DEDICATE THIS TOOL TO MY DEAR PERSIAN PEOPLE.**

**استفاده از این نرم افزار برای حمایت کنندگان جمهوری اسلامی حرام است.**

## 🎯 The Goal
Since there was no existing program capable of directly checking xray-core config links in bulk, I took it upon myself to develop such a tool. I have now made it publicly available, enabling everyone to benefit from and enjoy its functionality. (`net http` command).
You can also benefit from other key features of this program, such as its rotating proxy functionality (`proxy` command).

You can view the flags of each command by using the `-h` or `--help` option.

## 🌟 Features (main commands)
- `parse`: Detailed info about given xray config link.
- `subs`: Subscription management tool.
- `net`: Network testing tools for one or multiple xray configs.
- `scan`: Scanning tools needed for bypassing GFW (CF Scanner, REALITY Scanner).
- `proxy`: Creates proxy server to work as a client for xray-core configs.

## 📦 Download

Get the latest version from [GitHub](https://github.com/lilendian0x00/xray-knife/releases/latest).

## 🏗️ Build instruction
Only works on golang version 1.21

1. `Install golang`
2. `git clone https://github.com/lilendian0x00/xray-knife.git`
3. `cd xray-knife`
4. `go build .`
    

# 🧪 Examples
### http test CSV report
<img src="./images/httpCSV.png" width="600" alt="sample1">

### http test log
<img src="./images/httpTest.png" width="1357" alt="sample2">

# 📋 TODO
## protocols - parse
- [X] ~~Add Vmess link support (`vmess://...`, full b64 encoded)~~
- [X] ~~Add Vmess link v2 support (`vmess://...`, semi b64 encoded)~~
- [X] ~~Add Vless link support (`vless://...`)~~
- [X] ~~Add Shadowsocks support (`ss://...`)~~
- [X] ~~Add Trojan support (`trojan://...`)~~
- [X] ~~Add Socks support (`socks://...`)~~
- [X] ~~Add Wireguard support (`wireguard://...`)~~
- [ ] Load config from json file

## subs
- [X] ~~Fetch config links inside subscription~~
- [X] ~~Sort config links based on their real delay test when saving them into a file~~

## net
- [X] ~~Add icmp (ping) tester~~
- [X] ~~Add tcp connection delay tester~~
- [X] ~~Add full connection delay (AKA real delay) tester~~
- [X] ~~Add speed tester for http~~

## proxy
- [X] ~~Added CLI client feature~~
- [X] ~~Option to switch outbound connection automatically based on passed parameter (E.g. interval, availability) (rotating proxy)~~

## scan (under development)
- [ ] Cloudflare white-list IP scanner

Verify (Lil Endian)