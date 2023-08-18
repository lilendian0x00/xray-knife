# xray-knife
Swiss army knife tool (cli) for [xray-core](https://github.com/XTLS/Xray-core).

**I DEDICATE THIS TOOL TO MY DEAR PERSIAN PEOPLE.**

## Features (main flags)
- `parse`: Detailed info about given xray config link.
- `subs`: Subscription management tool.
- `net`: Network testing tools for one or multiple xray configs.
- `scan`: Scanning tools needed for bypassing GFW (CF Scanner, REALITY Scanner)
- `bot`: Automation bot for switching outbound connection automatically.

## Download

Get the latest version from [GitHub](https://github.com/lilendian0x00/xray-knife/releases/latest).

# Build instruction
Only tested on go version 1.20.2

1. `Install golang`
2. `git clone https://github.com/lilendian0x00/xray-knife.git`
3. `cd xray-knife`
4. `go build .`
    

# TODO
## parse
- [X] ~~Add Vmess link support (`vmess://...`, full b64 encoded)~~
- [X] ~~Add Vmess link v2 support (`vmess://...`, semi b64 encoded)~~
- [X] ~~Add Vless link support (`vless://...`)~~
- [X] ~~Add Shadowsocks support (`ss://...`)~~
- [ ] Add Trojan support (`trojan://...`)

## subs
- [X] ~~Fetch config links inside subscription~~
- [X] ~~Sort config links based on their real delay test when saving them into a file~~
- [ ] Database for managing subscriptions

## net
- [X] ~~Add icmp (ping) tester~~
- [X] ~~Add tcp connection delay tester~~
- [X] ~~Add full connection delay (AKA real delay) tester~~

## scan (under development)
- [ ] Cloudflare best IP finder (whitelist scanner)
- [ ] Xray REALITY scanner (TLS, H2)

## bot (under development)
- [ ] Initialization

