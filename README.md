# xray-knife
Swiss army knife tool (cli) for xray-core

## Features (main flags)
- `parse`: Detailed info about xray config link.
- `subs`: Subscription management tool.
- `net`: Multiple network testing tool for one or multiple xray configs.
- `bot`: Automation bot for switching outbound connection automatically.


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
- [ ] Add Shadowsocks support (`ss://...`)
- [ ] Add Trojan support (`trojan://...`)
## subs
- [X] ~~Sort configs based on their real delay when saving them into a file~~
- [ ] Database for managing subscriptions
## net
- [X] ~~Complete `tcp` command~~
## bot (under development)
- [ ] Initialization