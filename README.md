# xray-knife
Swiss army knife tool for xray-core

## Features (main flags)
- `parse`: Detailed info about xray config link.
- `subs`: Subscription management tool.
- `net`: Multiple network testing tool for one or multiple xray configs.
- `bot`: Automation bot for switching outbound connection automatically.


# Build instruction
only tested on go version 1.20.2
0. `Install golang`
1. `git clone https://github.com/lilendian0x00/xray-knife.git`
2. `cd xray-knife`
3. `go build .`
    

# TODO
## parse
- [X] Completed
## subs
- [ ] Sort configs based on their real delay when saving them into a file
- [ ] Database for managing subscriptions
## net
- [ ] Complete `tcp` command
## bot (under development)
- [ ] Initialization