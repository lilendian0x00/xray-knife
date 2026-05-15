# v10.0.0 — Proxy CLI Cleanup (Breaking)

`xray-knife proxy` has been reshaped. One mode flag became four
subcommands. `host-tun` got a shorter name. Help output is no longer
a wall of flags.

## Quick migration

| Old | New |
|---|---|
| `xray-knife proxy` | `xray-knife proxy inbound` |
| `xray-knife proxy --mode inbound` | `xray-knife proxy inbound` |
| `xray-knife proxy --mode system` | `xray-knife proxy system` |
| `xray-knife proxy --mode app --shell` | `xray-knife proxy app --shell` |
| `xray-knife proxy --mode host-tun ...` | `xray-knife proxy tun ...` |
| `--host-tun-deadman` (etc.) | `--tun-deadman` (etc.) |

If you typed `--mode` in a script, swap it for the matching subcommand.
Drop the `host-` prefix from any tun flags.

## What changed

**Subcommands replace `--mode`.** Pick one: `inbound`, `system`, `app`, `tun`. Each shows only its own flags in `--help`.

**`host-tun` is now `tun`.** All `--host-tun-*` flags drop the `host-` prefix.

**Shared flags moved to the parent.** `--core`, `--config`, `--file`, `--stdin`, `--addr`, `--port`, `--verbose`, `--insecure` work before or after the subcommand name. Mode-specific flags must come after the subcommand.

**`--i-might-lose-ssh` is gone.** The deadman timer (`--tun-deadman`, 60s by default), the safe TUN CIDR (RFC 2544), and the default skip of LAN traffic already keep SSH alive. No typed acknowledgement needed.

**`--bind` is now required on `tun`.** Bad invocations get rejected at parse time, not after half the tunnel is up.

**Cleaner help.** `xray-knife proxy --help` no longer dumps 33 flags. Each subcommand's help is short and on-topic.

**Better empty-DB error.** Tells you both options: run `subs fetch`, or pass `--config / --file / --stdin`.

**Examples on every subcommand.** Real invocations, not just flag lists.
