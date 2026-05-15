# v10.0.0 — Proxy CLI restructure (BREAKING)

The `proxy` command has been split into four mode-specific subcommands.
The `--mode` flag is gone, `host-tun` is renamed to `tun`, and the
`--host-tun-*` flags are renamed to `--tun-*`.

## Breaking changes

### `--mode` removed; use subcommands

| Old | New |
|---|---|
| `xray-knife proxy` (defaulted to inbound) | `xray-knife proxy inbound` |
| `xray-knife proxy --mode inbound` | `xray-knife proxy inbound` |
| `xray-knife proxy --mode system` | `xray-knife proxy system` |
| `xray-knife proxy --mode app --shell` | `xray-knife proxy app --shell` |
| `xray-knife proxy --mode host-tun ...` | `xray-knife proxy tun ...` |

### `host-tun` renamed to `tun`; flag prefix renamed

| Old flag | New flag |
|---|---|
| `--host-tun-deadman` | `--tun-deadman` |
| `--host-tun-exclude` | `--tun-exclude` |
| `--host-tun-name` | `--tun-name` |
| `--host-tun-addr` | `--tun-addr` |
| `--host-tun-mtu` | `--tun-mtu` |
| `--host-tun-include-private` | `--tun-include-private` |

### Persistent flags

`--core`, `--config`, `--file`, `--stdin`, `--addr`, `--port`,
`--verbose`, `--insecure` are now persistent on the `proxy` parent.
They may appear before or after the subcommand name. Mode-specific
flags must appear after the subcommand name.

## UX improvements

- `xray-knife proxy --help` and per-subcommand `--help` now show only
  the relevant flag set. The 33-flag wall is gone.
- `--shell` / `--namespace` are visible only on `proxy app`.
- `--tun-*` flags are visible only on `proxy tun`.
- `--bind` is now marked required on `tun`, so cobra rejects bad
  invocations at parse time instead of failing inside the service
  after partial setup.
- The `--i-might-lose-ssh` acknowledgement flag has been removed.
  The deadman switch (`--tun-deadman`, 60s default), the RFC 2544
  default TUN CIDR (198.18.0.0/15), and the default exclusion of
  RFC1918 private ranges together provide sufficient SSH-safety
  without requiring a typed acknowledgement.
- The "no configs in database" error now hints at both `subs fetch`
  AND `--config / --file / --stdin`.
- Each subcommand has an `Examples:` block.

## Migration

Update any scripts or systemd units that invoke `xray-knife proxy
--mode X` to use the subcommand form. The old `--mode` flag now
produces a clear `unknown flag: --mode` error.
