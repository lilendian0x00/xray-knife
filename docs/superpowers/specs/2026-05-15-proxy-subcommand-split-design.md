# Proxy CLI: Subcommand Split

**Date:** 2026-05-15
**Status:** Draft (awaiting approval)
**Owner:** lil
**Target release:** v10.0.0 (breaking change)

## Problem

`xray-knife proxy` exposes ~33 flags in a single flat namespace. Current invocation pattern:

```
xray-knife proxy --mode {inbound,system,app,host-tun} [flags]
```

Symptoms observed:

1. **Flag wall.** `xray-knife proxy --help` dumps all flags regardless of selected mode. Users see `--shell`, `--namespace` (only valid for `app`), `--host-tun-*` (only for `host-tun`), `--i-might-lose-ssh` (only for `host-tun`) on every invocation.
2. **Cross-mode validation lives at runtime.** `cmd/proxy/proxy.go:97-145` re-implements what cobra subcommands give for free: `--shell requires --mode app`, `--namespace requires --mode app`, `--mode host-tun requires --i-might-lose-ssh`, `--i-might-lose-ssh requires --mode host-tun`, etc.
3. **Dangerous flag undertagged.** `--i-might-lose-ssh` shows in default help like every other flag. No structural signal that `host-tun` mode is privileged and risky.
4. **Dead-end error.** `pkg/proxy/service.go:271` returns `"no configs found in the database. Use 'subs fetch' to populate it"` — half-actionable. Doesn't mention that `--config / --file / --stdin` would also satisfy.
5. **No examples.** Cobra's `Example:` field is unused on `proxy`. Users discover invocation patterns by reading flag descriptions.

## Goal

Replace the single `proxy` command with four mode-specific subcommands. Each subcommand exposes only flags relevant to its mode. Bundle small UX wins (better error messages, `Example:` blocks, automatic dangerous-flag scoping) into the same release.

## Non-goals

- Changing `pkg/proxy` API surface. `Config.Mode` field stays. The four subcommands each set `Mode` to their own name when constructing `Config`.
- Refactoring rotation/health/blacklist behavior. CLI shape only.
- Adding new modes or new functionality.
- Backward-compatibility shim for `--mode`. **Clean break** — old flag deleted.

## Design decisions (recorded)

| Decision | Choice | Rationale |
|---|---|---|
| Backwards compat for `--mode` | Clean break | Cleaner code, cleaner help. Major version bump signals breakage. |
| Bare `xray-knife proxy` (no subcommand) | Print help, exit 1 | Standard cobra parent behavior. Forces explicit choice. No accidental mode. |
| Shared-flag placement | Hybrid | Truly-universal persistent on parent; mode-tuning local per subcommand. |
| Scope of release | Bundled | Subcommand split + error-message hint + `Example:` blocks + dangerous-flag scoping. One PR. |
| `host-tun` subcommand name | `tun` | Shorter. Same applies to flag prefix: `--tun-*` (was `--host-tun-*`). |

## Command tree

```
xray-knife proxy                  # cobra prints help, exits 1
xray-knife proxy inbound  [flags] # local listener (current default mode)
xray-knife proxy system   [flags] # local listener + register OS system proxy
xray-knife proxy app      [flags] # per-process netns; supports --shell / --namespace
xray-knife proxy tun      [flags] # host-wide TUN capture; Linux only; dangerous over SSH
```

## Flag distribution

### Persistent on `proxy` parent (apply to all 4 subcommands)

| Flag | Short | Default | Notes |
|---|---|---|---|
| `--core` | `-z` | `xray` | xray, sing-box |
| `--config` | `-c` | — | Single config link |
| `--file` | `-f` | — | Read links from file |
| `--stdin` | `-i` | `false` | Read links from STDIN |
| `--addr` | `-a` | `127.0.0.1` | Listen address |
| `--port` | `-p` | `9999` | Listen port |
| `--verbose` | `-v` | `false` | Core verbose logging |
| `--insecure` | `-e` | `false` | Allow insecure TLS |

Mutual exclusion (set on parent via `MarkFlagsMutuallyExclusive`): `--config / --file / --stdin`.

### Common rotation block (helper `addRotationFlags`)

Registered on `inbound`, `system`, `app`, `tun` (all four — every mode rotates).

| Flag | Short | Default |
|---|---|---|
| `--rotate` | `-t` | `300` |
| `--mdelay` | `-d` | `3000` |
| `--batch` | `-b` | `0` |
| `--concurrency` | `-n` | `0` |
| `--health-check` | — | `30` |
| `--health-fail-threshold` | — | `0` |
| `--drain` | — | `0` |
| `--blacklist-strikes` | — | `3` |
| `--blacklist-duration` | — | `600` |

### Common chain block (helper `addChainFlags`)

Registered on `inbound`, `system`, `app`, `tun`.

| Flag | Default |
|---|---|
| `--chain` | `false` |
| `--chain-links` | — |
| `--chain-file` | — |
| `--chain-hops` | `2` |
| `--chain-rotation` | `none` |
| `--chain-attempts` | `0` |

Mutual exclusion: `--chain-links / --chain-file`.

### Common outbound network block (helper `addOutboundNetFlags`)

Registered on `inbound`, `system`, `app`, `tun`.

| Flag | Default |
|---|---|
| `--bind` | — |
| `--dns` | `1.1.1.1` |
| `--dns-type` | `udp` |

### `inbound`-only flags

| Flag | Short | Default |
|---|---|---|
| `--inbound` | `-j` | `socks` |
| `--inbound-config` | `-I` | — |
| `--transport` | `-u` | `tcp` |
| `--uuid` | `-g` | `random` |

Mutual exclusion: `--inbound-config / --inbound`.

### `system`-only flags

Identical set to `inbound`: `--inbound/-j`, `--inbound-config/-I`, `--transport/-u`, `--uuid/-g`, plus `MarkFlagsMutuallyExclusive("inbound-config", "inbound")`. System mode is inbound + OS-proxy registration; the registration logic lives in `pkg/proxy/sysproxy/` and is selected by `Config.Mode == "system"`.

### `app`-only flags

| Flag | Default |
|---|---|
| `--shell` | `false` |
| `--namespace` | — |

Mutual exclusion: `--shell / --namespace`.

`app` does NOT carry the inbound protocol flags (`--inbound/-j`, `--transport/-u`, `--uuid/-g`, `--inbound-config/-I`) — app mode binds SOCKS internally on `0.0.0.0:--port`. Common outbound-net flags (`--bind`, `--dns`, `--dns-type`) still apply via the shared helper.

### `tun`-only flags

| Flag | Default | Required? |
|---|---|---|
| `--i-might-lose-ssh` | `false` | **required** |
| `--bind` | — | **required** (overrides default; tun must pin physical NIC) |
| `--tun-deadman` | `60` | |
| `--tun-exclude` | — | |
| `--tun-name` | `xkt0` | |
| `--tun-addr` | `198.18.0.1/30` | |
| `--tun-mtu` | `1500` | |
| `--tun-include-private` | `false` | |

Required-flag enforcement via cobra `MarkFlagRequired` (replaces today's runtime check at `proxy.go:111-115`).

`tun` does NOT carry the inbound protocol flags (no inbound listener — TUN captures host-wide).

`--i-might-lose-ssh` only registered on `tun`. Cannot leak into other subcommands' help.

## Validation: what moves where

Today's runtime checks in `cmd/proxy/proxy.go:97-145` and where they go in the new layout:

| Old check | New location |
|---|---|
| `--shell requires --mode app` | Impossible by construction (only `app` declares `--shell`) |
| `--namespace requires --mode app` | Impossible by construction |
| `--shell and --namespace mutually exclusive` | `app.go`: `MarkFlagsMutuallyExclusive("shell", "namespace")` |
| `--mode host-tun requires --i-might-lose-ssh` | `tun.go`: `MarkFlagRequired("i-might-lose-ssh")` |
| `--mode host-tun requires --bind` | `tun.go`: `MarkFlagRequired("bind")` |
| `--i-might-lose-ssh requires --mode host-tun` | Impossible by construction |
| `--chain-rotation requires --chain` | Helper `validateChainFlags()` in `shared.go`; called by each subcommand RunE |
| `--chain requires explicit core type (not auto)` | Same helper. Note: parent's `--core` defaults to `xray`, never `auto`; check stays as defense in depth. |
| `--chain-rotation incompatible with fixed chains` | Same helper |
| `--inbound-config / --inbound` mutually exclusive | `inbound.go` and `system.go`: `MarkFlagsMutuallyExclusive("inbound-config", "inbound")` |
| `--config / --file / --stdin` mutually exclusive | Parent: `MarkFlagsMutuallyExclusive("config", "file", "stdin")` |

Net result: `cmd/proxy/proxy.go`'s 50-line validation block shrinks to a 5-line `validateChainFlags()` helper called by each subcommand.

## File layout

```
cmd/proxy/
  proxy.go        # ProxyCmd parent + persistent flags + addSubcommandPalettes() + init()
  inbound.go      # InboundCmd + flag registration + RunE
  system.go       # SystemCmd + flag registration + RunE
  app.go          # AppCmd + flag registration + RunE
  tun.go          # TunCmd + flag registration + RunE
  shared.go       # commonFlags struct, addRotationFlags, addChainFlags, addOutboundNetFlags, validateChainFlags, runService
```

`shared.go` provides:

- `parentFlags` — package-level struct bound to the parent's persistent flags inside `proxy.go`. Subcommands read its fields directly in their `RunE` (cobra has populated them by parse time).
- `rotationFlags`, `chainFlags`, `outboundNetFlags` — sub-config structs, one per subcommand.
- `addRotationFlags(cmd, *rotationFlags)` — binds the 9 rotation/health/blacklist flags.
- `addChainFlags(cmd, *chainFlags)` — binds the 6 chain flags + sets `MarkFlagsMutuallyExclusive("chain-links", "chain-file")`.
- `addOutboundNetFlags(cmd, *outboundNetFlags)` — binds `--bind`, `--dns`, `--dns-type`.
- `validateChainFlags(*chainFlags, coreType string) error` — runs the 3 chain-related checks (`--chain-rotation` requires `--chain`; `--chain` requires explicit core type; `--chain-rotation` incompatible with fixed chains).
- `runService(ctx, modeName string, links []string, parent *parentFlags, rot *rotationFlags, ch *chainFlags, net *outboundNetFlags, modeSpecific any) error` — assembles `pkgproxy.Config`, sets `Mode` to `modeName`, builds service, sets up signals (incl. `SIGHUP` for `tun`), starts manual rotation reader (skip when `app` + `--shell`), runs. `modeSpecific` is a tagged union (interface or per-mode struct switched on `modeName`) carrying e.g. `inboundFlags`, `appFlags`, `tunFlags`.

This mirrors the existing `cmd/subs/subs.go` pattern: parent var + `addSubcommandPalettes()` + `init()`.

## Error message + examples

### Error message change

`pkg/proxy/service.go:271`:

```diff
-return nil, errors.New("no configs found in the database. Use 'subs fetch' to populate it")
+return nil, errors.New("no configs in database. Run 'xray-knife subs fetch --all' to populate, or pass --config / --file / --stdin")
```

### `Example:` blocks

Every subcommand gets a populated `Example` field. Sample for `inbound`:

```
xray-knife proxy inbound                                # use DB pool, default port 9999
xray-knife proxy inbound -c "vless://..."               # one-shot single config
xray-knife proxy inbound -f configs.txt -t 60           # rotate every 60s from file
xray-knife proxy inbound --chain --chain-hops 3         # 3-hop chain from DB pool
```

Sample for `tun`:

```
sudo xray-knife proxy tun --bind eth0 --i-might-lose-ssh
sudo xray-knife proxy tun --bind eth0 --i-might-lose-ssh --tun-include-private
```

(Full `Example:` content for all four subcommands written during implementation.)

## Migration (breaking changes)

This is a **breaking change** to the CLI surface.

| Old | New |
|---|---|
| `xray-knife proxy --mode inbound` (or omitted) | `xray-knife proxy inbound` |
| `xray-knife proxy --mode system` | `xray-knife proxy system` |
| `xray-knife proxy --mode app --shell` | `xray-knife proxy app --shell` |
| `xray-knife proxy --mode host-tun --bind eth0 --i-might-lose-ssh` | `xray-knife proxy tun --bind eth0 --i-might-lose-ssh` |
| `--host-tun-deadman / --host-tun-exclude / --host-tun-name / --host-tun-addr / --host-tun-mtu / --host-tun-include-private` | `--tun-deadman / --tun-exclude / --tun-name / --tun-addr / --tun-mtu / --tun-include-private` |

Release vehicle: **v10.0.0**. Release notes must call out:

1. `--mode` flag removed; use subcommands.
2. `host-tun` renamed to `tun`; `--host-tun-*` flags renamed to `--tun-*`.
3. Persistent flags (`--addr`, `--port`, `--core`, etc.) may appear before OR after subcommand name.
4. Mode-local flags must appear after subcommand name.

`README.md` examples updated in same PR.

## Testing

`cmd/proxy/` currently has no tests. Plan adds `cmd/proxy/proxy_test.go` covering:

1. **Subcommand registration.** Each of `inbound/system/app/tun` is reachable from `ProxyCmd`.
2. **Flag scoping.** `--shell` exists only on `app`. `--i-might-lose-ssh`, `--tun-*` exist only on `tun`. `--inbound`, `--transport`, `--uuid`, `--inbound-config` exist only on `inbound` and `system`.
3. **Required-flag enforcement.** `xray-knife proxy tun` (no flags) errors with required-flag message; `xray-knife proxy tun --bind eth0` still errors (missing `--i-might-lose-ssh`).
4. **Mutual exclusion.** `--config + --file`, `--shell + --namespace`, `--inbound-config + --inbound`, `--chain-links + --chain-file` each rejected at parse time.
5. **Persistent-flag inheritance.** `xray-knife proxy --port 8080 inbound -c link://x` and `xray-knife proxy inbound --port 8080 -c link://x` both produce identical `pkgproxy.Config`.
6. **Chain validation.** `--chain-rotation full` without `--chain` errors. `--chain-rotation full` with `--chain-links` errors.

Manual smoke checklist (in PR description):

- [ ] `xray-knife proxy` → prints help, exits 1
- [ ] `xray-knife proxy inbound --help` → shows only inbound + persistent + rotation + chain + outbound-net flags; no `--shell`, no `--tun-*`, no `--i-might-lose-ssh`
- [ ] `xray-knife proxy app --help` → shows `--shell`, `--namespace`, no `--inbound`/`--transport`/`--uuid`
- [ ] `xray-knife proxy tun --help` → shows `--i-might-lose-ssh`, `--tun-*`; required flags marked
- [ ] `xray-knife proxy inbound -c <link>` runs end-to-end
- [ ] `xray-knife proxy app --shell -c <link>` runs end-to-end
- [ ] `xray-knife proxy tun --bind eth0 --i-might-lose-ssh -c <link>` runs end-to-end on Linux

## Out of scope (deferred)

- Renaming any other flags (e.g. `--mdelay` → `--max-delay`, `--rotate` → `--rotate-interval`).
- Refactoring `pkg/proxy/service.go` `Config` struct.
- Adding shell completion installer.
- Adding a `proxy status` introspection subcommand.
- Bumping any other CLI surface (parse, subs, http, net, cfscanner, webui).

## Risks

| Risk | Mitigation |
|---|---|
| Users with scripts pinned to `--mode X` break silently when upgrading | Major version bump (v10.0.0); release notes prominent; `xray-knife proxy --mode inbound` errors clearly with `unknown flag: --mode` (cobra default) |
| Users miss `host-tun` → `tun` rename | Same — release notes |
| Persistent vs local flag confusion ("why doesn't `--rotate` work before subcommand name?") | Document the rule in `README.md` proxy section; cobra's `--help` makes scope visible |
| Cobra inherited-flag display verbosity | Each subcommand's `--help` shows persistent flags under "Global Flags:" — acceptable, standard cobra UX |

## Open questions

None. All decisions captured in the table above.
