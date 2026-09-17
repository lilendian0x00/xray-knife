# MTProto proxy testing

Date: 2026-09-15
Status: implemented (2026-09-16; live-proxy correction to the transport padding bound noted below)

## Goal

Let `xray-knife http` (CLI and web UI) test Telegram MTProto proxy links the same way it tests VLESS, VMess, Trojan and the rest: accept the link from a file, a subscription or the database, report `passed` / `failed` / `timeout` / `broken` with a reason, record delay, connect time and time to first byte, deduplicate by connection identity, and persist results.

## Non-goals

- Using an MTProto proxy as an outbound for `proxy`, `tun`, chains or the Cloudflare scanner. MTProto proxies only relay Telegram traffic and cannot carry arbitrary TCP. These commands reject MTProto links with a clear error.
- Speed test, real IP and geolocation. There is no HTTP path through the proxy, so these fields stay at their "not measured" defaults.
- Full Telegram authorization (Diffie-Hellman key exchange, `ping`, DC migration). The probe stops at the first unencrypted server reply, which checks protocol reachability for DC 2. The reply is unauthenticated and can be synthesized by a proxy; it does not prove Telegram identity or reachability to every DC.
- Non-standard `mtproto://` share schemes. Only `tg://proxy` and the `t.me/proxy` HTTPS form are accepted.

## Background

An MTProto proxy accepts an obfuscated TCP stream, derives the obfuscation keys from a shared secret, and forwards the decrypted MTProto frames to a Telegram data center chosen by a DC number embedded in the client's first 64 bytes. Neither xray-core nor sing-box ships an MTProto outbound, so `Core.MakeHttpClient` cannot be used. The probe must be a native Go client that speaks the obfuscation layer and one MTProto request.

Three secret formats exist. All carry a 16-byte key.

| Prefix | Name | Wire behavior |
|---|---|---|
| none (32 hex) | simple | obfuscated2 stream |
| `dd` | secured / padded | obfuscated2 stream, padded-intermediate framing |
| `ee` + hex(domain) | fake TLS | TLS 1.3 look-alike handshake against a cloak domain, then obfuscated2 inside TLS application records |

Reference implementation for the client side: `github.com/gotd/td` v0.161.0, packages `mtproxy`, `mtproxy/obfuscated2`, `mtproxy/faketls`, `proto/codec` (MIT, copyright 2020 Aleksandr Razumov). Its fake TLS ClientHello is built with `github.com/refraction-networking/utls` and the Chrome fingerprint, which xray-knife already depends on.

## Design decisions already taken

- **Native implementation, no new modules.** Port the handshake code from gotd rather than importing it. Measured cost of importing `gotd/td/telegram/dcs` alone: 10 new modules, about 190 extra packages, roughly 1 to 1.5 MB on the final binary. Porting keeps the binary-size work in `docs/binary-size-audit.md` intact and follows the repo pattern where every protocol in `pkg/core/xray` parses its own link.
- **Verification depth: one MTProto round trip.** After the handshake the probe sends an unencrypted `req_pq_multi` and expects a `resPQ` carrying the same nonce. A proxy that accepts TCP but has the wrong secret, or that forwards to the cloak domain instead of Telegram, fails this step. A handshake-only check would pass such proxies.
- **Framing: padded intermediate for every secret type.** Official clients and gotd do this. Some proxies force padded intermediate regardless of secret prefix, so use it consistently for this probe; do not claim universal proxy compatibility.
- **Target data center: DC 2, fixed.** The link format carries no DC. This probe measures the route to DC 2 only; a failure does not imply that every other DC is unreachable.

## Link and secret parsing

Accepted forms, query parameters `server`, `port`, `secret` all required:

```
tg://proxy?server=HOST&port=PORT&secret=SECRET[#remark]
https://t.me/proxy?server=HOST&port=PORT&secret=SECRET
http://t.me/proxy?...            (also telegram.me, telegram.dog)
```

`SECRET` is decoded as hex first (case-insensitive). If that fails, it is decoded as URL-safe base64 with or without padding, then as standard base64. The decoded bytes are classified:

| Bytes | Type | Fields |
|---|---|---|
| 16 | simple | key = all 16 |
| 17, first byte `0xdd` | secured | key = bytes 1..17 |
| more than 17, first byte `0xee` | fake TLS | key = bytes 1..17, cloak host = bytes 17.. as ASCII, must be a syntactically valid hostname |
| anything else | error | `invalid mtproto secret: <why>` |

Reject malformed URL queries and duplicate required parameters. The parsed protocol keeps the original link, the normalized lowercase hex secret, host, decimal-normalized port, type and cloak host. Standard base64 secrets must be URL-escaped so a `+` is preserved. `GetLink` returns the canonical `tg://proxy?server=&port=&secret=` form with the hex secret. `ConvertToGeneralConfig` fills: `Protocol="mtproto"`, `Address`, `Port`, `ID` = hex secret, `TLS` = `faketls` or `none`, `SNI` = cloak host, `Network` and `Type` = `tcp`, `Remark` from the fragment if present, `OrigLink`.

`DetailsStr` prints protocol, remark, address, port, secret type, cloak host and the hex secret, in the same colored key/value style as the other protocols.

## Probe algorithm

Inputs: parsed protocol, overall timeout, optional bind interface. All steps share one deadline derived from the timeout. The clock starts before the TCP dial so `Delay` is comparable with the HTTP path, which also includes connection setup.

1. **Dial** `host:port` over TCP through a `net.Dialer` with the bind interface applied via `netbind`. Record `ConnectTime`.
2. **Handshake** by secret type.
   - simple, secured: generate the 64-byte obfuscated2 init block (rejecting the forbidden leading patterns), derive AES-CTR encrypt and decrypt streams from the block and the key, write protocol tag `dd dd dd dd` and DC `2` into bytes 56..62, send the header.
   - fake TLS: build a Chrome-fingerprint ClientHello for the cloak host with `utls`, zero the 32-byte client random, place `HMAC-SHA256(key, record)` there, XOR the last 4 bytes with the current Unix time, send. Read ServerHello, any extra handshake records, ChangeCipherSpec and one application record. Verify the server random equals `HMAC-SHA256(key, clientRandom || response-with-zeroed-random)`. Mismatch fails with `faketls: server digest mismatch (wrong secret or cloak domain answered)`. Then run the obfuscated2 handshake with all further bytes wrapped in TLS application records, preceded once by a ChangeCipherSpec record.
3. **Request.** Build the unencrypted MTProto message: `auth_key_id = 0` (8 bytes), `message_id` = Unix seconds in the high 32 bits plus fractional seconds in the low 32 bits, rounded to a multiple of four with a nonzero low word (8 bytes), `message_data_length = 20` (4 bytes), then `req_pq_multi` constructor `0xbe7e8ef1` (4 bytes little endian) and a random 16-byte nonce. Wrap in one padded-intermediate frame and send through the obfuscated stream.
4. **Response.** Read one padded-intermediate frame. Record `TTFB` at the first byte received from the proxy after the request was sent. Keep every transport padding byte until decoding; `message_data_length` is what separates body from padding. A negative four-byte transport error may have padding; report its signed value (`transport error -404` and so on). Otherwise validate `auth_key_id`, response message ID and declared body length; decode the complete `resPQ` TL object, including server nonce, `pq` and fingerprint vector. Require constructor `0x05162463` and a nonce equal to the one sent; reject truncated bodies and invalid lengths/counts. Record `Delay`.

   *Correction from live testing (2026-09-16):* the transport documentation describes 0–15 padding bytes, but real MTProxy servers pad further — a live proxy answered a 100-byte `resPQ` message inside a 135-byte frame, i.e. 35 bytes of padding. The decoder therefore bounds the body with `message_data_length` and the whole frame with `maxFrameLen`, and does not bound the trailing padding.
5. **Close.**

The probe returns `ProbeResult{ConnectTime, TTFB, Delay, Detail}` where `Detail` is a short human string such as `faketls, dc2 resPQ ok`.

Failure reasons are specific: dial error, `faketls: unexpected record type`, `faketls: server digest mismatch`, `read resPQ: EOF (proxy closed connection; wrong secret?)`, `read resPQ: timeout`, `resPQ nonce mismatch`, `unexpected constructor 0x…`.

## Architecture

### New package `pkg/core/mtproto`

| File | Contents |
|---|---|
| `mtproto.go` | `Core` implementing `core.Core`. `Name()` returns `mtproto`. `CreateProtocol` accepts the link forms above. `MakeHttpClient`, `MakeInstance` and `SetInbound` return `ErrNotProxyable`. |
| `protocol.go` | `MTProto` struct implementing `protocol.Protocol` and `protocol.Prober`. |
| `secret.go` | Secret decoding and classification. |
| `obfuscated2.go` | Ported: init generation, key derivation, stream wrapper. |
| `faketls.go` | Ported: ClientHello construction, ServerHello verification, TLS record reader and writer. |
| `framing.go` | Padded-intermediate frame write and read. |
| `reqpq.go` | `req_pq_multi` encoding, `resPQ` and transport-error decoding. |
| `prober.go` | `Probe` orchestration and timing. |
| `LICENSE.gotd` | MIT text and a note listing the ported files and the upstream commit. |

Ported files keep a header comment naming the upstream path. Dependencies from gotd are replaced with the standard library: `go-faster/errors` becomes `fmt.Errorf` with `%w`, `clock.Clock` becomes `time.Now`, `crypto.SHA256` becomes `sha256.Sum256`, `bin.Buffer` becomes `encoding/binary` on byte slices. Nothing from `gotd/td` is imported.

`ErrNotProxyable` is a package-level sentinel: `mtproto proxies only relay Telegram traffic and cannot be used as a general outbound`.

### `pkg/core/protocol`

```go
const MTProtoIdentifier = "mtproto"

// Prober is implemented by protocols that cannot carry HTTP and instead verify
// reachability with a protocol-native round trip.
type Prober interface {
	Probe(ctx context.Context, opts ProbeOptions) (ProbeResult, error)
}

type ProbeOptions struct {
	Timeout       time.Duration
	BindInterface string
}

type ProbeResult struct {
	ConnectTime time.Duration
	TTFB        time.Duration
	Delay       time.Duration
	Detail      string
}
```

### `pkg/core/factory.go`

`AutomaticCore` gains a third member, `mtprotoCore`. `selectCoreForLink` routes scheme `tg` to it, and schemes `http` and `https` when the host is `t.me`, `telegram.me` or `telegram.dog` and the path is `/proxy`. Everything else keeps its current routing. `CoreFactoryWith` does not learn a new `CoreType`; the MTProto core is only reachable through the automatic core, because it cannot stand in for xray or sing-box anywhere else.

Passing `--core xray` or `--core singbox` with an MTProto link keeps failing in `CreateProtocol` and surfaces as `broken` with `ErrNotProxyable` wrapped by `create protocol`; explicit cores still do not support MTProto probing.

### `pkg/http`

`ExamineConfig` checks, after `Parse` and after filling `ProtocolInfo` and `TLS`, whether the protocol implements `protocol.Prober`. If so it calls a new `examineProbe` in a new file `pkg/http/probe.go` and returns. `examineProbe`:

- calls `Probe` with `Timeout` and `BindInterface` from the examiner,
- on error sets `Status="failed"`, `Reason=err.Error()`, keeps `Delay=-1`, returns the error,
- on success sets `Delay`, `ConnectTime`, `TTFB` in milliseconds, `Reason=Detail`, `TotalCount=1`, `HTTPCode` stays `-1`; set `SuccessCount=1` only after the MaxDelay check passes,
- if `Delay` exceeds `MaxDelay` sets `Status="timeout"` and the same reason text the HTTP path uses, and returns an error so retries and sorting behave as today,
- on a passed result, if `DoSpeedtest` or `DoIPInfo` is set, appends `speedtest and ip lookup not applicable to mtproto` to the reason without changing the status.

`ExamineConfigWithRetries`, `TestManager`, result saving, CSV and JSON output need no change. `RealIPAddr` and `IpAddrLoc` stay `null`, `DownloadSpeed` and `UploadSpeed` stay `0`.

`handlePingMode` in `cmd/http/http.go` gets the same branch: when the protocol is a `Prober`, each tick calls `Probe` and feeds `Delay` into the existing statistics instead of `MeasureDelay`.

### `pkg/core/identity.go`

`ConnectionFingerprint` adds a case for `*mtproto.MTProto`: canonical text is `tg://proxy?port=P&secret=HEX&server=host` built from the normalized fields (lowercase host, decimal port, lowercase hex secret), preserving unknown query options, then passed through `canonicalURI` so query ordering and fragment handling match the other protocols. The `t.me` form and the `tg://` form of the same proxy therefore collapse to one identity, and so do hex and base64 spellings of the same secret.

### `pkg/http/prescan.go`

No change. `isUDPBased` returns false for `mtproto`, and `endpointForLink` already dials `Address:Port`, which is the right endpoint.

### `pkg/subscription` and `cmd/subs`

No parser change. `Decode` already accepts `tg://` and `https://` lines. `parseLinks` in `cmd/subs/fetch.go` uses the automatic core, so the `protocol` column becomes `mtproto` and `--protocol mtproto` works for `http --from-db` and `subs list-configs`.

### `pkg/proxy`

`ValidateChainForCore` in `pkg/core/chain.go` has no callers, so the check runs on `mtproto.IsProxyLink` before calling the selected core parser in: `resolveFixedChain`, `selectChainFromPool` and `selectExitHopFromPool` in `pkg/proxy/chain.go`. A fixed chain containing an MTProto hop fails with `chain hop N: mtproto cannot be a chain hop: it only relays Telegram traffic`; the two pool selectors skip MTProto links the same way they skip unparseable ones. The proxy service selects explicit xray/sing-box cores. Add an `IsProxyLink` guard in both cores’ `CreateProtocol` methods returning `ErrNotProxyable`, so single-outbound proxy, tun, rotation and scanner paths reject MTProto with the same clear reason before instance/client creation. Test chain behavior with both explicit cores as well as the automatic core.

### `cmd/net/tcp.go`

Constructs the xray core directly. Switch it to `core.NewAutomaticCore`, call `Parse` before `ConvertToGeneralConfig`, and use `net.JoinHostPort` so `net tcp -c tg://…` works with IPv4 and IPv6. `cmd/parse` already uses the automatic core for its default path; its xray-JSON path is xray-specific by design and stays unchanged.

### Web UI

No frontend change. The results table already prints `-` for zero speeds and only shows delay for passed rows. The protocol badge shows `mtproto` from `ProtocolInfo`.

### Docs

README feature list mentions MTProto. The Chinese README gets the same line.

## Error handling summary

| Situation | Status | Reason |
|---|---|---|
| Missing `server`, `port` or `secret`, bad secret | broken | `parse protocol: …` |
| TCP dial fails | failed | dial error text |
| Fake TLS digest mismatch | failed | `faketls: server digest mismatch (wrong secret or cloak domain answered)` |
| Proxy closes after handshake | failed | `read resPQ: EOF (proxy closed connection; wrong secret?)` |
| No reply within timeout | failed | `read resPQ: timeout` |
| Transport error frame | failed | `transport error <code>` |
| `resPQ` with other nonce or constructor | failed | `resPQ nonce mismatch` / `unexpected constructor` |
| Round trip slower than `MaxDelay` | timeout | same text as HTTP path |
| Round trip within budget | passed | `<type>, dc2 resPQ ok` |

## Testing

All new unit tests use in-memory I/O or loopback listeners; none require public network access. A fake MTProto proxy lives in `pkg/core/mtproto/testserver_test.go` and implements the server side of both obfuscation modes: it reads the 64-byte init or the ClientHello, derives the mirrored keys, verifies the fake TLS digest, reads one padded-intermediate frame, parses `req_pq_multi` and answers `resPQ` with the client's nonce, a random server nonce, a fixed `pq` and one fingerprint. Modes: `ok`, `wrong-secret` (closes after the handshake), `hang` (never answers), `garbage` (answers with a wrong constructor), `transport-error` (answers a 4-byte `-404`).

- `secret_test.go`: hex, URL-safe base64, standard base64, all three types, invalid lengths, invalid tag, invalid cloak host.
- `protocol_test.go`: every accepted link form, missing parameters, fragment remark, `GetLink` canonical output, `GeneralConfig` fields.
- `obfuscated2_test.go`: init generation with a seeded reader never emits forbidden prefixes; independent header/payload vector for a fixed seed and key (decrypted bytes 0..56 are discarded, not compared to plaintext); client encrypt and server decrypt streams agree.
- `faketls_test.go`: ClientHello has the digest at offset 11 and the time XOR in the last 4 bytes; ServerHello verification accepts a correct digest and rejects a wrong one; record reader rejects unknown versions.
- `reqpq_test.go`: frame bytes for a fixed nonce and time; fractional message IDs; complete `resPQ` parsing with malformed-length/vector/truncation cases; transport error decoding; every legal padding length 0–15.
- `prober_test.go`: each fake-server mode produces the expected result or error text; timings are positive and `ConnectTime <= TTFB <= Delay`; bind interface `""` is a no-op; cancellation during handshake/read preserves `context.Canceled` and promptly closes the connection.
- `pkg/http/probe_test.go`: `ExamineConfig` through a stub core returning a stub `Prober` with a scripted result, covering passed, timeout via a tiny `MaxDelay`, failed with the probe's error text, and the speedtest note. The real MTProto client is covered in its own package; this test only proves the examiner wiring.
- `pkg/core/factory_test.go`: routing of `tg://`, `https://t.me/proxy`, `https://telegram.me/proxy`, and non-proxy `https://` links.
- `pkg/core/identity_test.go`: `tg://` and `t.me` forms of one proxy share a fingerprint; hex and base64 secrets share a fingerprint; different secrets differ.
- `pkg/proxy/chain_test.go`: fixed chain with an MTProto hop rejected; pool selection skips MTProto links.
- Integration: `prober_live_test.go` runs only when `XRAY_KNIFE_MTPROTO_LINK` is set, against the given real proxy, and is skipped otherwise, following the convention used for network-dependent sing-box tests.

## Rollout

Single pull request. No database migration: the `protocol` column is free text and results reuse existing columns. No config or flag changes.

## Review references and limits

The implementation plan incorporates the [Telegram transport padding rules](https://core.telegram.org/mtproto/mtproto-transports#padded-intermediate) and [message ID requirements](https://core.telegram.org/mtproto/description#message-identifier-msg-id). `resPQ` validation checks protocol structure and the echoed nonce; authentication of Telegram itself remains outside this probe’s scope. Offline integration tests must cover subscription parsing, prescan, persistence and result rendering; a dedup-only smoke test cannot establish those paths.
