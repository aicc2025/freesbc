# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build the only binary: `go build -o freesbc ./cmd/freesbc` (`/freesbc` is gitignored). Set the version with `-ldflags "-X main.version=<v>"` (default `dev`).
- Release: `.github/workflows/release.yml` runs on pushed `v*` tags, or by hand with a `tag` input to backfill one. It builds `CGO_ENABLED=0 -trimpath` binaries for linux/darwin x amd64/arm64, packages `freesbc_<tag>_<os>_<arch>.tar.gz` (binary, README, LICENSE, `freesbc.example.yaml`) with `SHA256SUMS`, runs `check` on the linux/amd64 build, and uploads to the release with `gh`.
- Vet: `go vet ./...`. There is no linter config or Makefile; `gofmt -l .` and `go mod tidy -diff` are clean and CI keeps them so.
- CI (`.github/workflows/ci.yml`, on push to main and PRs): gofmt, `go mod tidy -diff`, vet, build, `check` on the example config, `go test -race ./...`, and govulncheck (pinned v1.8.0, `GOTOOLCHAIN=local`). `soak.yml` runs nightly and on demand: the suite under `-race -count=N`, and each `Fuzz*` target for `-fuzztime`. A new fuzz target must be added to its matrix.
- Tests (as the README runs them): `go test ./... -race`. One package: `go test -race ./internal/config`. One test: `go test ./internal/app -run '^TestCheckExamples$' -count=1 -v`.
- No build tags. The edge suite is mostly integration tests over real loopback sockets (real sipgo transports and RTP sockets), not mocks.
- CLI: `freesbc run|check [-c file]`. `-c` defaults to `freesbc.yaml`; a positional argument is a usage error (exit 2), so always pass `-c`.
- Example config: `./freesbc check -c freesbc.example.yaml` passes (`TestCheckExamples` guards this). It is the only example file; the local copy `/freesbc.yaml` is gitignored.
- `check` only parses and validates; it does not open cert files, bind sockets or test that an address is local. `run` fails at startup unless `public.bind` and the private IP are assigned to a local interface, so adapt `public`/`private` before `run -c freesbc.yaml`.
- Opt-in live FreeSWITCH interop. It skips unless `FREESBC_FS_INTEROP=1` and shells out to `/usr/local/freeswitch/bin/fs_cli`, so run it on the FreeSWITCH host:
  `FREESBC_FS_INTEROP=1 FREESBC_FS_ADDR=<fs-ip>:5060 FREESBC_FS_LOCAL=<this-host-ip> FREESBC_FS_USER=1000 FREESBC_FS_PASS=<pw> go test ./internal/edge/ -run TestFreeSWITCH -v`

## Architecture

One process and one YAML file (schema v2: `public`, `private`, `rtp`, `tls`, `edge`, `shield`, `admin`) run the edge SIP plane. There are no `enabled:` flags and no wildcard binds; the old trunk-era keys (`peers`, `routes`, `listen`, `sip`, `network`, `webrtc`, ...) are unknown-field errors.

- **Edge** (`internal/edge`): a stateful SIP proxy, not a B2BUA, for SIP/UDP phones and WS/WSS/WebRTC browsers in front of FreeSWITCH. Call-ID, tags and CSeq pass through, and the proxy stays on the path with RFC 5658 double Record-Route. FreeSWITCH is the registrar: REGISTER and its digest are forwarded verbatim, and FreeSBC holds no credentials.
- **FreeSWITCH** sits on a private LAN. It is reached only over UDP, from the one fixed private socket `private.ip:5060` (`config.PrivateSIPPort`), at literal `edge.switch` `IP:port` entries (the edge plane does no DNS). It reaches the edge only on that trusted private socket, never a public listener. SDP, Contact and the Request-URI never give it a public client's address and never give clients its address. It does see the client's address in Via `received=`.
- Dependencies run one way: `cmd/freesbc → app → {edge, admin}`. `edge` imports `config`, `media`, `shield`, `sip` and `sip/sdp`. `config`, `media`, `sip` and `sip/sdp` import nothing from this module. `admin` reads the planes only through `admin.Deps` closures built in `app`.

### Signaling and media planes
- Signaling uses `emiago/sipgo` v1.4.3 for transactions and retransmission. The edge has its own sipgo user agent, listeners and `shield.Shield`. `internal/sip` holds shared RFC 3261 primitives with no policy.
- Media (`internal/media`) knows nothing about SIP; the planes pass it addresses, latch modes and SRTP keys. Every stream is anchored on SBC ports. There is no media pass-through and no transcoding.
  - Edge: a public and a private `PlanePool` over the same `rtp` range (default 20000-29999), bound to `public.bind` and the private IP, so each side has its own port namespace (`AllocateAcross`). Browser legs use `WebRTCLeg`: ICE-Lite plus DTLS-SRTP built on pion ice/dtls/srtp, with no `PeerConnection`. The DTLS identity is always one self-signed certificate per process. The edge plane never reads or offers `a=crypto`, and rejects an answer that renumbers payload types (`sdp.ErrRenumbered`).
  - Media uses first-packet latching (strict or loose) and a silence watchdog (the `rtpSilenceTimeout` constant, 5m). The watchdog is the only automatic reclaim for a confirmed call whose BYE was lost.

### Call flow
- Edge INVITE (`onInvite` in `invite.go`) is classified in this order:
  1. A To-tag makes it a re-INVITE.
  2. Arrival on the private bind (`inbound.private()`) goes to a registered client. The client is found only by the `fsbc=` token that FreeSWITCH copies from the stored Contact into the Request-URI (`resolveTarget`); there is no address-of-record fallback, so an unknown or expired token is a 404.
  3. Anything else is a public out-of-dialog INVITE and must pass admission (`admitPublicInvite`, `admission.go`): its source must be a carrier source (`edge.carrier_sources` plus literal-IP `edge.carriers`, `topology.carrierSources`) or the exact transport + IP:port of a live registration (`Location.HasSource`). FreeSWITCH has no clause here: it speaks only on the trusted private bind. Otherwise it is dropped with no response: the handler returns unanswered and sipgo's `TerminateGracefully` terminates the transaction before its 200 ms automatic 100 Trying. This check runs before the 100rel 420.
  4. An admitted INVITE goes to an upstream chosen by an FNV-1a hash of the user.
- REGISTER is always forwarded, except that a public source (IPv4 address, IPv6 /64) with 10 distinct AoRs rejected 403/404 by FreeSWITCH in 10 minutes has further REGISTERs dropped silently until the window ends (`enumLimiter`, `admission.go`). Drops of both kinds count in `freesbc_edge_admission_drops_total{reason}`.
- Edge tests share 127.0.0.1, so the shared harness lists it in `edge.carrier_sources`; admission and shield-ban tests use `startHarnessStrict`, which does not (carrier sources are exempt from the scanner ban). The harness (`harness_test.go`) writes v2 YAML with `public.ip` 127.0.0.1, a non-local placeholder `private.ip` (192.0.2.250) and a `startHarnessSwitches` pool whose nodes are named by their `IP:port`; it builds the server with `edge.WithPrivateAddr(127.0.0.1:<port>)`. That exported option is a test seam: in production the private socket is fixed at `private.ip:5060`. A WebSocket listener exists only when the harness is started with `webrtc` true (WebRTC is on iff `edge.listen.ws`/`wss` is set), and `Server.setRTPTimeout` shortens the RTP silence timeout. `app` tests do the same through the unexported `testHookEdgeOptions`.
- Edge handlers return after the final response. From then on `dialogTable` owns the dialog and its media; a dialog is matched on Call-ID plus both tags, and it is confirmed before its 2xx is relayed.
- SDP: the edge builds every body from scratch with `internal/sip/sdp` (`Build`) and never copies the other leg's body. That is what guarantees topology hiding. 

### Config model
- `config.Parse` runs in this order: strict YAML (unknown keys are errors), `${VAR}` expansion, defaults, then `validate`, which joins all errors. Expansion runs after unmarshal, so parse errors never echo a secret, and expanded values are never written back. Validation lives in one file, `validate.go`; it does no locality checks and opens no files. Address fields stay strings so they can carry `${VAR}`; validate compiles the switch nodes, carrier list and carrier prefixes, exposed through accessors (`Switches`, `CarrierNets`, `CarrierList`, `WebRTC`, `PrivateAddr`).
- `config.Store` publishes immutable `*Config` snapshots through an atomic pointer. Code reads `store.Current()` at the point of use, once per unit of work, and passes that snapshot down instead of reading again: `app.Run` makes every startup decision from the `cfg` it loaded, a media pool reads its params once per allocation. Never mutate a snapshot. `config.Watch` (fsnotify on the parent directory, 200 ms debounce) is the only caller of `Store.Replace`, and a bad file keeps the previous snapshot. Admin `PUT /api/config` only writes the file atomically and lets the watcher reload it.
- Hot vs restart-only settings are tabulated in `docs/design.md` §4.4 ("What is hot vs restart-only"). Everything is restart-only except `shield`: `public`, `private`, `rtp`, `tls`, `edge.*` and `admin` (including its password hash).
- A reload that edits a restart-only setting is still published, with a warning listing the keys (`config.RestartOnlyChanges`, `internal/config/restart.go`; keep its table in step with design.md). The edge keeps the snapshot it was built from (`edge.Server.boot`) and reads restart-only settings only from it, never from the store.
- Validation requires literal `IP:port` for `edge.switch` (`parseIPPort`), specific (non-wildcard) `public.ip`/`public.bind`/`private.ip` with `private.ip` != `public.bind`, and `tls` for `edge.listen.wss` and `admin.allow_remote`. `edge.carriers` and `edge.carrier_sources` are parsed and validated (`ParseCarrierHost`); the carrier path itself is not implemented yet. `edge.Run` (not `check`) verifies that `public.bind` and the effective private IP are local before binding.

### Security boundaries
- The edge installs a sipgo transport read filter (`internal/sip/readfilter.go`) that runs before parsing. It caps reads at 24 KiB (`fsip.MaxReadSize`; stream transports are also bounded by sipgo's 64 KiB `ParseMaxMessageLength`), drops public reads from shield-banned sources (no FreeSWITCH exemption: FreeSWITCH does not use a public listener), and, on the trusted private bind, admits only upstream IPs and stamps each request with an internal `X-FreeSBC-Arrival` header (per-process secret plus the socket) in a new byte slice. `guard` strips every occurrence of that header first, on every transport, and hands handlers `inbound{src, arr}`; a missing or forged marker means public. Trust is keyed on the local socket alone, never on a source address (`edge/arrival.go`). A filter must never return an error, because sipgo treats that as fatal to the read loop; reject by returning `nil, nil`.
- The edge private plane is trusted and exempt from the shield. `shield.New` takes an `isCarrier` predicate: carrier sources use `shield.carrier_rate_limit` and are never scanner-banned. Bans are in memory only; there is no nftables backend (removed with P2-SHD-004). The admin call list, call count, port usage, listeners and shield drop metrics come from the edge plane. There is no unban API (`DELETE /api/bans/{ip}` was removed).
- Admin uses bcrypt Basic Auth (user is always `admin`, hash cost ≥ 10) and is loopback-only unless `admin.allow_remote: true` is set, which requires top-level `tls` and serves HTTPS. `GET /api/config/raw` is unredacted on purpose.

### sipgo v1.4.3 workarounds (re-check when upgrading sipgo)
- Listeners bypass `ListenAndServe*`, whose unsynchronised close is flagged by `-race` on every shutdown.
- `edge.New` raises the process-wide `sip.UDPMTUSize` to 8192.

`docs/design.md` describes the code as implemented, with file:line citations: §4 lifecycle/reload, §7 edge, §8 media, §11 concurrency, §14 security, §15.2 all timeouts, §17 package ownership. `docs/edge.md` and the README section "Status & limitations" list the non-goals and known limitations.

## Test environment gotchas

- `TestAuditMED006LooseLatchFirstPacketHijack` (media) binds 127.0.0.2 and skips, not fails, when macOS has no such loopback alias. Fix with `sudo ifconfig lo0 alias 127.0.0.2 up` (not persistent), or run in Linux: `docker run --rm -v "$PWD":/src -w /src golang:1.27.1 go test -race -count=1 ./...`.
- Test ports: each package owns a disjoint band, all below 32768 (the start of Linux's ephemeral range, so the kernel never hands a test's fixed port to a client socket; macOS's starts at 49152). Keep new test ports inside the package's band:

  | Band | Package | How ports are chosen |
  |---|---|---|
  | 10000–10099 | app | kernel-assigned SIP ports with retry on a bind collision; the RTP ranges are 10010-10029 |
  | 10100–10199 | admin | fixed (`TestAdminServesTLS`); other admin tests listen on `:0` |
  | 20000–24999 | media | fixed per test |
  | 25000–27999 | edge SIP | `nextPort`: probed free, cursor wraps |
  | 28000–32399 | edge media | `nextMediaBase`: a 400-port window per harness (one `rtp` range shared by both pools), every port probed free, cursor wraps |

  Packages can therefore run in parallel inside one `go test ./...`, and `-count=N` works. Two concurrent runs of the same package (for example from two checkouts) still collide on the fixed media ports.
- `WARN UDP ref went negative on try close` lines come from sipgo v1.4.3 (`sip/transport_udp.go`, logged without returning an error) and are not test failures.
