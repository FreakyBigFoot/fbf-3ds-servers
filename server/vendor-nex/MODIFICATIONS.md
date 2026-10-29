# Modifications to PretendoNetwork/nex-go

This directory is a **modified copy** of [PretendoNetwork/nex-go](https://github.com/PretendoNetwork/nex-go)
v2.3.1, vendored via a `replace` directive in `../go.mod`. It is licensed under the
**GNU AGPL-3.0** (see `LICENSE`), the same license as upstream.

Changes from upstream:
- `ffe_experiment.go`, `ffe_shotgun.go` — added: throwaway PRUDP CONNECT
  experimentation harness used while reverse-engineering the handshake
  (gated behind env vars; inert by default).
- `prudp_server.go`, `prudp_endpoint.go` — small edits to hook the above.
- `prudp_connection.go` — keepalive retuned for 3DS co-op: ping every 5 s and
  only drop a connection after 45 s of silence (upstream: single 10 s/20 s
  `MaxSilenceTime`). During 3-4 player games the console<->server link goes
  idle while traffic flows peer-to-peer, and strict home NATs dropped the
  mapping, collapsing the party.
- `prudp_server.go` — recover from a panic while processing a single packet
  (log and drop it) instead of taking down every endpoint in the process.

Per AGPL-3.0, the complete corresponding source of this modified version is
included in this repository.
