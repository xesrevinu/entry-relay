# entry-net

TLS entry relay (`entry-relay`) and a localhost SOCKS balancer (`entry-balance`).

The balancer keeps a few long-lived TLS 1.3 mux sessions to one or more relays. Each new stream is one `OPEN/OK` round trip. A relay listens on a public port but is not an open proxy: a failed check returns an ordinary web page and does not connect upstream.

- Credit window per stream and direction (default 4MB). The TLS writer applies backpressure from that budget.
- Dead sessions: TCP keepalive (15s/5s×3) plus `TCP_USER_TIMEOUT` 30s. The balancer PINGs every 2s and redials a slot after 8s with no inbound frame. The relay closes a session after 90s with no inbound frame.
- The process is a master. The worker accepts. `SIGUSR2` stops new accepts and drains in-flight streams (`ENTRY_DRAIN_SECS`, default 30).
- Release builds are static musl: `lto=fat`, `opt-level=3`, `panic=abort`, stripped.

```bash
nix shell nixpkgs#zig nixpkgs#cargo-zigbuild -c sh -c 'for t in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  env -u CC -u CFLAGS -u CXX RUSTFLAGS="-C target-feature=+crt-static" cargo zigbuild --release --target $t --bin entry-relay --bin entry-balance; done'
cargo test --release
```

Relay addresses, the allowlist, the certificate name, and the listen port are config. They are not compiled in. `entry-relay gen-cert` defaults the certificate name to `relay.example`.
