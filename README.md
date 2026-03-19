# TinyTun

TinyTun is a Rust-based transparent proxy runner using TUN inbound capture.

## Requirements

- Rust 1.70+
- Admin/root privileges for network operations
- Linux/macOS/Windows supported
- Windows requires `wintun.dll` beside `tinytun.exe` or in `PATH`

## Build

```bash
cargo build --release
```

- Linux/macOS binary: `target/release/tinytun`
- Windows binary: `target/release/tinytun.exe`

## Minimal Example

`config.tun.min.json`:

```json
{
  "tun": {
    "auto_route": true
  },
  "socks5": {
    "address": "127.0.0.1:1080",
    "username": null,
    "password": null,
    "dns_over_socks5": true
  },
  "dns": {
    "servers": [{ "address": "8.8.8.8:53", "route": "direct" }],
    "listen_port": 53,
    "timeout_ms": 5000
  },
  "filtering": {
    "skip_ips": ["127.0.0.1"],
    "skip_networks": ["127.0.0.0/8"],
    "block_ports": [],
    "allow_ports": []
  }
}
```

All other `tun` fields (`name`, `ip`, `netmask`, `ipv6_mode`, `mtu`, ...) use
built-in defaults when omitted.

Run:

```bash
sudo ./target/release/tinytun run --config config.tun.min.json
```

## CLI Command Checklist

```bash
# Help
tinytun --help
tinytun run --help

# Build
cargo build --release

# Run by config
tinytun run --config <FILE>

# Common overrides
tinytun run --config <FILE> --loglevel warning
tinytun run --config <FILE> --socks5 127.0.0.1:1080
tinytun run --config <FILE> --skip-ip 1.1.1.1 --skip-network 10.0.0.0/8
```

## License

GNU GPL-3.0-or-later. See `LICENSE`.
