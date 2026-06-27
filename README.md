# TinyTun

TinyTun is a Rust-based transparent proxy runner using TUN inbound capture, with
SOCKS5 proxy support, custom routing, encrypted DNS (DoT / DoH / DoQ), and
user-space process exclusion.

## Requirements

- Rust 1.70+
- Admin/root privileges for network operations
- Linux / macOS / Windows supported
- Windows requires `wintun.dll` beside `tinytun.exe` or in `PATH`

## Build

```bash
cargo build --release
```

- Linux/macOS binary: `target/release/tinytun`
- Windows binary: `target/release/tinytun.exe`

No special toolchains or features are required — a simple `cargo build` works on
all platforms. The binary uses the **mimalloc** allocator for improved performance
and reduced memory fragmentation.

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
tinytun run --config <FILE> --log-hide-timestamp
tinytun run --config <FILE> --socks5 127.0.0.1:1080
tinytun run --config <FILE> --skip-ip 1.1.1.1 --skip-network 10.0.0.0/8
```

## Process Exclusion

TinyTun supports excluding specific processes from proxy handling via the
`--exclude-process` flag or `exclude_processes` config option. This is
implemented in **user-space** using platform-native process lookups (netlink on
Linux, sysctl on FreeBSD, `GetExtendedTcpTable` / `GetExtendedUdpTable` on
Windows) — no eBPF or kernel dependencies required.

## License

GNU GPL-3.0-or-later. See `LICENSE`.

## Performance Notes

- **mimalloc**: The global allocator is switched to mimalloc for lower
  latency and reduced memory fragmentation under high connection counts.
- **Atomic TCP state**: TCP sequence numbers and window sizes use lock-free
  atomics (`AtomicU32`/`AtomicU16`) to minimize `Mutex` contention on the
  hot path.
- **Parallel shutdown**: Route cleanup, DNS hijack teardown, and device
  cleanup run concurrently via `tokio::join!` for faster exit.
- **Linear IP lookup**: Skip-network matching uses flat `Vec` scans instead
  of nested B-tree maps, reducing per-packet overhead.
- **Bounded backpressure**: DNS and UDP task semaphores use a short wait
  (100ms) before dropping overloaded packets, improving reliability under
  burst traffic.
