# TinyTun

TinyTun is a Rust-based `tun2socks` project that captures traffic from a TUN interface and forwards eligible traffic through a SOCKS5 proxy, with DNS forwarding and filtering support.

## Features

- SOCKS5 forwarding for TCP flows
- DNS forwarding with per-server route mode (`direct` or `proxy`)
- IP/network/port filtering rules
- JSON configuration file with CLI overrides
- IPv4 + optional IPv6 TUN settings
- Optional automatic route setup/cleanup

## Project Status

TinyTun is functional for common SOCKS5 + DNS use cases, but it is still evolving.

- DNS forwarding is supported.
- UDP proxying is not a full generic SOCKS5 UDP implementation yet.
- Advanced TCP edge cases may still need refinement.

## Requirements

- Rust 1.70+
- Administrator/root privileges to create and manage TUN interfaces
- Supported OS: Windows, Linux, macOS
- On Windows: `wintun.dll` must be available next to `tinytun.exe` or in `PATH`

## Build

```bash
cargo build --release
```

Binary path:

- Linux/macOS: `target/release/tinytun`
- Windows: `target/release/tinytun.exe`

## Usage

### 1) Run With Config File

```bash
tinytun run --config config.json
```

On Linux/macOS, run with elevated privileges if required:

```bash
sudo ./target/release/tinytun run --config config.json
```

On Windows, start PowerShell or CMD as Administrator, then run:

```powershell
.\target\release\tinytun.exe run --config .\config.json
```

### 2) Run With CLI Overrides

```bash
tinytun run \
  --socks5 127.0.0.1:1080 \
  --dns-listen-port 53 \
  --dns 8.8.8.8:53 --dns-route direct \
  --dns 1.1.1.1:53 --dns-route proxy \
  --exclude-process chrome.exe \
  --exclude-process code \
  --interface tun0 \
  --ip 198.18.0.1 \
  --netmask 255.255.255.255 \
  --ipv6-mode auto \
  --auto-route \
  --auto-detect-interface
```

Or pin bypass routing to a specific physical NIC:

```bash
tinytun run --config config.json --auto-route --auto-detect-interface false --default-interface "Ethernet"
```

Notes:

- `--dns` and `--dns-route` are repeatable and paired by order.
- `--exclude-process` is repeatable and matched by process executable name (case-insensitive).
- Process exclusion currently applies to TCP flows handled by TinyTun; matched flows are rejected locally instead of being proxied.
- DNS capture on TUN path uses `dns.listen_port` from config, or `--dns-listen-port` if provided.
- You can combine `--config` with CLI flags; CLI values override config values.
- `--auto-detect-interface` and `--default-interface` are mutually exclusive when both enabled.

### 3) CLI Help

```bash
tinytun --help
tinytun run --help
```

## Configuration Reference

Example `config.json`:

```json
{
  "tun": {
    "name": "tun0",
    "ip": "198.18.0.1",
    "netmask": "255.255.255.255",
    "ipv6_mode": "auto",
    "ipv6": "fd00::1",
    "ipv6_prefix": 128,
    "auto_route": false,
    "mtu": 1500
  },
  "socks5": {
    "address": "127.0.0.1:1080",
    "username": null,
    "password": null,
    "dns_over_socks5": true
  },
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8:53",
        "route": "direct"
      },
      {
        "address": "1.1.1.1:53",
        "route": "proxy"
      }
    ],
    "listen_port": 53,
    "timeout_ms": 5000
  },
  "filtering": {
    "skip_ips": ["127.0.0.1", "198.18.0.1"],
    "skip_networks": [
      "192.168.0.0/16",
      "172.16.0.0/12",
      "10.0.0.0/8",
      "127.0.0.0/8",
      "169.254.0.0/16"
    ],
    "block_ports": [22, 23, 25, 110, 143],
    "allow_ports": [80, 443, 53],
    "exclude_processes": ["chrome.exe", "curl"]
  },
  "route": {
    "auto_detect_interface": true,
    "default_interface": null
  }
}
```

## Troubleshooting

- Permission errors: run as Administrator/root.
- Windows `LoadLibraryExW` / `wintun.dll` error: place `wintun.dll` next to the executable or add its directory to `PATH`.
- Linux TUN issues: ensure TUN module is loaded (`sudo modprobe tun`).

## Copyright

Copyright (c) 2026 TinyTun contributors.

This project includes or links to third-party open source software. Their copyrights remain with their respective authors.

## License

TinyTun is licensed under **GNU General Public License v3.0 or later (GPL-3.0-or-later)**. See `LICENSE`.

Why GPL-3.0-or-later for this project:

- TinyTun currently depends on `socks5-impl`, which is licensed under `GPL-3.0-or-later`.
- To keep distribution terms compliant with upstream licensing, this project adopts a compatible GPL license.

If the GPL dependency is replaced in the future, relicensing options can be re-evaluated by the maintainers.

## Third-Party Notices

Key dependencies include:

- `socks5-impl` - GPL-3.0-or-later
- `tun` - WTFPL
- `clap`, `serde`, `etherparse`, `trust-dns-*` - MIT OR Apache-2.0
- `tokio` - MIT

Please refer to each dependency's own repository and license text for full details.