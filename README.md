# TinyTun

TinyTun is a Rust-based transparent proxy runner with two inbound modes:

- `tun`: capture with TUN and route selected traffic to SOCKS5
- `linux-ebpf`: capture with Linux eBPF/tc and policy route + redirect

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

## Minimal Example 1: TUN Mode

`config.tun.min.json`:

```json
{
  "inbound": { "mode": "tun" },
  "tun": {
    "name": "tun0",
    "ip": "198.18.0.1",
    "netmask": "255.255.255.255",
    "ipv6_mode": "off",
    "ipv6": "fd00::1",
    "ipv6_prefix": 128,
    "auto_route": true,
    "mtu": 1500
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
    "timeout_ms": 5000,
    "hijack": { "enabled": false, "mark": 1, "table_id": 100, "capture_tcp": true }
  },
  "filtering": {
    "skip_ips": ["127.0.0.1"],
    "skip_networks": ["127.0.0.0/8"],
    "block_ports": [],
    "allow_ports": [],
    "exclude_processes": [],
    "process_lookup": { "linux_backend": "auto", "linux_ebpf_cache_path": null }
  },
  "route": { "auto_detect_interface": true, "default_interface": null },
  "log": { "loglevel": "warning" }
}
```

Run:

```bash
sudo ./target/release/tinytun run --config config.tun.min.json
```

## Minimal Example 2: Linux eBPF Mode

`config.ebpf.min.json`:

```json
{
  "inbound": {
    "mode": "linux-ebpf",
    "linux_ebpf": {
      "enabled": true,
      "interface": "eth0",
      "bpf_object": "/etc/tinytun/tinytun_ingress.bpf.o",
      "bpf_section": "classifier/ingress",
      "skip_map_path": "/sys/fs/bpf/tinytun/skip_v4",
      "skip_map_v6_path": "/sys/fs/bpf/tinytun/skip_v6",
      "mark": 563,
      "table_id": 233,
      "redirect_port": 15080,
      "redirect_tcp": true,
      "redirect_udp": true
    }
  },
  "tun": {
    "name": "tun0",
    "ip": "198.18.0.1",
    "netmask": "255.255.255.255",
    "ipv6_mode": "off",
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
    "servers": [{ "address": "8.8.8.8:53", "route": "direct" }],
    "listen_port": 53,
    "timeout_ms": 5000,
    "hijack": { "enabled": false, "mark": 1, "table_id": 100, "capture_tcp": true }
  },
  "filtering": {
    "skip_ips": ["127.0.0.1", "10.0.0.1"],
    "skip_networks": ["10.0.0.0/8", "fc00::/7"],
    "block_ports": [],
    "allow_ports": [],
    "exclude_processes": [],
    "process_lookup": { "linux_backend": "auto", "linux_ebpf_cache_path": null }
  },
  "route": { "auto_detect_interface": true, "default_interface": null },
  "log": { "loglevel": "warning" }
}
```

Run:

```bash
sudo ./target/release/tinytun run --config config.ebpf.min.json
```

Notes:

- `linux-ebpf` mode is Linux-only
- `redirect_port` must have a transparent inbound listener
- TinyTun applies and cleans network rules automatically on start/exit

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

# Force TUN mode
tinytun run --config <FILE> --inbound-mode tun

# Force Linux eBPF mode
tinytun run --config <FILE> --inbound-mode linux-ebpf --linux-ebpf-ingress-enabled

# eBPF key parameters
tinytun run --config <FILE> --linux-ebpf-ingress-interface eth0
tinytun run --config <FILE> --linux-ebpf-bpf-object /etc/tinytun/tinytun_ingress.bpf.o
tinytun run --config <FILE> --linux-ebpf-bpf-section classifier/ingress
tinytun run --config <FILE> --linux-ebpf-skip-map-path /sys/fs/bpf/tinytun/skip_v4
tinytun run --config <FILE> --linux-ebpf-skip-map-v6-path /sys/fs/bpf/tinytun/skip_v6
tinytun run --config <FILE> --linux-ebpf-ingress-mark 563 --linux-ebpf-ingress-table-id 233
tinytun run --config <FILE> --linux-ebpf-ingress-redirect-port 15080
```

## License

GNU GPL-3.0-or-later. See `LICENSE`.