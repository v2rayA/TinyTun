# TinyTun

TinyTun is a Rust-based transparent proxy runner with two inbound modes:

- `tun`: capture with TUN and route selected traffic to SOCKS5
- `linux-ebpf`: capture with Linux eBPF/tc + sk_lookup, fully embedded BPF,
  no TUN device, no iptables/firewall rules

## Requirements

- Rust 1.70+
- Admin/root privileges for network operations
- Linux/macOS/Windows supported
- Windows requires `wintun.dll` beside `tinytun.exe` or in `PATH`

### Additional build requirements for `linux-ebpf` mode

- `clang` (any version with `-target bpf` support, e.g. clang-15+)
- `libbpf-dev` (provides `/usr/include/bpf/bpf_helpers.h`)
- Linux kernel headers (`linux-headers-$(uname -r)`)

Example (Ubuntu/Debian):
```bash
sudo apt-get install clang libbpf-dev linux-headers-$(uname -r)
```

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
      "mark": 563,
      "table_id": 233,
      "redirect_port": 15080,
      "redirect_tcp": true,
      "redirect_udp": false
    }
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

### How `linux-ebpf` mode works

1. **Embedded BPF object** – The eBPF programs are compiled from C source at
   build time and embedded directly in the binary (no external `.bpf.o` file
   needed at runtime).

2. **TC egress classifier** – A BPF TC program is attached to the *egress*
   path of the configured network interface.  For each outgoing packet whose
   destination IP is not in `skip_ips` / `skip_networks`, the packet is marked
   with the configured `fwmark` value.

3. **Policy routing (no iptables)** – Two `ip` routing rules are installed:
   ```
   ip rule  add fwmark <mark> lookup <table>
   ip route add local default dev lo table <table>
   ```
   Marked packets are re-delivered to the loopback interface, making them
   appear as incoming connections.

4. **sk_lookup redirect** – A BPF `sk_lookup` program attached to the network
   namespace intercepts socket lookups that would otherwise fail (because no
   process is listening on the original destination IP:port).  It redirects
   those connections to TinyTun's own `IP_TRANSPARENT` listening socket.

5. **Transparent proxy** – TinyTun accepts connections on an `IP_TRANSPARENT`
   socket; `getsockname()` on each accepted connection returns the *original*
   destination IP:port (e.g. `8.8.8.8:443`).  TinyTun then tunnels the
   traffic through the configured SOCKS5 proxy.

### Important notes

- `linux-ebpf` mode is Linux-only.
- The SOCKS5 proxy address should be in `skip_ips` / `skip_networks` if it is
  not on loopback (otherwise TinyTun would try to proxy its own SOCKS5
  connections and loop).
- No iptables, nftables, or TUN/TAP device is created or required.
- Requires kernel ≥ 5.9 (for `sk_lookup` BPF program type, introduced in
  Linux 5.9) and Linux ≥ 4.19 for BPF LPM trie and TC classifiers.

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
tinytun run --config <FILE> --linux-ebpf-ingress-mark 563 --linux-ebpf-ingress-table-id 233
tinytun run --config <FILE> --linux-ebpf-ingress-redirect-port 15080
```

## License

GNU GPL-3.0-or-later. See `LICENSE`.