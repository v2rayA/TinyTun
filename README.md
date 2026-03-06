# TinyTun

A Rust-based tun2socks implementation built on top of [tun-rs](https://github.com/tun-rs/tun-rs) that provides SOCKS5 proxy functionality with DNS support and IP filtering capabilities.

## Features

- **SOCKS5 Proxy Support**: Connect to SOCKS5 proxies with optional authentication
- **DNS Over SOCKS5**: Route DNS queries through the SOCKS5 proxy for enhanced privacy
- **IP Address Filtering**: Skip defined IP addresses and networks from proxying
- **DNS Rerouting**: Intercept and reroute DNS requests to upstream servers
- **TUN Device Management**: Automatic TUN device creation and cleanup
- **Configuration File Support**: JSON-based configuration with CLI overrides

## Requirements

- Rust 1.70+ 
- Administrative privileges (required for TUN device creation)
- Linux, Windows, or macOS

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/TinyTun.git
cd TinyTun
```

2. Build the project:
```bash
cargo build --release
```

## Usage

### Basic Usage

Run with default configuration:
```bash
sudo ./target/release/tinytun run
```

### With Configuration File

```bash
sudo ./target/release/tinytun run --config config.json
```

### With CLI Arguments

```bash
sudo ./target/release/tinytun run \
  --socks5 127.0.0.1:1080 \
  --dns 8.8.8.8:53 --dns-route direct \
  --dns 1.1.1.1:53 --dns-route proxy \
  --interface tun0 \
  --ip 10.0.0.1 \
  --netmask 255.255.255.0
```

### With Authentication

```bash
sudo ./target/release/tinytun run --config config.json
```

Where `config.json` contains:
```json
{
  "socks5": {
    "address": "proxy.example.com:1080",
    "username": "your_username",
    "password": "your_password",
    "dns_over_socks5": true
  }
}
```

## Configuration

The configuration file (`config.json`) supports the following options:

### TUN Device Configuration
```json
{
  "tun": {
    "name": "tun0",
    "ip": "10.0.0.1",
    "netmask": "255.255.255.0",
    "mtu": 1500
  }
}
```

### SOCKS5 Configuration
```json
{
  "socks5": {
    "address": "127.0.0.1:1080",
    "username": null,
    "password": null,
    "dns_over_socks5": true
  }
}
```

### DNS Configuration
```json
{
  "dns": {
    "upstream_server": "8.8.8.8:53",
    "servers": [
      { "address": "8.8.8.8:53", "route": "direct" },
      { "address": "1.1.1.1:53", "route": "proxy" }
    ],
    "listen_port": 53,
    "timeout_ms": 5000
  }
}
```

### Filtering Configuration
```json
{
  "filtering": {
    "skip_ips": ["127.0.0.1", "10.0.0.1"],
    "skip_networks": ["192.168.0.0/16", "10.0.0.0/8"],
    "block_ports": [22, 23, 25],
    "allow_ports": [80, 443, 53]
  }
}
```

## How It Works

1. **TUN Device Creation**: Creates a virtual network interface that captures IP packets
2. **Packet Processing**: Analyzes incoming packets and determines routing
3. **Filtering**: Applies IP and port filtering rules to skip certain traffic
4. **SOCKS5 Proxying**: Routes eligible TCP connections through the SOCKS5 proxy
5. **DNS Handling**: Intercepts DNS requests and forwards them to configured servers

## Supported Protocols

- **TCP**: Full SOCKS5 proxy support with connection establishment
- **UDP**: Basic support (DNS requests are handled, other UDP traffic is logged)
- **DNS**: Multi-upstream DNS forwarding with per-server `direct`/`proxy` route

## Limitations

- UDP proxying through SOCKS5 is not fully implemented (only DNS is supported)
- Bidirectional TCP proxying requires more complex state management
- Requires administrative privileges for TUN device creation
- DNS response injection path is currently IPv4 UDP-focused

## Security Considerations

- Always use strong authentication for SOCKS5 proxies
- Be cautious with DNS server selection to avoid DNS hijacking
- Filter sensitive local networks from being proxied
- Monitor logs for any unexpected connection attempts

## Troubleshooting

### Permission Errors
Ensure you're running with sufficient privileges:
```bash
sudo ./target/release/tinytun run
```

On Windows, run the terminal as Administrator before starting TinyTun.

### Wintun Runtime Errors (Windows)
If startup fails with `wintun.dll`/`LoadLibraryExW` errors, place `wintun.dll` in the same directory as `tinytun.exe` (for example `target/release`) or add the DLL directory to `PATH`.

### TUN Device Issues
On Linux, ensure the `tun` module is loaded:
```bash
sudo modprobe tun
```

### Network Configuration
After starting TinyTun, you may need to configure routing:
```bash
# Add route for traffic to go through the TUN interface
sudo ip route add 10.0.0.0/24 dev tun0
```

## Development

### Building
```bash
cargo build
```

### Testing
```bash
cargo test
```

### Running with Debug Output
```bash
RUST_LOG=debug sudo ./target/debug/tinytun run
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Dependencies

- `tun`: TUN device management
- `tokio`: Async runtime
- `etherparse`: Packet parsing
- `clap`: CLI argument parsing
- `serde`: Configuration serialization
- `log`: Logging framework

## Related Projects

- [tun-rs](https://github.com/tun-rs/tun-rs): TUN device library
- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust): Shadowsocks implementation
- [badvpn](https://github.com/ambrop72/badvpn): Alternative tun2socks implementation