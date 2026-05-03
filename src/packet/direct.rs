use anyhow::Result;
use tokio::net::TcpStream;

/// Connect directly to `dst` via the physical outbound interface, bypassing
/// the TUN device. Uses `SO_BINDTODEVICE` (Linux) or `IP_BOUND_IF`/
/// `IPV6_BOUND_IF` (macOS) so the socket is pinned to the physical
/// NIC and never re-enters the TUN routing path.
pub async fn open_direct_tcp(dst: std::net::SocketAddr, outbound_interface: &str) -> Result<TcpStream> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        use tokio::net::TcpSocket;

        let socket = if dst.is_ipv6() {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        let fd = socket.as_raw_fd();
        let iface_c = std::ffi::CString::new(outbound_interface)
            .map_err(|_| anyhow::anyhow!("outbound interface name contains null byte"))?;
        // SAFETY: `fd` is a valid raw file descriptor from `socket.as_raw_fd()`.
        // `iface_c.as_ptr()` is a valid, NUL-terminated C string pointer.
        // `to_bytes_with_nul().len()` gives the correct buffer size including NUL.
        // `setsockopt` with `SO_BINDTODEVICE` only reads from the provided buffer;
        // no data races occur as the socket is not yet connected. Return value is checked.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_c.as_ptr() as *const libc::c_void,
                iface_c.to_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let os_err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "SO_BINDTODEVICE to '{}' failed: {}. \
                 Ensure the process has CAP_NET_RAW capability or runs as root.",
                outbound_interface, os_err
            ));
        }
        let stream = socket.connect(dst).await?;
        stream.set_nodelay(true)?;
        return Ok(stream);
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        use tokio::net::TcpSocket;

        // Resolve interface name → index once.
        // SAFETY: `iface_c.as_ptr()` is a valid NUL-terminated C string.
        // `if_nametoindex` only reads from the provided pointer; no side effects on Rust state.
        // Return value 0 indicates error, which is checked below.
        let if_index = unsafe {
            let iface_c = std::ffi::CString::new(outbound_interface)
                .map_err(|_| anyhow::anyhow!("outbound interface name contains null byte"))?;
            libc::if_nametoindex(iface_c.as_ptr())
        };
        if if_index != 0 {
            let socket = if dst.is_ipv6() {
                TcpSocket::new_v6()?
            } else {
                TcpSocket::new_v4()?
            };
            let fd = socket.as_raw_fd();
            // IP_BOUND_IF = 25 (IPv4), IPV6_BOUND_IF = 125 (IPv6) — macOS only
            let (level, optname) = if dst.is_ipv6() {
                (libc::IPPROTO_IPV6, 125i32)
            } else {
                (libc::IPPROTO_IP, libc::IP_BOUND_IF as i32)
            };
            let idx = if_index;
            // SAFETY: `fd` is a valid raw file descriptor. `&idx` is a valid pointer to
            // a properly sized `c_uint`. `setsockopt` only reads from the buffer; no data
            // races. Return value is checked (0 = success) to detect errors.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    optname,
                    &idx as *const libc::c_uint as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                let os_err = std::io::Error::last_os_error();
                return Err(anyhow::anyhow!(
                    "IP_BOUND_IF/IPV6_BOUND_IF to '{}' (index={}) failed: {}",
                    outbound_interface, if_index, os_err
                ));
            }
            let stream = socket.connect(dst).await?;
            stream.set_nodelay(true)?;
            return Ok(stream);
        } else {
            return Err(anyhow::anyhow!(
                "if_nametoindex('{}') failed: interface not found",
                outbound_interface
            ));
        }
    }

    // Neither the Linux nor the macOS cfg block applies here.  This
    // platform does not support socket-level interface binding.
    // Call sites should be gated with #[cfg(any(linux, macos))]; this
    // Err acts as a safety net for any future unconstrained call sites.
    Err(anyhow::anyhow!(
        "direct TCP: socket-level interface binding is not supported on \
         this platform (Linux requires SO_BINDTODEVICE, macOS requires \
         IP_BOUND_IF); configure auto_route for excluded-process bypass"
    ))
}

/// Send a single UDP datagram directly to `dst` via the physical outbound
/// interface and return the first response datagram. Uses `SO_BINDTODEVICE`
/// (Linux) or `IP_BOUND_IF`/`IPV6_BOUND_IF` (macOS) to prevent
/// the socket from re-entering the TUN device.
pub async fn direct_udp_exchange(
    dst: std::net::SocketAddr,
    payload: Vec<u8>,
    outbound_interface: String,
) -> Result<Vec<u8>> {
    use tokio::net::UdpSocket;

    let bind_addr: std::net::SocketAddr = if dst.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let socket = UdpSocket::bind(bind_addr).await?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let iface_c = std::ffi::CString::new(outbound_interface.as_str())
            .map_err(|_| anyhow::anyhow!("outbound interface name contains null byte"))?;
        // SAFETY: Same pattern as `open_direct_tcp` — `fd` is a valid UDP socket fd,
        // `iface_c` is a valid NUL-terminated C string. `setsockopt` only reads from
        // the buffer. Return value is checked for errors.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_c.as_ptr() as *const libc::c_void,
                iface_c.to_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let os_err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "SO_BINDTODEVICE to '{}' for direct UDP failed: {}. \
                 Ensure the process has CAP_NET_RAW capability or runs as root.",
                outbound_interface, os_err
            ));
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: Same pattern as `open_direct_tcp` macOS branch.
        // `iface_c.as_ptr()` is a valid NUL-terminated C string.
        // Return value 0 indicates error, checked below.
        let if_index = unsafe {
            let iface_c = std::ffi::CString::new(outbound_interface.as_str())
                .map_err(|_| anyhow::anyhow!("outbound interface name contains null byte"))?;
            libc::if_nametoindex(iface_c.as_ptr())
        };
        if if_index != 0 {
            let fd = socket.as_raw_fd();
            // IP_BOUND_IF = 25 (IPv4), IPV6_BOUND_IF = 125 (IPv6) — macOS only
            let (level, optname) = if dst.is_ipv6() {
                (libc::IPPROTO_IPV6, 125i32)
            } else {
                (libc::IPPROTO_IP, libc::IP_BOUND_IF as i32)
            };
            // SAFETY: Same pattern as `open_direct_tcp` macOS branch.
            // `fd` is a valid UDP socket fd, `&if_index` is a valid pointer.
            // Return value is checked for errors.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    optname,
                    &if_index as *const libc::c_uint as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                let os_err = std::io::Error::last_os_error();
                return Err(anyhow::anyhow!(
                    "IP_BOUND_IF/IPV6_BOUND_IF to '{}' for direct UDP failed: {}",
                    outbound_interface, os_err
                ));
            }
        } else {
            return Err(anyhow::anyhow!(
                "if_nametoindex('{}') failed for direct UDP: interface not found",
                outbound_interface
            ));
        }
    }

    // Same safety net as open_direct_tcp: platforms that reach this point
    // have no interface binding, so return Err rather than doing a plain
    // connect that may re-enter the TUN device.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (&dst, &payload, &outbound_interface);
        return Err(anyhow::anyhow!(
            "direct UDP: socket-level interface binding is not supported on this platform"
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    socket.connect(dst).await?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    socket.send(&payload).await?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut buf = vec![0u8; 65535];
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let n = socket.recv(&mut buf).await?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    buf.truncate(n);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Ok(buf)
}
