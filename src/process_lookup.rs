use std::net::SocketAddr;
use std::process::Command;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

pub fn find_process_name_for_flow(
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    #[cfg(windows)]
    {
        return find_process_name_for_flow_windows(protocol, src, dst);
    }

    #[cfg(target_os = "linux")]
    {
        return find_process_name_for_flow_linux(protocol, src, dst);
    }

    #[cfg(target_os = "macos")]
    {
        return find_process_name_for_flow_macos(protocol, src, dst);
    }

    #[allow(unreachable_code)]
    None
}

#[cfg(windows)]
fn find_process_name_for_flow_windows(
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    let script = match protocol {
        TransportProtocol::Tcp => format!(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $conn = Get-NetTCPConnection -State SynSent,Established,CloseWait,FinWait1,FinWait2,TimeWait -ErrorAction SilentlyContinue | \
                 Where-Object {{ $_.LocalPort -eq {src_port} -and $_.RemotePort -eq {dst_port} -and $_.RemoteAddress -eq '{dst_ip}' }} | \
                 Select-Object -First 1; \
             if ($conn) {{ \
                 $p = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue; \
                 if ($p) {{ $p.ProcessName }} \
             }}",
            src_port = src.port(),
            dst_port = dst.port(),
            dst_ip = ps_single_quote(&dst.ip().to_string())
        ),
        TransportProtocol::Udp => format!(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $ep = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | \
                 Where-Object {{ $_.LocalPort -eq {src_port} }} | \
                 Select-Object -First 1; \
             if ($ep) {{ \
                 $p = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue; \
                 if ($p) {{ $p.ProcessName }} \
             }}",
            src_port = src.port(),
        ),
    };

    run_and_capture("powershell", &["-NoProfile", "-Command", &script])
}

#[cfg(target_os = "linux")]
fn find_process_name_for_flow_linux(
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    let output = match protocol {
        TransportProtocol::Tcp => run_and_capture(
            "ss",
            &[
                "-tnp",
                &format!(
                    "sport = :{} and dport = :{}",
                    src.port(),
                    dst.port()
                ),
            ],
        ),
        TransportProtocol::Udp => run_and_capture(
            "ss",
            &[
                "-unp",
                &format!("sport = :{}", src.port()),
            ],
        ),
    }?;

    parse_linux_ss_process_name(&output)
}

#[cfg(target_os = "linux")]
fn parse_linux_ss_process_name(ss_output: &str) -> Option<String> {
    let marker = "users:((\"";
    let start = ss_output.find(marker)? + marker.len();
    let rest = &ss_output[start..];
    let end = rest.find('"')?;
    let name = rest[..end].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(target_os = "macos")]
fn find_process_name_for_flow_macos(
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    let output = match protocol {
        TransportProtocol::Tcp => run_and_capture(
            "lsof",
            &[
                "-nP",
                &format!("-iTCP:{}", src.port()),
            ],
        ),
        TransportProtocol::Udp => run_and_capture(
            "lsof",
            &[
                "-nP",
                &format!("-iUDP:{}", src.port()),
            ],
        ),
    }?;

    parse_macos_lsof_process_name(&output, protocol, dst)
}

#[cfg(target_os = "macos")]
fn parse_macos_lsof_process_name(
    lsof_output: &str,
    protocol: TransportProtocol,
    dst: SocketAddr,
) -> Option<String> {
    for line in lsof_output.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }

        let name_col = cols[0].trim();
        if name_col.is_empty() {
            continue;
        }

        if protocol == TransportProtocol::Tcp {
            let target = format!("->{}:{}", dst.ip(), dst.port());
            if !line.contains(&target) {
                continue;
            }
        }

        return Some(name_col.to_string());
    }

    None
}

fn run_and_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(windows)]
fn ps_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}
