use thiserror::Error;

/// Unified error type for TinyTun.
///
/// Each variant carries a human-readable description.  Use the `From`
/// impls to convert from library-specific errors without manual mapping.
#[derive(Error, Debug)]
pub enum TinyTunError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Packet parsing error: {0}")]
    PacketParsing(String),

    #[error("SOCKS5 error: {0}")]
    Socks5(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Process lookup error: {0}")]
    ProcessLookup(String),

    #[error("Route management error: {0}")]
    Route(String),

    #[error("TUN device error: {0}")]
    TunDevice(String),

    #[error("DNS hijack error: {0}")]
    DnsHijack(String),

    #[error("eBPF loader error: {0}")]
    Ebpf(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<etherparse::err::ReadError> for TinyTunError {
    fn from(err: etherparse::err::ReadError) -> Self {
        TinyTunError::PacketParsing(format!("Etherparse error: {}", err))
    }
}

impl From<serde_json::Error> for TinyTunError {
    fn from(err: serde_json::Error) -> Self {
        TinyTunError::Config(format!("JSON parsing error: {}", err))
    }
}

impl From<serde_yaml::Error> for TinyTunError {
    fn from(err: serde_yaml::Error) -> Self {
        TinyTunError::Config(format!("YAML parsing error: {}", err))
    }
}

impl From<anyhow::Error> for TinyTunError {
    fn from(err: anyhow::Error) -> Self {
        TinyTunError::Internal(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for TinyTunError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        TinyTunError::Timeout(err.to_string())
    }
}
