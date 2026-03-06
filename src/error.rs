use thiserror::Error;

#[derive(Error, Debug)]
pub enum TinyTunError {
    #[error("TUN device error: {0}")]
    TunDevice(#[from] tun::Error),
    
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
}

impl From<etherparse::ReadError> for TinyTunError {
    fn from(err: etherparse::ReadError) -> Self {
        TinyTunError::PacketParsing(format!("Etherparse error: {}", err))
    }
}

impl From<serde_json::Error> for TinyTunError {
    fn from(err: serde_json::Error) -> Self {
        TinyTunError::Config(format!("JSON parsing error: {}", err))
    }
}