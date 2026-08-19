use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub tun: TunConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TunConfig {
    pub local_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            tun: TunConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            addr: "193.124.117.242".to_string(),
            port: 7878,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig { token: String::new() }
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            local_ip: "10.8.0.2".parse().unwrap(),
            gateway: "10.8.0.1".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            mtu: 1500,
        }
    }
}

impl ClientConfig {
    /// Load config from `path`. A missing file yields the defaults.
    pub fn load(path: &Path) -> io::Result<ClientConfig> {
        let raw = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ClientConfig::default()),
            Err(e) => return Err(e),
        };
        toml::from_str(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad config: {e}")))
    }
}