use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
    /// Outbound interface for NAT masquerading (Linux only).
    pub nat_iface: Option<String>,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub allowed_tokens: Vec<String>,
    /// Optional path to a newline-separated allowlist file (merged with
    /// `allowed_tokens`; blank lines and `#` comments are ignored).
    pub allowed_tokens_file: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen_addr: "0.0.0.0:7878".to_string(),
            gateway: "10.8.0.1".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            mtu: 1500,
            nat_iface: None,
            auth: AuthConfig::default(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            allowed_tokens: Vec::new(),
            allowed_tokens_file: None,
        }
    }
}

impl ServerConfig {
    /// Load config from `path`. A missing file yields the defaults.
    pub fn load(path: &Path) -> io::Result<ServerConfig> {
        let raw = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ServerConfig::default()),
            Err(e) => return Err(e),
        };
        toml::from_str(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad config: {e}")))
    }

    /// Expanded set of authorized client tokens.
    pub fn allowed_tokens(&self) -> io::Result<HashSet<Vec<u8>>> {
        let mut tokens: HashSet<Vec<u8>> = self
            .auth
            .allowed_tokens
            .iter()
            .filter(|t| !t.is_empty())
            .map(|t| t.as_bytes().to_vec())
            .collect();

        if let Some(path) = &self.auth.allowed_tokens_file {
            let content = fs::read_to_string(path)?;
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    tokens.insert(line.as_bytes().to_vec());
                }
            }
        }

        Ok(tokens)
    }
}