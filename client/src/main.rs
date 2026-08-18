mod tunnel;

use std::io;

use tunnel::{ClientConfig, run_client};

const DEFAULT_VPN_ADDR: &str = "193.124.117.242";
const DEFAULT_VPN_PORT: u16 = 7878;

const DEFAULT_LOCAL_IP: &str = "10.8.0.2";
const DEFAULT_GATEWAY: &str = "10.8.0.1";
const DEFAULT_NETMASK: &str = "255.255.255.0";

fn main() -> io::Result<()> {
    let config = ClientConfig {
        server_addr: env_or("VPN_SERVER_ADDR", DEFAULT_VPN_ADDR),
        server_port: env_parse("VPN_SERVER_PORT").unwrap_or(DEFAULT_VPN_PORT),
        local_ip: env_or("TUN_LOCAL_IP", DEFAULT_LOCAL_IP).parse().map_err(|_| {
            io::Error::other("TUN_LOCAL_IP must be a valid IPv4 address")
        })?,
        gateway: env_or("TUN_GATEWAY", DEFAULT_GATEWAY).parse().map_err(|_| {
            io::Error::other("TUN_GATEWAY must be a valid IPv4 address")
        })?,
        netmask: env_or("TUN_NETMASK", DEFAULT_NETMASK).parse().map_err(|_| {
            io::Error::other("TUN_NETMASK must be a valid IPv4 address")
        })?,
        mtu: env_parse("TUN_MTU").unwrap_or(1500),
    };

    run_client(config)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse(key: &str) -> Option<u16> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}