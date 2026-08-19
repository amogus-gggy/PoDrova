use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct S {
    listen_addr: String,
    nat_iface: Option<String>,
}
impl Default for S {
    fn default() -> Self {
        S { listen_addr: "x".into(), nat_iface: None }
    }
}
fn main() {
    let raw = r#"
[server]
nat_iface = "eth0"
"#;
    let v: S = toml::from_str(raw).unwrap();
    println!("PARSED: {:?}", v);
}
