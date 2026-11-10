use anyhow::{Context, Result, bail};
use serde::{
    Deserialize, Deserializer,
    de::{IgnoredAny, MapAccess, Visitor},
};
use std::fmt;
use std::{collections::HashSet, fs, path::Path};
use tracing::warn;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(rename = "type")]
    pub kind: String,
    pub client_user: String,
    pub client_password: String,
    #[serde(default = "default_true")]
    pub enable_encrypt: bool,
    #[serde(default)]
    pub local_host: Option<String>,
    #[serde(default = "default_max_send_body_size")]
    pub max_send_body_size: usize,
    #[serde(default = "default_heartbeat_period")]
    pub heartbeat_period: i64,
    #[serde(default = "default_reconnect_base_delay")]
    pub transport_reconnect_base_delay_millis: u64,
    #[serde(default = "default_reconnect_max_delay")]
    pub transport_reconnect_max_delay_millis: u64,
    #[serde(default = "default_reconnect_jitter")]
    pub transport_reconnect_jitter_millis: u64,
    #[serde(default)]
    pub post: PostConfig,
    #[serde(default)]
    pub hppt: HpptConfig,
    #[serde(default)]
    pub websocket: WebSocketConfig,
    #[serde(default)]
    pub forwards: Vec<Forward>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostConfig {
    pub server_url: String,
    #[serde(default = "default_send_sleep_time")]
    pub send_sleep_time: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HpptConfig {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_length_field_length")]
    pub length_field_length: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebSocketConfig {
    pub server_url: String,
    #[serde(default = "default_ping_interval")]
    pub ping_interval: i64,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            ping_interval: default_ping_interval(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Forward {
    pub local_host: Option<String>,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    duplicate_fields: Vec<String>,
}

impl<'de> Deserialize<'de> for Forward {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ForwardVisitor;

        impl<'de> Visitor<'de> for ForwardVisitor {
            type Value = Forward;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a forwarding configuration")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut local_host = None;
                let mut local_port = None;
                let mut remote_host = None;
                let mut remote_port = None;
                let mut seen = HashSet::new();
                let mut duplicate_fields = Vec::new();

                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        duplicate_fields.push(key.clone());
                    }
                    match key.as_str() {
                        "localHost" => local_host = map.next_value()?,
                        "localPort" => local_port = Some(map.next_value()?),
                        "remoteHost" => remote_host = Some(map.next_value()?),
                        "remotePort" => remote_port = Some(map.next_value()?),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                Ok(Forward {
                    local_host,
                    local_port: local_port
                        .ok_or_else(|| serde::de::Error::missing_field("localPort"))?,
                    remote_host: remote_host
                        .ok_or_else(|| serde::de::Error::missing_field("remoteHost"))?,
                    remote_port: remote_port
                        .ok_or_else(|| serde::de::Error::missing_field("remotePort"))?,
                    duplicate_fields,
                })
            }
        }

        deserializer.deserialize_map(ForwardVisitor)
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path.as_ref())
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        let config: Self = serde_yaml::from_str(&contents).context("parse YAML")?;
        for (index, forward) in config.forwards.iter().enumerate() {
            if !forward.duplicate_fields.is_empty() {
                warn!(
                    forward_index = index,
                    repeated_fields = %forward.duplicate_fields.join(", "),
                    "forward configuration contains duplicate keys; last values are used"
                );
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.client_user.is_empty() || self.client_password.is_empty() {
            bail!("clientUser and clientPassword must not be empty");
        }
        match self.kind.as_str() {
            "post" => {
                if self.post.server_url.is_empty() {
                    bail!("post.serverUrl must be set");
                }
                let url =
                    reqwest::Url::parse(&self.post.server_url).context("invalid post.serverUrl")?;
                if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                    bail!("post.serverUrl must be an absolute http:// or https:// URL");
                }
                if url.query().is_some() || url.fragment().is_some() {
                    bail!("post.serverUrl must not include a query or fragment");
                }
            }
            "hppt" => {
                if self.hppt.host.is_empty() || self.hppt.port == 0 {
                    bail!("hppt.host and hppt.port must be set");
                }
                if !(1..=4).contains(&self.hppt.length_field_length) {
                    bail!("hppt.lengthFieldLength must be between 1 and 4");
                }
            }
            "websocket" => {
                if self.websocket.server_url.is_empty() {
                    bail!("websocket.serverUrl must be set");
                }
                let url = reqwest::Url::parse(&self.websocket.server_url)
                    .context("invalid websocket.serverUrl")?;
                if !matches!(url.scheme(), "ws" | "wss") || url.host_str().is_none() {
                    bail!("websocket.serverUrl must be an absolute ws:// or wss:// URL");
                }
                if url.query().is_some() || url.fragment().is_some() {
                    bail!("websocket.serverUrl must not include a query or fragment");
                }
            }
            other => bail!("unsupported transport type {other:?}"),
        }
        if self.max_send_body_size == 0 {
            bail!("maxSendBodySize must be greater than zero");
        }
        if self.transport_reconnect_max_delay_millis < self.transport_reconnect_base_delay_millis {
            bail!("transportReconnectMaxDelayMillis must be >= transportReconnectBaseDelayMillis");
        }
        let mut local_ports = HashSet::with_capacity(self.forwards.len());
        for forward in &self.forwards {
            if forward.local_port == 0 || forward.remote_port == 0 {
                bail!("forward ports must be between 1 and 65535");
            }
            if forward.remote_host.is_empty() {
                bail!("forward remoteHost must not be empty");
            }
            if !local_ports.insert(forward.local_port) {
                bail!(
                    "localPort {} is configured more than once",
                    forward.local_port
                );
            }
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn default_max_send_body_size() -> usize {
    10 * 1024 * 1024
}

fn default_heartbeat_period() -> i64 {
    120_000
}

fn default_send_sleep_time() -> u64 {
    5
}

fn default_length_field_length() -> usize {
    3
}

fn default_ping_interval() -> i64 {
    30_000
}

fn default_reconnect_base_delay() -> u64 {
    1_000
}

fn default_reconnect_max_delay() -> u64 {
    15_000
}

fn default_reconnect_jitter() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).unwrap()
    }

    const BASE: &str = r#"
type: post
clientUser: rust
clientPassword: secret
post:
  serverUrl: http://localhost:20871/proxy/
forwards:
  - localPort: 10022
    remoteHost: localhost
    remotePort: 22
"#;

    #[test]
    fn defaults_match_java_client_and_accept_proxy_paths() {
        let parsed = config(BASE);
        parsed.validate().unwrap();
        assert!(parsed.enable_encrypt);
        assert_eq!(parsed.heartbeat_period, 120_000);
        assert_eq!(parsed.transport_reconnect_base_delay_millis, 1_000);
        assert_eq!(parsed.transport_reconnect_max_delay_millis, 15_000);
    }

    #[test]
    fn duplicate_local_ports_are_rejected() {
        let yaml =
            format!("{BASE}  - localPort: 10022\n    remoteHost: elsewhere\n    remotePort: 80\n");
        assert!(config(&yaml).validate().is_err());
    }

    #[test]
    fn reconnect_max_must_not_be_below_base() {
        let yaml = format!(
            "{BASE}transportReconnectBaseDelayMillis: 1000\ntransportReconnectMaxDelayMillis: 500\n"
        );
        assert!(config(&yaml).validate().is_err());
    }

    #[test]
    fn hppt_transport_accepts_java_length_field_sizes() {
        let parsed = config(
            r#"
type: hppt
clientUser: rust
clientPassword: secret
hppt:
  host: localhost
  port: 20871
  lengthFieldLength: 3
"#,
        );
        parsed.validate().unwrap();
        assert_eq!(parsed.hppt.length_field_length, 3);
    }

    #[test]
    fn hppt_transport_rejects_invalid_length_field_size() {
        let parsed = config(
            r#"
type: hppt
clientUser: rust
clientPassword: secret
hppt:
  host: localhost
  port: 20871
  lengthFieldLength: 5
"#,
        );
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn websocket_transport_accepts_ws_and_wss_urls() {
        for server_url in ["ws://localhost:20871", "wss://example.test/hppt"] {
            let yaml = format!(
                r#"
type: websocket
clientUser: rust
clientPassword: secret
websocket:
  serverUrl: {server_url}
"#
            );
            config(&yaml).validate().unwrap();
        }
    }

    #[test]
    fn duplicate_forward_fields_use_the_last_value_and_are_reported() {
        let parsed = config(
            r#"
type: hppt
clientUser: rust
clientPassword: secret
hppt:
  host: localhost
  port: 20871
forwards:
  - localPort: 15433
    remoteHost: 10.123.220.208
    remotePort: 15432
    remoteHost: 10.123.220.209
    remotePort: 9677
"#,
        );
        parsed.validate().unwrap();
        let forward = &parsed.forwards[0];
        assert_eq!(forward.local_port, 15433);
        assert_eq!(forward.remote_host, "10.123.220.209");
        assert_eq!(forward.remote_port, 9677);
        assert_eq!(forward.duplicate_fields, ["remoteHost", "remotePort"]);
    }
}
