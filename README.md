# hppt-rs

`hppt-rs` is a Tokio-based Rust client for [hppt](https://github.com/codingmiao/hppt).
It implements Java-compatible `post`, `hppt`, and `websocket` client transports
and can forward local TCP ports through an existing Java hppt server. The Rust
server and Java `rhppt`, `rpost`, and `file` transport types are not
implemented.

## Run

Choose the same transport type as the Java server and configure its connection:

```yaml
type: post
clientUser: user1
clientPassword: "replace-with-the-server-password"
enableEncrypt: true

post:
  serverUrl: http://127.0.0.1:20871
  sendSleepTime: 5

forwards:
  - localHost: 127.0.0.1
    localPort: 10022
    remoteHost: 192.168.0.2
    remotePort: 22
```

The corresponding Java server must use `type: post`, listen on the matching
port, and authorize the configured `clientUser` / `clientPassword` pair. Then
start the client with:

```sh
cargo run --release -- sc sc.yml
```

Connect to `127.0.0.1:10022` to reach `192.168.0.2:22` through the Java server.
`serverUrl` may include an HTTP(S) reverse-proxy path, for example
`https://example.com/hppt`.

For the Java `hppt` TCP transport, use:

```yaml
type: hppt
clientUser: user1
clientPassword: "replace-with-the-server-password"
enableEncrypt: true

hppt:
  host: 127.0.0.1
  port: 20871
  lengthFieldLength: 3

forwards:
  - localHost: 127.0.0.1
    localPort: 10022
    remoteHost: 192.168.0.2
    remotePort: 22
```

For the Java `websocket` transport, set its base WebSocket URL (the client
connects to the `/s` endpoint):

```yaml
type: websocket
clientUser: user1
clientPassword: "replace-with-the-server-password"
enableEncrypt: true

websocket:
  serverUrl: ws://127.0.0.1:20871
  pingInterval: 30000

forwards:
  - localHost: 127.0.0.1
    localPort: 10022
    remoteHost: 192.168.0.2
    remotePort: 22
```

All transports use the Java `dt`/`login` handshake, `MessagePb` protobuf wire
format, and Java-compatible AES-128/ECB/PKCS5Padding key generation. `post`
uses `/s?c=...` and `/r?c=...` with `BytesListPb`; `hppt` uses big-endian
length-prefixed TCP frames; `websocket` sends protocol frames as binary
WebSocket messages. Encryption is enabled by default, matching the Java
client. Set `enableEncrypt: false` only when the Java server is configured the
same way.

Supported settings include `type`, `clientUser`, `clientPassword`,
`enableEncrypt`, `localHost`, `maxSendBodySize`, `heartbeatPeriod`, the
transport-specific `post`, `hppt`, and `websocket` blocks,
`transportReconnectBaseDelayMillis`, `transportReconnectMaxDelayMillis`,
`transportReconnectJitterMillis`, and `forwards`. The Java-compatible reconnect
defaults are 1s base, 15s maximum, and up to 300ms jitter. After a transport
failure, the client repeats the time/login handshake and reopens local
connections that were still awaiting session initialization. Established TCP
sessions are closed on transport loss and should be reopened by their local
applications.

The client uses bounded event, frame, and local TCP write queues. If a local
TCP peer cannot keep up and its bounded write queue fills, that one forwarded
session is closed instead of blocking unrelated sessions or growing memory
without limit. Local TCP write queues are capped at 10 MiB per session and
64 MiB total; at most 1024 local connections may wait for server-side session
initialization. POST response bodies above 32 MiB and individual server
protocol frames above 10 MiB are rejected. Outbound messages respect
`maxSendBodySize`; `hppt` frames also respect the configured length-field
capacity. Unknown YAML fields are ignored; duplicate local ports and
unsupported transport types fail explicitly rather than silently selecting a
different protocol. If a forwarding item repeats a field, the last value is
used and a warning identifies the repeated keys.

## Tests

```sh
cargo test
```

The tests cover the protobuf wire layout and AES key/ciphertext vectors
generated with the JDK's `SHA1PRNG` and `AES` providers, client configuration
validation, and transport reset/backoff behavior.
