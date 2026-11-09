use crate::{
    config::Config,
    crypto::{JavaAes, grid_decrypt, grid_encrypt, session_cipher},
    protocol::{
        Message, SessionBytes, decode_bytes_list, decode_message, encode_bytes_list, encode_message,
    },
};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use rand::{Rng, RngCore};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::{self, Instant},
};
use tokio_tungstenite::{WebSocketStream, connect_async, tungstenite::Message as WebSocketMessage};

enum Event {
    Accepted {
        port: u16,
        stream: TcpStream,
    },
    LocalData {
        generation: u64,
        session_id: i32,
        bytes: Vec<u8>,
    },
    LocalClosed {
        generation: u64,
        session_id: i32,
    },
    LocalWriteFailed {
        generation: u64,
        session_id: i32,
        reason: String,
    },
    ServerFrame {
        generation: u64,
        bytes: Vec<u8>,
        _permit: OwnedSemaphorePermit,
    },
    TransportReset {
        generation: u64,
        reason: String,
    },
    Fatal(anyhow::Error),
}

const MAX_PENDING_LOCAL_CONNECTIONS: usize = 1024;
const MAX_PENDING_SESSION_BYTES: usize = 10 * 1024 * 1024;
const MAX_PENDING_SESSION_CHUNKS: usize = 1024;
const MAX_POST_BATCH_MESSAGES: usize = 1024;
const MAX_POST_BATCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_POST_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SERVER_FRAME_BYTES: usize = 10 * 1024 * 1024;
const MAX_POST_EVENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_LOCAL_WRITE_BYTES: usize = 64 * 1024 * 1024;
const TRANSPORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn run(config: Config) -> Result<()> {
    let (events_tx, mut events_rx) = mpsc::channel(4096);
    let (outbound_tx, outbound_rx) = mpsc::channel(4096);
    let (restart_tx, restart_rx) = mpsc::unbounded_channel();
    let frame_budget = Arc::new(Semaphore::new(MAX_POST_EVENT_BYTES));
    match config.kind.as_str() {
        "post" => {
            let base_url = config.post.server_url.trim_end_matches('/').to_owned();
            start_post_transport(
                config.clone(),
                outbound_rx,
                events_tx.clone(),
                restart_rx,
                Arc::clone(&frame_budget),
                base_url,
            );
        }
        "hppt" => start_hppt_transport(
            config.clone(),
            outbound_rx,
            events_tx.clone(),
            restart_rx,
            Arc::clone(&frame_budget),
        ),
        "websocket" => start_websocket_transport(
            config.clone(),
            outbound_rx,
            events_tx.clone(),
            restart_rx,
            frame_budget,
        ),
        _ => bail!("unsupported transport type {:?}", config.kind),
    }

    let mut listeners = Vec::new();
    for forward in &config.forwards {
        let host = forward
            .local_host
            .as_deref()
            .filter(|host| !host.is_empty())
            .or(config.local_host.as_deref())
            .filter(|host| !host.is_empty())
            .unwrap_or("0.0.0.0");
        let address = tokio::net::lookup_host((host, forward.local_port))
            .await
            .with_context(|| format!("resolve local bind address {host}:{}", forward.local_port))?
            .next()
            .with_context(|| format!("no address found for {host}:{}", forward.local_port))?;
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("bind local forward {address}"))?;
        eprintln!(
            "forward listening on {} -> {}:{}",
            listener.local_addr()?,
            forward.remote_host,
            forward.remote_port
        );
        listeners.push(listener);
    }

    for listener in listeners {
        let tx = events_tx.clone();
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        if let Err(error) = stream.set_nodelay(true) {
                            let _ = tx.send(Event::Fatal(error.into())).await;
                            return;
                        }
                        if let Err(error) = tx.send(Event::Accepted { port, stream }).await {
                            let _ = error.0;
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(Event::Fatal(error.into())).await;
                        return;
                    }
                }
            }
        });
    }

    let message_body_size = if config.kind == "hppt" {
        config.max_send_body_size.min(
            max_frame_size(config.hppt.length_field_length)?
                .saturating_sub(64)
                .max(1),
        )
    } else {
        config.max_send_body_size
    };
    let mut state = ClientState::new(message_body_size);
    let mut send_tick = time::interval(Duration::from_millis(5));
    let heartbeat_period = Duration::from_millis(config.heartbeat_period.max(1) as u64);
    let mut heartbeat_tick = time::interval(heartbeat_period);
    heartbeat_tick.tick().await;
    let mut last_server_heartbeat = Instant::now();
    let mut restart_requested = false;
    let mut pending_accepts = VecDeque::new();
    let mut pending_sessions: HashMap<u32, (u16, TcpStream)> = HashMap::new();
    let mut writers: HashMap<i32, LocalWriter> = HashMap::new();
    let mut reader_tasks: HashMap<i32, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut pending_data: HashMap<i32, Vec<Vec<u8>>> = HashMap::new();
    let global_write_budget = Arc::new(Semaphore::new(MAX_TOTAL_LOCAL_WRITE_BYTES));

    eprintln!(
        "connecting to Java hppt server using {} transport",
        config.kind
    );

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("listen for Ctrl-C")?;
                break;
            }
            event = events_rx.recv() => {
                let Some(event) = event else {
                    bail!("client event channel closed unexpectedly");
                };
                match event {
                    Event::Accepted { port, stream } => {
                        if pending_accepts.len() + pending_sessions.len()
                            >= MAX_PENDING_LOCAL_CONNECTIONS
                        {
                            eprintln!("too many pending local connections; rejecting port {port}");
                            drop(stream);
                            continue;
                        }
                        pending_accepts.push_back((port, stream));
                        if state.logged_in {
                            send_pending_accepts(
                                &config,
                                &mut pending_accepts,
                                &mut pending_sessions,
                                &mut state,
                            );
                        }
                    }
                    Event::LocalData { generation, session_id, bytes } => {
                        if generation == state.generation {
                            state.session_bytes.push_back(SessionBytes { session_id, bytes });
                        }
                    }
                    Event::LocalClosed { generation, session_id } => {
                        if generation != state.generation {
                            continue;
                        }
                        let existed = writers.remove(&session_id).is_some();
                        if let Some(task) = reader_tasks.remove(&session_id) {
                            task.abort();
                        }
                        pending_data.remove(&session_id);
                        if existed && state.logged_in {
                            state.commands.push_back(format!("1{session_id}"));
                        }
                    }
                    Event::LocalWriteFailed { generation, session_id, reason } => {
                        if generation != state.generation {
                            continue;
                        }
                        eprintln!("local session {session_id} write failed: {reason}");
                        let existed = writers.remove(&session_id).is_some();
                        if let Some(task) = reader_tasks.remove(&session_id) {
                            task.abort();
                        }
                        pending_data.remove(&session_id);
                        if existed && state.logged_in {
                            state.commands.push_back(format!("1{session_id}"));
                        }
                    }
                    Event::ServerFrame { generation, bytes: frame, _permit } => {
                        if generation != state.generation {
                            continue;
                        }
                        if !state.logged_in {
                            process_handshake(
                                &config,
                                &frame,
                                &outbound_tx,
                                &mut state,
                            ).await?;
                            if state.logged_in {
                                last_server_heartbeat = Instant::now();
                                restart_requested = false;
                                eprintln!("logged in as {}", config.client_user);
                                send_pending_accepts(
                                    &config,
                                    &mut pending_accepts,
                                    &mut pending_sessions,
                                    &mut state,
                                );
                            }
                            continue;
                        }
                        let message = decode_server_message(&config, &state, &frame)?;
                        for command in message.commands {
                            process_server_command(
                                command,
                                &mut state,
                                CommandContext {
                                    pending_sessions: &mut pending_sessions,
                                    writers: &mut writers,
                                    reader_tasks: &mut reader_tasks,
                                    pending_data: &mut pending_data,
                                    last_server_heartbeat: &mut last_server_heartbeat,
                                    events_tx: &events_tx,
                                    global_write_budget: &global_write_budget,
                                },
                            )
                            ?;
                        }
                        for data in message.sessions {
                            if let Some(writer) = writers.get(&data.session_id) {
                                if let Err(error) = writer.try_write(data.bytes) {
                                    eprintln!("local session {} write queue failed: {error}", data.session_id);
                                    writers.remove(&data.session_id);
                                    if let Some(task) = reader_tasks.remove(&data.session_id) {
                                        task.abort();
                                    }
                                    state.commands.push_back(format!("1{}", data.session_id));
                                }
                            } else {
                                let chunks = pending_data.entry(data.session_id).or_default();
                                let pending_size = chunks.iter().map(Vec::len).sum::<usize>();
                                if pending_size.saturating_add(data.bytes.len())
                                    > MAX_PENDING_SESSION_BYTES
                                    || chunks.len() >= MAX_PENDING_SESSION_CHUNKS
                                {
                                    eprintln!(
                                        "discarding oversized pre-init data for session {}",
                                        data.session_id
                                    );
                                    pending_data.remove(&data.session_id);
                                    state.commands.push_back(format!("1{}", data.session_id));
                                } else {
                                    pending_data.entry(data.session_id).or_default().push(data.bytes);
                                }
                            }
                        }
                    }
                    Event::TransportReset { generation, reason } => {
                        eprintln!("transport disconnected: {reason}; reconnecting");
                        pending_accepts.extend(pending_sessions.drain().map(|(_, (port, stream))| (port, stream)));
                        for task in reader_tasks.drain().map(|(_, task)| task) {
                            task.abort();
                        }
                        writers.clear();
                        pending_data.clear();
                        state.reset_for_transport(generation);
                        restart_requested = false;
                    }
                    Event::Fatal(error) => return Err(error).context("background client task failed"),
                }
            }
            _ = send_tick.tick() => {
                if state.logged_in
                    && let Some(message) = state.take_outbound_message()
                {
                    let bytes = encode_message(&message);
                    let bytes = if config.enable_encrypt {
                        state.cipher.as_ref().expect("authenticated cipher").encrypt(&bytes)
                    } else {
                        bytes
                    };
                    outbound_tx.send(bytes).await.context("queue client protocol message")?;
                }
            }
            _ = heartbeat_tick.tick(), if config.heartbeat_period > 0 && state.logged_in => {
                if last_server_heartbeat.elapsed() > heartbeat_period.saturating_mul(3)
                    && !restart_requested
                {
                    restart_requested = true;
                    let _ = restart_tx.send("server heartbeat timeout".to_owned());
                } else {
                    state.commands.push_back(format!("3:{}", unix_time_millis()));
                }
            }
        }
    }

    eprintln!("shutting down local forwards");
    Ok(())
}

struct ClientState {
    generation: u64,
    dt_ms: Option<i64>,
    cipher: Option<JavaAes>,
    login_sent: bool,
    login_attempts: u8,
    logged_in: bool,
    next_init_flag: u32,
    max_send_body_size: usize,
    commands: VecDeque<String>,
    session_bytes: VecDeque<SessionBytes>,
}

impl ClientState {
    fn new(max_send_body_size: usize) -> Self {
        Self {
            generation: 1,
            dt_ms: None,
            cipher: None,
            login_sent: false,
            login_attempts: 0,
            logged_in: false,
            next_init_flag: 0,
            max_send_body_size,
            commands: VecDeque::new(),
            session_bytes: VecDeque::new(),
        }
    }

    fn reset_for_transport(&mut self, generation: u64) {
        self.generation = generation;
        self.dt_ms = None;
        self.cipher = None;
        self.login_sent = false;
        self.login_attempts = 0;
        self.logged_in = false;
        self.commands.clear();
        self.session_bytes.clear();
    }

    fn take_outbound_message(&mut self) -> Option<Message> {
        if self.commands.is_empty() && self.session_bytes.is_empty() {
            return None;
        }
        let mut message = Message::default();
        let mut body_size = 0;
        while let Some(command) = self.commands.pop_front() {
            body_size += command.len() + 1;
            message.commands.push(command);
            if body_size >= self.max_send_body_size {
                break;
            }
        }
        while body_size < self.max_send_body_size {
            let Some(session) = self.session_bytes.pop_front() else {
                break;
            };
            body_size += session.bytes.len();
            message.sessions.push(session);
            if body_size >= self.max_send_body_size {
                break;
            }
        }
        if message.commands.is_empty() && message.sessions.is_empty() {
            return None;
        }
        Some(message)
    }
}

async fn process_handshake(
    config: &Config,
    frame: &[u8],
    outbound_tx: &mpsc::Sender<Vec<u8>>,
    state: &mut ClientState,
) -> Result<()> {
    let plaintext = grid_decrypt(frame).context("decrypt Java server handshake")?;
    let text = std::str::from_utf8(&plaintext).context("decode Java server handshake")?;
    let (command, parameter) = text.split_once(' ').unwrap_or((text, ""));

    match command {
        "dt" => {
            let server_time: i64 = parameter.parse().context("parse server time")?;
            let dt = server_time - unix_time_millis();
            state.dt_ms = Some(dt);
            let cipher = session_cipher(&config.client_password, unix_time_millis() + dt);
            let password_code = STANDARD.encode(cipher.encrypt(config.client_password.as_bytes()));
            let login = format!("login {} {password_code}", config.client_user);
            outbound_tx
                .send(grid_encrypt(login.as_bytes()))
                .await
                .context("queue login request")?;
            state.cipher = Some(cipher);
            state.login_sent = true;
            state.login_attempts = 1;
            eprintln!("time synchronized with Java server (offset {dt} ms)");
        }
        "login" if parameter == "0" => {
            if !state.login_sent {
                bail!("Java server acknowledged login before a login request was sent");
            }
            state.logged_in = true;
        }
        "login" => {
            if state.login_attempts >= 2 {
                bail!("Java server rejected login with code {parameter}");
            }
            let dt = state
                .dt_ms
                .context("server login response arrived before time sync")?;
            let cipher = session_cipher(&config.client_password, unix_time_millis() + dt);
            let password_code = STANDARD.encode(cipher.encrypt(config.client_password.as_bytes()));
            let login = format!("login {} {password_code}", config.client_user);
            outbound_tx
                .send(grid_encrypt(login.as_bytes()))
                .await
                .context("queue login retry")?;
            state.cipher = Some(cipher);
            state.login_attempts += 1;
            eprintln!(
                "Java server rejected the first login attempt; retrying with a fresh time key"
            );
        }
        other => bail!("unexpected Java handshake command {other:?}"),
    }
    Ok(())
}

fn decode_server_message(config: &Config, state: &ClientState, frame: &[u8]) -> Result<Message> {
    let plaintext = if config.enable_encrypt {
        state
            .cipher
            .as_ref()
            .context("missing authenticated cipher")?
            .decrypt(frame)
            .context("decrypt Java server message")?
    } else {
        frame.to_vec()
    };
    decode_message(&plaintext).context("decode Java protobuf message")
}

struct CommandContext<'a> {
    pending_sessions: &'a mut HashMap<u32, (u16, TcpStream)>,
    writers: &'a mut HashMap<i32, LocalWriter>,
    reader_tasks: &'a mut HashMap<i32, tokio::task::JoinHandle<()>>,
    pending_data: &'a mut HashMap<i32, Vec<Vec<u8>>>,
    last_server_heartbeat: &'a mut Instant,
    events_tx: &'a mpsc::Sender<Event>,
    global_write_budget: &'a Arc<Semaphore>,
}

fn process_server_command(
    command: String,
    state: &mut ClientState,
    ctx: CommandContext<'_>,
) -> Result<()> {
    let Some((kind, parameter)) = command.split_at_checked(1) else {
        bail!("Java server sent an empty command");
    };
    match kind {
        "0" => {
            let (session, flag) = parameter
                .split_once(',')
                .context("invalid init-session command")?;
            let session_id: i32 = session.parse().context("invalid session id")?;
            let flag: u32 = flag.parse().context("invalid session init flag")?;
            if let Some((_, stream)) = ctx.pending_sessions.remove(&flag) {
                let (reader, writer) = stream.into_split();
                ctx.writers.insert(
                    session_id,
                    LocalWriter::new(
                        state.generation,
                        session_id,
                        writer,
                        ctx.events_tx.clone(),
                        MAX_PENDING_SESSION_BYTES,
                        Arc::clone(ctx.global_write_budget),
                    ),
                );
                ctx.reader_tasks.insert(
                    session_id,
                    start_local_reader(
                        state.generation,
                        session_id,
                        reader,
                        ctx.events_tx.clone(),
                        state.max_send_body_size.min(16 * 1024),
                    ),
                );
                if let Some(chunks) = ctx.pending_data.remove(&session_id)
                    && let Some(writer) = ctx.writers.get(&session_id)
                {
                    for chunk in chunks {
                        if let Err(error) = writer.try_write(chunk) {
                            eprintln!("local session {session_id} queued write failed: {error}");
                            ctx.writers.remove(&session_id);
                            if let Some(task) = ctx.reader_tasks.remove(&session_id) {
                                task.abort();
                            }
                            state.commands.push_back(format!("1{session_id}"));
                            break;
                        }
                    }
                }
            } else {
                eprintln!("server initialized unknown local connection flag {flag}");
                state.commands.push_back(format!("1{session_id}"));
            }
        }
        "1" => {
            let session_id: i32 = parameter
                .parse()
                .context("invalid active-check session id")?;
            if ctx.writers.contains_key(&session_id) {
                state.commands.push_back(format!("2{session_id}"));
            } else {
                state.commands.push_back(format!("1{session_id}"));
            }
        }
        "2" => {
            let session_id: i32 = parameter.parse().context("invalid close-session id")?;
            ctx.writers.remove(&session_id);
            if let Some(task) = ctx.reader_tasks.remove(&session_id) {
                task.abort();
            }
            ctx.pending_data.remove(&session_id);
        }
        "3" => *ctx.last_server_heartbeat = Instant::now(),
        other => bail!("unknown Java server command {other:?}"),
    }
    Ok(())
}

struct QueuedBytes {
    bytes: Vec<u8>,
    _session_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
}

struct LocalWriter {
    sender: mpsc::Sender<QueuedBytes>,
    session_budget: Arc<Semaphore>,
    global_budget: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}

impl LocalWriter {
    fn new(
        generation: u64,
        session_id: i32,
        mut writer: OwnedWriteHalf,
        events_tx: mpsc::Sender<Event>,
        max_queued_bytes: usize,
        global_budget: Arc<Semaphore>,
    ) -> Self {
        let session_budget = Arc::new(Semaphore::new(max_queued_bytes));
        let (sender, mut receiver) = mpsc::channel::<QueuedBytes>(256);
        let task = tokio::spawn(async move {
            while let Some(queued) = receiver.recv().await {
                if let Err(error) = writer.write_all(&queued.bytes).await {
                    let _ = events_tx
                        .send(Event::LocalWriteFailed {
                            generation,
                            session_id,
                            reason: error.to_string(),
                        })
                        .await;
                    return;
                }
            }
        });
        Self {
            sender,
            session_budget,
            global_budget,
            task,
        }
    }

    fn try_write(&self, bytes: Vec<u8>) -> Result<(), String> {
        let amount = u32::try_from(bytes.len())
            .map_err(|_| "TCP frame exceeds the local write queue capacity".to_owned())?;
        let global_permit = self
            .global_budget
            .clone()
            .try_acquire_many_owned(amount)
            .map_err(|_| "global local TCP write budget is full".to_owned())?;
        let session_permit = self
            .session_budget
            .clone()
            .try_acquire_many_owned(amount)
            .map_err(|_| {
                "local TCP receiver is too slow; bounded write queue is full".to_owned()
            })?;
        self.sender
            .try_send(QueuedBytes {
                bytes,
                _session_permit: session_permit,
                _global_permit: global_permit,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    "local TCP write task queue is full".to_owned()
                }
                mpsc::error::TrySendError::Closed(_) => {
                    "local TCP write task has stopped".to_owned()
                }
            })
    }
}

impl Drop for LocalWriter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn send_pending_accepts(
    config: &Config,
    pending_accepts: &mut VecDeque<(u16, TcpStream)>,
    pending_sessions: &mut HashMap<u32, (u16, TcpStream)>,
    state: &mut ClientState,
) {
    while let Some((port, stream)) = pending_accepts.pop_front() {
        let Some(forward) = config
            .forwards
            .iter()
            .find(|forward| forward.local_port == port)
        else {
            eprintln!("accepted connection for unconfigured local port {port}");
            continue;
        };
        state.next_init_flag = state.next_init_flag.wrapping_add(1).max(1);
        let init_flag = state.next_init_flag;
        let command = format!(
            "0{},{},{}",
            forward.remote_host, forward.remote_port, init_flag
        );
        pending_sessions.insert(init_flag, (port, stream));
        state.commands.push_back(command);
    }
}

fn start_local_reader(
    generation: u64,
    session_id: i32,
    mut reader: OwnedReadHalf,
    events_tx: mpsc::Sender<Event>,
    chunk_size: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; chunk_size.max(1)];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    let _ = events_tx
                        .send(Event::LocalClosed {
                            generation,
                            session_id,
                        })
                        .await;
                    return;
                }
                Ok(size) => {
                    if events_tx
                        .send(Event::LocalData {
                            generation,
                            session_id,
                            bytes: buffer[..size].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("local session {session_id} read failed: {error}");
                    let _ = events_tx
                        .send(Event::LocalClosed {
                            generation,
                            session_id,
                        })
                        .await;
                    return;
                }
            }
        }
    })
}

fn start_post_transport(
    config: Config,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    mut restart_rx: mpsc::UnboundedReceiver<String>,
    frame_budget: Arc<Semaphore>,
    base_url: String,
) {
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(90))
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                let _ = events_tx.send(Event::Fatal(error.into())).await;
                return;
            }
        };

        let mut generation = 1_u64;
        let failures = Arc::new(AtomicU32::new(0));
        loop {
            while outbound_rx.try_recv().is_ok() {}
            let cookie = uuid_string();
            let result = run_post_generation(
                &client,
                &mut outbound_rx,
                &events_tx,
                PostGeneration {
                    base_url: &base_url,
                    cookie: &cookie,
                    generation,
                    send_sleep_time: config.post.send_sleep_time,
                    failures: Arc::clone(&failures),
                    frame_budget: Arc::clone(&frame_budget),
                },
                &mut restart_rx,
            )
            .await;
            let Err(error) = result else {
                return;
            };
            if outbound_rx.is_closed() {
                return;
            }
            let failure_count = failures.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            let delay = reconnect_delay(
                config.transport_reconnect_base_delay_millis,
                config.transport_reconnect_max_delay_millis,
                config.transport_reconnect_jitter_millis,
                failure_count,
            );
            generation = generation.wrapping_add(1).max(1);
            if events_tx
                .send(Event::TransportReset {
                    generation,
                    reason: format!("{error:#}"),
                })
                .await
                .is_err()
            {
                return;
            }
            eprintln!("POST transport attempt {failure_count} failed; retrying in {delay} ms");
            time::sleep(Duration::from_millis(delay)).await;
        }
    });
}

struct PostGeneration<'a> {
    base_url: &'a str,
    cookie: &'a str,
    generation: u64,
    send_sleep_time: u64,
    failures: Arc<AtomicU32>,
    frame_budget: Arc<Semaphore>,
}

async fn run_post_generation(
    client: &reqwest::Client,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    events_tx: &mpsc::Sender<Event>,
    generation: PostGeneration<'_>,
    restart_rx: &mut mpsc::UnboundedReceiver<String>,
) -> Result<()> {
    let send_url = format!("{}/s?c={}", generation.base_url, generation.cookie);
    let reply_url = format!("{}/r?c={}", generation.base_url, generation.cookie);
    tokio::select! {
        result = post_send_loop(
            client,
            outbound_rx,
            &send_url,
            generation.send_sleep_time,
            Arc::clone(&generation.failures),
        ) => {
            result.context("POST sender stopped")
        }
        result = post_receive_loop(
            client,
            events_tx,
            &reply_url,
            generation.send_sleep_time,
            generation.generation,
            Arc::clone(&generation.failures),
            Arc::clone(&generation.frame_budget),
        ) => {
            result.context("POST receiver stopped")
        }
        reason = restart_rx.recv() => {
            bail!("transport restart requested: {}", reason.unwrap_or_else(|| "restart channel closed".to_owned()))
        }
    }
}

async fn post_send_loop(
    client: &reqwest::Client,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    url: &str,
    send_sleep_time: u64,
    failures: Arc<AtomicU32>,
) -> Result<()> {
    let mut initial_frame = Some(grid_encrypt(b"dt"));
    let mut pending_frame = None;
    loop {
        let first = if let Some(frame) = pending_frame.take() {
            frame
        } else if let Some(frame) = initial_frame.take() {
            frame
        } else if let Some(frame) = outbound_rx.recv().await {
            frame
        } else {
            bail!("outbound queue closed");
        };
        let mut messages = vec![first];
        let mut batch_size = messages[0].len();
        if send_sleep_time > 0 {
            time::sleep(Duration::from_millis(send_sleep_time)).await;
        }
        while messages.len() < MAX_POST_BATCH_MESSAGES && batch_size < MAX_POST_BATCH_BYTES {
            let Ok(bytes) = outbound_rx.try_recv() else {
                break;
            };
            if !messages.is_empty() && batch_size.saturating_add(bytes.len()) > MAX_POST_BATCH_BYTES
            {
                pending_frame = Some(bytes);
                break;
            }
            batch_size = batch_size.saturating_add(bytes.len());
            messages.push(bytes);
        }
        let body = encode_bytes_list(&messages);
        let mut response = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await
            .context("send POST /s request")?;
        let status = response.status();
        if !status.is_success() {
            bail!("POST /s returned HTTP {status}");
        }
        if response
            .chunk()
            .await
            .context("read POST /s response")?
            .is_some()
        {
            bail!("POST /s returned an unexpected non-empty response body");
        }
        failures.store(0, Ordering::Relaxed);
    }
}

async fn post_receive_loop(
    client: &reqwest::Client,
    events_tx: &mpsc::Sender<Event>,
    url: &str,
    send_sleep_time: u64,
    generation: u64,
    failures: Arc<AtomicU32>,
    frame_budget: Arc<Semaphore>,
) -> Result<()> {
    loop {
        let response = client
            .post(url)
            .send()
            .await
            .context("send POST /r request")?;
        let status = response.status();
        if !status.is_success() {
            bail!("POST /r returned HTTP {status}");
        }
        let body = read_bounded_response(response).await?;
        if !body.is_empty() {
            for frame in decode_bytes_list(&body).context("decode Java BytesListPb")? {
                if frame.len() > MAX_SERVER_FRAME_BYTES {
                    bail!("Java server frame exceeds {} bytes", MAX_SERVER_FRAME_BYTES);
                }
                let permit = frame_budget
                    .clone()
                    .acquire_many_owned(frame.len() as u32)
                    .await
                    .context("acquire bounded server-frame queue capacity")?;
                events_tx
                    .send(Event::ServerFrame {
                        generation,
                        bytes: frame,
                        _permit: permit,
                    })
                    .await
                    .context("deliver server frame")?;
            }
        }
        failures.store(0, Ordering::Relaxed);
        if send_sleep_time > 0 {
            time::sleep(Duration::from_millis(send_sleep_time)).await;
        }
    }
}

async fn read_bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_POST_RESPONSE_BYTES as u64)
    {
        bail!("POST /r response exceeds {} bytes", MAX_POST_RESPONSE_BYTES);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read POST /r response")? {
        if body.len().saturating_add(chunk.len()) > MAX_POST_RESPONSE_BYTES {
            bail!("POST /r response exceeds {} bytes", MAX_POST_RESPONSE_BYTES);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn start_hppt_transport(
    config: Config,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    mut restart_rx: mpsc::UnboundedReceiver<String>,
    frame_budget: Arc<Semaphore>,
) {
    tokio::spawn(async move {
        let host = config.hppt.host.clone();
        let port = config.hppt.port;
        let length_field_length = config.hppt.length_field_length;
        let failures = Arc::new(AtomicU32::new(0));
        let mut generation = 1_u64;
        loop {
            while outbound_rx.try_recv().is_ok() {}
            let result = async {
                let stream = time::timeout(
                    TRANSPORT_CONNECT_TIMEOUT,
                    TcpStream::connect((host.as_str(), port)),
                )
                .await
                .context("hppt TCP connect timed out")?
                .with_context(|| format!("connect hppt server {host}:{port}"))?;
                stream.set_nodelay(true).context("set TCP_NODELAY")?;
                run_hppt_generation(
                    stream,
                    StreamContext {
                        outbound_rx: &mut outbound_rx,
                        events_tx: &events_tx,
                        restart_rx: &mut restart_rx,
                        frame_budget: &frame_budget,
                        failures: Arc::clone(&failures),
                        generation,
                    },
                    length_field_length,
                )
                .await
            }
            .await;
            let Err(error) = result else {
                return;
            };
            if outbound_rx.is_closed() {
                return;
            }
            let failures_count = failures.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            let delay = reconnect_delay(
                config.transport_reconnect_base_delay_millis,
                config.transport_reconnect_max_delay_millis,
                config.transport_reconnect_jitter_millis,
                failures_count,
            );
            generation = generation.wrapping_add(1).max(1);
            if events_tx
                .send(Event::TransportReset {
                    generation,
                    reason: format!("{error:#}"),
                })
                .await
                .is_err()
            {
                return;
            }
            eprintln!("hppt transport attempt {failures_count} failed; retrying in {delay} ms");
            time::sleep(Duration::from_millis(delay)).await;
        }
    });
}

async fn run_hppt_generation(
    stream: TcpStream,
    context: StreamContext<'_>,
    length_field_length: usize,
) -> Result<()> {
    let StreamContext {
        outbound_rx,
        events_tx,
        restart_rx,
        frame_budget,
        failures,
        generation,
    } = context;
    let (mut reader, mut writer) = stream.into_split();
    write_hppt_frame(&mut writer, &grid_encrypt(b"dt"), length_field_length)
        .await
        .context("send hppt time synchronization frame")?;
    tokio::select! {
        result = hppt_send_loop(&mut writer, outbound_rx, length_field_length, Arc::clone(&failures)) => {
            result.context("hppt sender stopped")
        }
        result = hppt_receive_loop(&mut reader, events_tx, frame_budget, generation, length_field_length, failures) => {
            result.context("hppt receiver stopped")
        }
        reason = restart_rx.recv() => {
            bail!("transport restart requested: {}", reason.unwrap_or_else(|| "restart channel closed".to_owned()))
        }
    }
}

async fn hppt_send_loop(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    length_field_length: usize,
    failures: Arc<AtomicU32>,
) -> Result<()> {
    while let Some(frame) = outbound_rx.recv().await {
        write_hppt_frame(writer, &frame, length_field_length)
            .await
            .context("write hppt frame")?;
        failures.store(0, Ordering::Relaxed);
    }
    bail!("outbound queue closed")
}

async fn hppt_receive_loop(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    events_tx: &mpsc::Sender<Event>,
    frame_budget: &Arc<Semaphore>,
    generation: u64,
    length_field_length: usize,
    failures: Arc<AtomicU32>,
) -> Result<()> {
    loop {
        let frame = read_hppt_frame(reader, length_field_length)
            .await
            .context("read hppt frame")?;
        failures.store(0, Ordering::Relaxed);
        queue_server_frame(events_tx, frame_budget, generation, frame)
            .await
            .context("deliver hppt frame")?;
    }
}

async fn write_hppt_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    payload: &[u8],
    length_field_length: usize,
) -> Result<()> {
    let header = encode_hppt_header(payload.len(), length_field_length)?;
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    Ok(())
}

async fn read_hppt_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    length_field_length: usize,
) -> Result<Vec<u8>> {
    let mut header = vec![0_u8; length_field_length];
    reader.read_exact(&mut header).await?;
    let mut length = 0_usize;
    for byte in header {
        length = (length << 8) | byte as usize;
    }
    if length > MAX_SERVER_FRAME_BYTES {
        bail!("hppt frame exceeds {} bytes", MAX_SERVER_FRAME_BYTES);
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

fn max_frame_size(length_field_length: usize) -> Result<usize> {
    if !(1..=4).contains(&length_field_length) {
        bail!("lengthFieldLength must be between 1 and 4");
    }
    Ok(if length_field_length == 4 {
        u32::MAX as usize
    } else {
        (1_usize << (length_field_length * 8)) - 1
    })
}

fn encode_hppt_header(payload_size: usize, length_field_length: usize) -> Result<Vec<u8>> {
    let max_size = max_frame_size(length_field_length)?;
    if payload_size > max_size {
        bail!(
            "hppt frame of {payload_size} bytes exceeds {}-byte length field capacity ({max_size})",
            length_field_length
        );
    }
    let mut header = vec![0_u8; length_field_length];
    let mut length = payload_size;
    for byte in header.iter_mut().rev() {
        *byte = (length & 0xff) as u8;
        length >>= 8;
    }
    Ok(header)
}

fn start_websocket_transport(
    config: Config,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    mut restart_rx: mpsc::UnboundedReceiver<String>,
    frame_budget: Arc<Semaphore>,
) {
    tokio::spawn(async move {
        let base_url = config.websocket.server_url.trim_end_matches('/');
        let url = format!("{base_url}/s");
        let failures = Arc::new(AtomicU32::new(0));
        let mut generation = 1_u64;
        loop {
            while outbound_rx.try_recv().is_ok() {}
            let result = async {
                let (socket, _) = time::timeout(TRANSPORT_CONNECT_TIMEOUT, connect_async(&url))
                    .await
                    .context("websocket connect timed out")?
                    .with_context(|| format!("connect websocket {url}"))?;
                run_websocket_generation(
                    socket,
                    StreamContext {
                        outbound_rx: &mut outbound_rx,
                        events_tx: &events_tx,
                        restart_rx: &mut restart_rx,
                        frame_budget: &frame_budget,
                        failures: Arc::clone(&failures),
                        generation,
                    },
                    config.websocket.ping_interval,
                )
                .await
            }
            .await;
            let Err(error) = result else {
                return;
            };
            if outbound_rx.is_closed() {
                return;
            }
            let failures_count = failures.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            let delay = reconnect_delay(
                config.transport_reconnect_base_delay_millis,
                config.transport_reconnect_max_delay_millis,
                config.transport_reconnect_jitter_millis,
                failures_count,
            );
            generation = generation.wrapping_add(1).max(1);
            if events_tx
                .send(Event::TransportReset {
                    generation,
                    reason: format!("{error:#}"),
                })
                .await
                .is_err()
            {
                return;
            }
            eprintln!(
                "websocket transport attempt {failures_count} failed; retrying in {delay} ms"
            );
            time::sleep(Duration::from_millis(delay)).await;
        }
    });
}

struct StreamContext<'a> {
    outbound_rx: &'a mut mpsc::Receiver<Vec<u8>>,
    events_tx: &'a mpsc::Sender<Event>,
    restart_rx: &'a mut mpsc::UnboundedReceiver<String>,
    frame_budget: &'a Arc<Semaphore>,
    failures: Arc<AtomicU32>,
    generation: u64,
}

async fn run_websocket_generation<S>(
    mut socket: WebSocketStream<S>,
    context: StreamContext<'_>,
    ping_interval_millis: i64,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let StreamContext {
        outbound_rx,
        events_tx,
        restart_rx,
        frame_budget,
        failures,
        generation,
    } = context;
    socket
        .send(WebSocketMessage::Binary(grid_encrypt(b"dt").into()))
        .await
        .context("send websocket time synchronization message")?;
    let mut ping_tick = time::interval(Duration::from_millis(ping_interval_millis.max(1) as u64));
    ping_tick.tick().await;
    loop {
        tokio::select! {
            outbound = outbound_rx.recv() => {
                let Some(frame) = outbound else {
                    bail!("outbound queue closed");
                };
                socket.send(WebSocketMessage::Binary(frame.into())).await.context("send websocket binary message")?;
                failures.store(0, Ordering::Relaxed);
            }
            incoming = socket.next() => {
                let Some(incoming) = incoming else {
                    bail!("websocket server closed the connection");
                };
                match incoming.context("read websocket message")? {
                    WebSocketMessage::Binary(frame) => {
                        failures.store(0, Ordering::Relaxed);
                        queue_server_frame(events_tx, frame_budget, generation, frame.to_vec()).await?;
                    }
                    WebSocketMessage::Ping(payload) => {
                        socket.send(WebSocketMessage::Pong(payload)).await.context("reply to websocket ping")?;
                    }
                    WebSocketMessage::Close(frame) => {
                        bail!("websocket closed: {frame:?}");
                    }
                    WebSocketMessage::Text(_) | WebSocketMessage::Pong(_) => {}
                    _ => {}
                }
            }
            _ = ping_tick.tick(), if ping_interval_millis > 0 => {
                socket.send(WebSocketMessage::Ping(Vec::new().into())).await.context("send websocket ping")?;
            }
            reason = restart_rx.recv() => {
                bail!("transport restart requested: {}", reason.unwrap_or_else(|| "restart channel closed".to_owned()))
            }
        }
    }
}

async fn queue_server_frame(
    events_tx: &mpsc::Sender<Event>,
    frame_budget: &Arc<Semaphore>,
    generation: u64,
    bytes: Vec<u8>,
) -> Result<()> {
    if bytes.len() > MAX_SERVER_FRAME_BYTES {
        bail!("Java server frame exceeds {} bytes", MAX_SERVER_FRAME_BYTES);
    }
    let permit = frame_budget
        .clone()
        .acquire_many_owned(bytes.len() as u32)
        .await
        .context("acquire bounded server-frame queue capacity")?;
    events_tx
        .send(Event::ServerFrame {
            generation,
            bytes,
            _permit: permit,
        })
        .await
        .context("deliver server frame")
}

fn reconnect_delay(base_ms: u64, max_ms: u64, jitter_ms: u64, failures: u32) -> u64 {
    let multiplier = 1_u64
        .checked_shl(failures.saturating_sub(1).min(63))
        .unwrap_or(u64::MAX);
    let exponential = base_ms.saturating_mul(multiplier).min(max_ms);
    let jitter = if jitter_ms == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=jitter_ms.min(u64::MAX - exponential))
    };
    exponential.saturating_add(jitter).min(max_ms)
}

fn unix_time_millis() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after Unix epoch")
            .as_millis(),
    )
    .expect("current timestamp fits in i64")
}

fn uuid_string() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_is_32_lowercase_hex_characters() {
        let cookie = uuid_string();
        assert_eq!(cookie.len(), 32);
        assert!(
            cookie
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
    }

    #[test]
    fn outbound_message_respects_configured_limit_for_multiple_frames() {
        let mut state = ClientState::new(16);
        state.session_bytes.push_back(SessionBytes {
            session_id: 1,
            bytes: vec![1; 16],
        });
        state.session_bytes.push_back(SessionBytes {
            session_id: 2,
            bytes: vec![2; 16],
        });
        let first = state.take_outbound_message().unwrap();
        assert_eq!(first.sessions.len(), 1);
        let second = state.take_outbound_message().unwrap();
        assert_eq!(second.sessions.len(), 1);
    }

    #[test]
    fn reconnect_delay_grows_exponentially_and_is_capped() {
        assert_eq!(reconnect_delay(100, 1_000, 0, 1), 100);
        assert_eq!(reconnect_delay(100, 1_000, 0, 3), 400);
        assert_eq!(reconnect_delay(100, 250, 0, 8), 250);
    }

    #[test]
    fn transport_reset_clears_session_output_and_authentication() {
        let mut state = ClientState::new(128);
        state.logged_in = true;
        state.login_sent = true;
        state.commands.push_back("03:1".to_owned());
        state.session_bytes.push_back(SessionBytes {
            session_id: 7,
            bytes: vec![1],
        });

        state.reset_for_transport(9);

        assert_eq!(state.generation, 9);
        assert!(!state.logged_in);
        assert!(!state.login_sent);
        assert!(state.commands.is_empty());
        assert!(state.session_bytes.is_empty());
    }

    #[test]
    fn outbound_commands_stop_at_java_body_size_threshold() {
        let mut state = ClientState::new(4);
        state.commands.extend(["123".to_owned(), "4".to_owned()]);

        assert_eq!(
            state.take_outbound_message().unwrap().commands,
            ["123".to_owned()]
        );
        assert_eq!(
            state.take_outbound_message().unwrap().commands,
            ["4".to_owned()]
        );
    }

    #[test]
    fn hppt_length_prefixes_are_big_endian_and_bounded() {
        assert_eq!(encode_hppt_header(0x7f, 1).unwrap(), [0x7f]);
        assert_eq!(encode_hppt_header(0x1234, 2).unwrap(), [0x12, 0x34]);
        assert_eq!(encode_hppt_header(0x123456, 3).unwrap(), [0x12, 0x34, 0x56]);
        assert_eq!(
            encode_hppt_header(0x12345678, 4).unwrap(),
            [0x12, 0x34, 0x56, 0x78]
        );
        assert!(encode_hppt_header(0x100, 1).is_err());
        assert!(encode_hppt_header(0, 0).is_err());
    }
}
