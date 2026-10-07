//! HTTP request construction and execution.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use digest::Digest;
use futures_util::{Stream, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use reqwest::multipart::{Form, Part};
use reqwest::{header, Client, Method, RequestBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::cli::Args;
use crate::dns::fetch_dns;
use crate::i18n::L10n;
use crate::protocol::{
    fetch_data, fetch_file, fetch_ftp, fetch_gopher, fetch_sftp, interrupted,
    FetchError, Resource, ResourceBody,
};
use crate::udp::fetch_udp;
use crate::ui::{format_bytes, Palette, BRAILLE};
use crate::ws::fetch_ws;

/// Output paths already claimed by an in-flight job. Two URLs that resolve to
/// the same file name must not both stream into it, so the second claim gets a
/// numeric suffix instead.
pub type ClaimedOutputs = tokio::sync::Mutex<HashMap<PathBuf, usize>>;

/// Downloads of at least this many bytes are treated as "large" (e.g.
/// installers) and get the "streaming to <path>" status instead of "fetching".
const LARGE_FILE_THRESHOLD: u64 = 1024 * 1024;

/// The maximum number of redirect hops to follow.
const MAX_REDIRECTS: usize = 10;

/// Exit code used when a `--expected-hash`/`--verify` checksum does not match.
const EXIT_CHECKSUM_MISMATCH: u8 = 90;

/// A supported content-hash algorithm for `--expected-hash` / `--verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlgo {
    Sha256,
    Sha1,
    Md5,
    Sha512,
}

impl HashAlgo {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Some(Self::Sha256),
            "sha1" | "sha-1" => Some(Self::Sha1),
            "md5" => Some(Self::Md5),
            "sha512" | "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
            Self::Md5 => "md5",
            Self::Sha512 => "sha512",
        }
    }
}

/// A streaming hasher for one of the supported algorithms.
enum Hasher {
    Sha256(sha2::Sha256),
    Sha1(sha1::Sha1),
    Md5(md5::Md5),
    Sha512(sha2::Sha512),
}

impl Hasher {
    fn new(algo: HashAlgo) -> Self {
        match algo {
            HashAlgo::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            HashAlgo::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            HashAlgo::Md5 => Hasher::Md5(md5::Md5::new()),
            HashAlgo::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    fn finish_hex(self) -> String {
        let bytes: Vec<u8> = match self {
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Md5(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        };
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Parse an `--expected-hash` spec of the form `ALGO:HEX` into a normalized
/// `(algorithm, lowercase-hex)` pair.
fn parse_expected_hash(spec: &str) -> Result<(HashAlgo, String)> {
    let (algo, hex) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("expected hash must be \"ALGO:HEX\", got: {spec}"))?;
    let algo = HashAlgo::parse(algo).ok_or_else(|| anyhow!("unsupported hash algorithm: {algo}"))?;
    let hex = hex.trim().to_ascii_lowercase();
    if hex.is_empty() || hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("invalid {} digest: {spec}", algo.name()));
    }
    Ok((algo, hex))
}

/// Stream a file from disk through the given hash, returning its lowercase-hex
/// digest.
async fn hash_path(algo: HashAlgo, path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Hasher::new(algo);
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish_hex())
}

/// Where a response body should be written.
#[derive(Debug, Clone)]
pub enum OutputMode {
    /// Write to this explicit path (a bare name is resolved lazily at runtime).
    File(PathBuf),
    /// Derive the file name from Content-Disposition or the URL once the
    /// response headers are known.
    Auto,
}

/// A single request to run, already resolved from the CLI arguments.
#[derive(Debug, Clone)]
pub struct Job {
    /// Stable index of this URL on the command line, used to keep output-path
    /// claims idempotent across retries.
    pub id: usize,
    pub url: String,
    pub method: Method,
    pub include_headers: bool,
    pub head_only: bool,
    pub output: Option<OutputMode>,
    /// Resume byte offset, when `-C`/`--continue-at` was given. Only HTTP uses it.
    pub resume_offset: Option<u64>,
    /// Hashes to verify the finished file against (`--expected-hash` / `--verify`).
    pub expected_hashes: Vec<(HashAlgo, String)>,
}

/// The final result of one request.
#[derive(Debug)]
pub enum JobOutcome {
    Done,
    /// Failed, carrying a curl-style exit code (see [`error_code`]).
    Failed(u8),
    Interrupted,
}

/// Build the shared HTTP client from the CLI options.
pub fn build_client(args: &Args) -> Result<Client> {
    let mut builder = Client::builder();

    // Redirects are followed manually in `execute` so each hop can be logged
    // with a rustup-style `info: redirecting to …` line.
    builder = builder.redirect(reqwest::redirect::Policy::none());

    if args.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let Some(ua) = &args.user_agent {
        builder = builder.user_agent(ua);
    }

    if let Some(proxy) = &args.proxy {
        builder = builder.proxy(
            reqwest::Proxy::all(proxy).with_context(|| format!("invalid proxy URL: {proxy}"))?,
        );
    }

    if let Some(ca) = &args.cacert {
        let pem = std::fs::read(ca).with_context(|| format!("reading CA bundle {ca}"))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .with_context(|| format!("invalid CA bundle {ca}"))?;
        builder = builder.add_root_certificate(cert);
    }

    if let Some(secs) = args.max_time {
        builder = builder.timeout(Duration::from_secs(secs));
    }

    if let Some(secs) = args.connect_timeout {
        builder = builder.connect_timeout(Duration::from_secs(secs));
    }

    builder.build().context("failed to build HTTP client")
}

/// Resolve the list of jobs (one per URL) from the CLI arguments.
pub fn build_jobs(args: &Args) -> Result<Vec<Job>> {
    let method = resolve_method(args);
    let total = args.urls.len();

    let expected_hashes = args
        .expected_hash
        .iter()
        .map(|s| parse_expected_hash(s))
        .collect::<Result<Vec<_>>>()?;
    let verifying = !expected_hashes.is_empty() || args.verify;

    args.urls
        .iter()
        .enumerate()
        .map(|(index, url)| {
            let output = resolve_output(args, index, total);
            if verifying && !matches!(output, Some(OutputMode::File(_))) {
                return Err(anyhow!(
                    "--expected-hash / --verify requires an explicit output file (-o=FILE)"
                ));
            }
            let resume_offset = resolve_resume(args, output.as_ref())?;
            Ok(Job {
                id: index,
                url: url.clone(),
                method: method.clone(),
                include_headers: args.include || args.head,
                head_only: args.head,
                output,
                resume_offset,
                expected_hashes: expected_hashes.clone(),
            })
        })
        .collect()
}

fn resolve_method(args: &Args) -> Method {
    if let Some(m) = &args.method {
        return parse_method(m);
    }
    if args.head {
        return Method::HEAD;
    }
    let has_body = args.data.is_some()
        || args.data_raw.is_some()
        || args.data_binary.is_some()
        || args.json.is_some()
        || !args.form.is_empty();
    if has_body {
        Method::POST
    } else {
        Method::GET
    }
}

fn parse_method(s: &str) -> Method {
    match s.to_ascii_uppercase().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "PATCH" => Method::PATCH,
        "HEAD" => Method::HEAD,
        "OPTIONS" => Method::OPTIONS,
        "CONNECT" => Method::CONNECT,
        "TRACE" => Method::TRACE,
        other => Method::from_bytes(other.as_bytes()).unwrap_or(Method::GET),
    }
}

fn resolve_output(args: &Args, index: usize, total: usize) -> Option<OutputMode> {
    // An explicit `--output=FILE` / `-o=FILE`.
    if let Some(Some(out)) = &args.output {
        if total == 1 {
            return Some(OutputMode::File(out.clone()));
        }
        // Multiple URLs: disambiguate with a numeric suffix, e.g. "file.1.html".
        let parent = out.parent().unwrap_or_else(|| Path::new(""));
        let stem = out
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let ext = out
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        return Some(OutputMode::File(parent.join(format!("{stem}.{}{ext}", index + 1))));
    }
    // `-O`/`--remote-name`, or a bare `-o`/`--output` with no file name: the
    // name is resolved from the response headers / URL at runtime.
    if args.remote_name || matches!(args.output, Some(None)) {
        return Some(OutputMode::Auto);
    }
    None
}

/// Resolve the `-C`/`--continue-at` byte offset.
///
/// `-C -` resumes from the current size of the output file (0 when it does not
/// exist yet); `-C N` resumes from byte offset `N`. Resume needs an explicit
/// `-o=FILE` so we know which file to measure and append to.
fn resolve_resume(args: &Args, output: Option<&OutputMode>) -> Result<Option<u64>> {
    let Some(spec) = &args.continue_at else {
        return Ok(None);
    };
    let path = match output {
        Some(OutputMode::File(p)) => p,
        _ => return Err(anyhow!("--continue-at (-C) requires an explicit output file (-o=FILE)")),
    };
    let offset = if spec == "-" {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    } else {
        spec.parse::<u64>()
            .map_err(|_| anyhow!("invalid --continue-at offset: {spec}"))?
    };
    Ok(Some(offset))
}

/// Extract a file name from a `Content-Disposition` header value (RFC 6266).
///
/// Prefers the RFC 5987 `filename*=` parameter, then falls back to `filename=`.
fn content_disposition_filename(value: &str) -> Option<String> {
    let mut fallback = None;
    for part in value.split(';').skip(1) {
        let part = part.trim();
        let Some((key, val)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let val = val.trim();
        match key.as_str() {
            "filename*" => {
                // RFC 5987: `charset'lang'percent-encoded`. Take the tail and
                // percent-decode it.
                let encoded = val.rsplit_once('\'').map(|(_, v)| v).unwrap_or(val);
                if let Ok(decoded) = percent_encoding::percent_decode_str(encoded).decode_utf8() {
                    return Some(decoded.into_owned());
                }
            }
            "filename" => {
                let name = val
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(val);
                fallback = Some(name.to_string());
            }
            _ => {}
        }
    }
    fallback
}

/// Reduce a possibly-qualified name to a bare file name, guarding against path
/// traversal (`../`, absolute paths, etc.).
fn safe_name(name: &str) -> Option<String> {
    let name = Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())?;
    if name.is_empty() || name == "." || name == ".." {
        None
    } else {
        Some(name)
    }
}

fn remote_name(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(segment) = parsed.path_segments().and_then(|mut s| s.next_back()) {
            if !segment.is_empty() {
                let decoded = percent_encoding::percent_decode_str(segment)
                    .decode_utf8_lossy()
                    .to_string();
                if let Some(name) = safe_name(&decoded) {
                    return name;
                }
            }
        }
    }
    "index.html".to_string()
}

/// Build the concrete request for one URL (or one redirect hop).
fn build_request(
    client: &Client,
    args: &Args,
    method: &Method,
    url: &str,
    cross_host: bool,
    include_body: bool,
    range_header: Option<String>,
) -> Result<RequestBuilder> {
    let mut builder = client.request(method.clone(), url);

    for raw in &args.headers {
        let (name, value) = raw
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid header (expected \"Name: value\"): {raw}"))?;
        builder = builder.header(name.trim(), value.trim_start());
    }

    // Authorization and Cookie are dropped once a redirect crosses hosts,
    // matching curl and reqwest's default policy.
    if !cross_host {
        if let Some(cookie) = &args.cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if let Some(auth) = &args.user {
            let (user, pass) = match auth.split_once(':') {
                Some((u, p)) => (u.to_string(), Some(p.to_string())),
                None => (auth.clone(), None),
            };
            builder = builder.basic_auth(user, pass);
        }
    }

    if let Some(referer) = &args.referer {
        builder = builder.header(header::REFERER, referer);
    }

    if let Some(range) = &range_header {
        builder = builder.header(header::RANGE, range);
    } else if let Some(range) = &args.range {
        let value = if range.starts_with("bytes=") {
            range.clone()
        } else {
            format!("bytes={range}")
        };
        builder = builder.header(header::RANGE, value);
    }

    if include_body {
        builder = apply_body(builder, args)?;
    }

    Ok(builder)
}

/// A `3xx` status that carries a `Location` header worth following.
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// The method to use on the next hop, following curl's redirect rules:
/// `303` becomes GET, `301`/`302` turn POST into GET, `307`/`308` keep it.
fn redirect_method(status: u16, current: &Method) -> Method {
    match status {
        303 => Method::GET,
        301 | 302 if *current == Method::POST => Method::GET,
        _ => current.clone(),
    }
}

/// Whether following a redirect would change the host, scheme, or port.
fn is_cross_host(prev: &str, next: &str) -> bool {
    let (Ok(p), Ok(n)) = (url::Url::parse(prev), url::Url::parse(next)) else {
        return true;
    };
    p.scheme() != n.scheme() || p.host_str() != n.host_str() || p.port() != n.port()
}

/// Resolve a (possibly relative) `Location` header against the current URL.
fn resolve_redirect(base: &str, location: &str) -> Option<String> {
    let base = url::Url::parse(base).ok()?;
    base.join(location).ok().map(|u| u.to_string())
}

fn apply_body(builder: RequestBuilder, args: &Args) -> Result<RequestBuilder> {
    if let Some(json) = &args.json {
        let value: serde_json::Value =
            serde_json::from_str(json).context("invalid JSON body for --json")?;
        return Ok(builder.json(&value));
    }

    if !args.form.is_empty() {
        let mut form = Form::new();
        for field in &args.form {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid form field (expected name=value): {field}"))?;
            let name = name.to_string();
            if let Some(path) = value.strip_prefix('@') {
                let bytes = std::fs::read(path)
                    .with_context(|| format!("reading form file {path}"))?;
                let fname = Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("file")
                    .to_string();
                form = form.part(name, Part::bytes(bytes).file_name(fname));
            } else {
                form = form.text(name, value.to_string());
            }
        }
        return Ok(builder.multipart(form));
    }

    if let Some(data) = &args.data_binary {
        return Ok(builder.body(resolve_data(data, false)?));
    }

    if let Some(data) = &args.data_raw {
        return Ok(builder.body(data.as_bytes().to_vec()));
    }

    if let Some(data) = &args.data {
        return Ok(builder
            .body(resolve_data(data, true)?)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded"));
    }

    Ok(builder)
}

/// Resolve `--data` / `--data-binary` input; `@file` reads a file's contents.
fn resolve_data(data: &str, strip_trailing_newlines: bool) -> Result<Vec<u8>> {
    if let Some(path) = data.strip_prefix('@') {
        let mut bytes =
            std::fs::read(path).with_context(|| format!("reading data file {path}"))?;
        if strip_trailing_newlines {
            while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                bytes.pop();
            }
        }
        Ok(bytes)
    } else {
        Ok(data.as_bytes().to_vec())
    }
}

/// Resolve the outgoing payload for message-oriented protocols (UDP,
/// WebSocket) from `--data-binary` / `--data-raw` / `--data`. Returns `None`
/// when no body was supplied. Mirrors [`apply_body`]'s precedence.
pub(crate) fn outgoing_payload(args: &Args) -> Result<Option<Vec<u8>>> {
    if let Some(data) = &args.data_binary {
        return Ok(Some(resolve_data(data, false)?));
    }
    if let Some(data) = &args.data_raw {
        return Ok(Some(data.as_bytes().to_vec()));
    }
    if let Some(data) = &args.data {
        return Ok(Some(resolve_data(data, true)?));
    }
    Ok(None)
}

enum Drain {
    Complete,
    Error(String),
    Interrupted,
}

/// Stream a resource body into an async writer while updating the progress bar.
async fn drain_to<W, S>(
    mut stream: S,
    mut writer: W,
    pb: &ProgressBar,
    done_bytes: &AtomicU64,
    rx: watch::Receiver<bool>,
) -> Drain
where
    W: tokio::io::AsyncWrite + Unpin,
    S: Stream<Item = Result<Bytes>> + Unpin,
{
    loop {
        tokio::select! {
            biased;
            _ = interrupted(rx.clone()) => return Drain::Interrupted,
            item = stream.next() => {
                match item {
                    None => return Drain::Complete,
                    Some(Ok(chunk)) => {
                        let len = chunk.len() as u64;
                        pb.inc(len);
                        done_bytes.fetch_add(len, Ordering::Relaxed);
                        if let Err(e) = writer.write_all(&chunk).await {
                            return Drain::Error(e.to_string());
                        }
                    }
                    Some(Err(e)) => {
                        return Drain::Error(
                            e.chain().map(|c| c.to_string()).collect::<Vec<_>>().join(": "),
                        )
                    }
                }
            }
        }
    }
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner} {msg}")
        .expect("valid template")
        .tick_chars(BRAILLE)
}

/// Create a braille spinner progress bar (not yet added to a MultiProgress).
pub fn new_spinner() -> ProgressBar {
    ProgressBar::new_spinner().with_style(spinner_style())
}

/// Re-arm a spinner that has finished or been cleared (e.g. between retries),
/// restoring its spinner style and steady tick so it can animate again.
pub fn reset_spinner(pb: &ProgressBar) {
    pb.reset();
    pb.set_style(spinner_style());
    pb.enable_steady_tick(Duration::from_millis(80));
}

/// rustup-style download bar: `███… 54.5 MiB / 54.5 MiB (100 %) 18.3 MiB/s in 3s ETA: 0s`.
fn bar_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{bar:40.cyan/blue} {ibytes} / {itotal} ({percent} %) {ispeed} in {elapsed} ETA: {eta}",
    )
    .expect("valid template")
    .progress_chars("█▓▒░ ")
    // Custom 1-decimal binary byte formatting, matching rustup's output
    // (`54.5 MiB` / `18.3 MiB/s`) instead of indicatif's 2-decimal default.
    .with_key("ibytes", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
        let _ = w.write_str(&format_bytes(state.pos()));
    })
    .with_key("itotal", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
        let _ = w.write_str(&format_bytes(state.len().unwrap_or(0)));
    })
    .with_key("ispeed", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
        let _ = w.write_str(&format!("{}/s", format_bytes(state.per_sec() as u64)));
    })
}

/// Print a line to stderr, routing through the MultiProgress when live so the
/// spinner/bar is not clobbered.
fn emit(mp: &MultiProgress, live: bool, line: String) {
    if live {
        let _ = mp.println(line);
    } else {
        anstream::eprintln!("{line}");
    }
}

/// An informational step, prefixed with rustup's bright-green `info:`.
fn info_line(
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    palette: &Palette,
    msg: impl std::fmt::Display,
) {
    if silent {
        return;
    }
    emit(mp, live, format!("{} {}", palette.info(), msg));
}

/// A failure, prefixed with rustup's bright-red `error:`.
fn error_line(
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    palette: &Palette,
    msg: impl std::fmt::Display,
) {
    if silent {
        return;
    }
    emit(mp, live, format!("{} {}", palette.error(), msg));
}

/// Execute one request to completion, honouring interrupts.
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    client: &Client,
    args: &Args,
    job: &Job,
    pb: &ProgressBar,
    palette: &Palette,
    l10n: &L10n,
    mp: &MultiProgress,
    live: bool,
    done_bytes: &AtomicU64,
    total_bytes: &AtomicU64,
    used_outputs: &ClaimedOutputs,
    rx: watch::Receiver<bool>,
) -> JobOutcome {
    let silent = args.quiet();
    let started = Instant::now();

    info_line(
        mp,
        live,
        silent,
        palette,
        format!("{} {}", l10n.requesting(), job.url),
    );

    let parsed = url::Url::parse(&job.url);
    let scheme = parsed
        .as_ref()
        .ok()
        .map(|u| u.scheme().to_ascii_lowercase());

    let resource = match scheme.as_deref() {
        Some("http") | Some("https") => {
            match fetch_http(client, args, job, palette, l10n, mp, live, rx.clone()).await {
                Ok(r) => r,
                Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
            }
        }
        Some("file") => match fetch_file(&job.url, rx.clone()).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        Some("data") => match fetch_data(&job.url).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        Some("gopher") => match fetch_gopher(&job.url, args, rx.clone()).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        Some("ftp") | Some("ftps") => match fetch_ftp(&job.url, args, rx.clone()).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        Some("sftp") | Some("scp") => match fetch_sftp(&job.url, args, rx.clone()).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        Some("ws") | Some("wss") => match fetch_ws(&job.url, args, rx.clone()).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        Some("udp") => match fetch_udp(&job.url, args, rx.clone()).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        Some("dns") => match fetch_dns(&job.url, args, rx.clone()).await {
            Ok(r) => r,
            Err(e) => return fetch_fail(e, pb, mp, live, silent, palette, job, l10n),
        },
        _ => {
            if parsed.is_err() {
                return fail(
                    pb,
                    mp,
                    live,
                    silent,
                    palette,
                    job,
                    format!("invalid URL: {}", job.url),
                );
            }
            let shown = scheme.as_deref().unwrap_or("<none>");
            return fail(
                pb,
                mp,
                live,
                silent,
                palette,
                job,
                format!("unsupported protocol: {shown}"),
            );
        }
    };

    // `-I` (HEAD) only applies to HTTP; other schemes just download.
    let head_only = job.head_only && matches!(scheme.as_deref(), Some("http") | Some("https"));

    // `--segments N`: split a plain GET into parallel byte-range requests. It
    // only applies to HTTP(S) writing to an explicit file, and is skipped (so
    // the single-connection path above is used) whenever a range or resume
    // offset was already requested. `segmented_download` returns `None` when
    // the server does not advertise byte ranges, falling through here too.
    let wants_segments = args.segments.is_some_and(|n| n > 1)
        && args.range.is_none()
        && job.resume_offset.is_none()
        && job.method == Method::GET
        && matches!(scheme.as_deref(), Some("http") | Some("https"))
        && matches!(job.output, Some(OutputMode::File(_)));
    if wants_segments
        && let Some(outcome) = segmented_download(
            client,
            args,
            job,
            args.segments.unwrap_or(1),
            started,
            pb,
            palette,
            l10n,
            mp,
            live,
            silent,
            done_bytes,
            total_bytes,
            used_outputs,
            rx.clone(),
        )
        .await
    {
        return outcome;
    }

    // Resolve the checksums to verify: explicit `--expected-hash`, plus the
    // sidecar auto-fetched by `--verify` when none was given explicitly.
    let mut expected = job.expected_hashes.clone();
    if args.verify
        && expected.is_empty()
        && matches!(scheme.as_deref(), Some("http") | Some("https"))
    {
        match fetch_sidecar_checksum(client, &job.url).await {
            Some(h) => expected.push(h),
            None => info_line(
                mp,
                live,
                silent,
                palette,
                format!("no sidecar checksum found for {}", job.url),
            ),
        }
    }

    transfer(
        resource,
        job,
        head_only,
        args,
        started,
        pb,
        palette,
        l10n,
        mp,
        live,
        silent,
        done_bytes,
        total_bytes,
        used_outputs,
        expected,
        rx,
    )
    .await
}

/// Fetch an HTTP(S) resource, following redirects and logging each hop.
#[allow(clippy::too_many_arguments)]
async fn fetch_http(
    client: &Client,
    args: &Args,
    job: &Job,
    palette: &Palette,
    l10n: &L10n,
    mp: &MultiProgress,
    live: bool,
    rx: watch::Receiver<bool>,
) -> Result<Resource, FetchError> {
    let silent = args.quiet();

    // Track the URL and method across redirect hops. 301/302/… are followed
    // by default and each hop is logged, so `-o file URL` transparently lands
    // on the final resource (e.g. a CDN that redirects to a mirror).
    let mut current_url = job.url.clone();
    let mut current_method = job.method.clone();
    let mut previous_url: Option<String> = None;
    let mut redirects = 0usize;
    let mut include_body = true;
    let range_header = job
        .resume_offset
        .filter(|o| *o > 0)
        .map(|o| format!("bytes={o}-"));

    let response = loop {
        let cross_host = previous_url
            .as_deref()
            .map(|prev| is_cross_host(prev, &current_url))
            .unwrap_or(false);

        let builder =
            match build_request(
                client,
                args,
                &current_method,
                &current_url,
                cross_host,
                include_body,
                range_header.clone(),
            )
            {
                Ok(b) => b,
                Err(e) => return Err(FetchError::Failed(e.to_string())),
            };

        if args.verbose {
            emit(
                mp,
                live,
                palette.bold(format!("> {} {}", current_method, current_url)),
            );
            for raw in &args.headers {
                emit(mp, live, palette.dim(format!("> {raw}")));
            }
        }

        let response = tokio::select! {
            biased;
            _ = interrupted(rx.clone()) => return Err(FetchError::Interrupted),
            resp = builder.send() => resp,
        };

        let response = match response {
            Ok(r) => r,
            Err(e) => return Err(FetchError::Failed(err_full(&e))),
        };

        let status = response.status();
        let status_code = status.as_u16();

        // Feature: show the IP address the request was actually made to.
        if let Some(remote) = response.remote_addr() {
            info_line(
                mp,
                live,
                silent,
                palette,
                format!("{} {}", l10n.connected_to(), remote),
            );
        }

        if args.verbose {
            let version = format!("{:?}", response.version());
            let reason = status.canonical_reason().unwrap_or("").to_string();
            emit(
                mp,
                live,
                palette.bold(format!("< {version} {status_code} {reason}")),
            );
            for (name, value) in response.headers() {
                emit(
                    mp,
                    live,
                    palette.dim(format!("< {name}: {}", value.to_str().unwrap_or_default())),
                );
            }
        }

        // Stop here unless this is a redirect.
        if !is_redirect(status_code) {
            break response;
        }

        let location = match response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
        {
            Some(l) => l,
            // A redirect without a Location cannot be followed.
            None => break response,
        };

        let next_url = match resolve_redirect(&current_url, location) {
            Some(u) => u,
            None => {
                return Err(FetchError::Failed(format!(
                    "invalid redirect Location: {location}"
                )))
            }
        };

        redirects += 1;
        if redirects > MAX_REDIRECTS {
            return Err(FetchError::Failed(format!(
                "too many redirects (>{MAX_REDIRECTS})"
            )));
        }

        info_line(
            mp,
            live,
            silent,
            palette,
            format!("{} {next_url}", l10n.redirecting()),
        );

        let next_method = redirect_method(status_code, &current_method);
        if next_method != current_method {
            include_body = false;
        }
        previous_url = Some(current_url);
        current_url = next_url;
        current_method = next_method;
    };

    let status_code = response.status().as_u16();
    let version = format!("{:?}", response.version());
    let reason = response.status().canonical_reason().unwrap_or("").to_string();
    let headers = response.headers().clone();
    let total = response.content_length();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let filename = headers
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .and_then(content_disposition_filename);

    // The "document" header (status line + headers), included for -i / -I.
    let mut head: Vec<u8> = Vec::new();
    if job.include_headers {
        head.extend_from_slice(format!("{version} {status_code} {reason}\r\n").as_bytes());
        for (name, value) in &headers {
            head.extend_from_slice(
                format!("{name}: {}\r\n", value.to_str().unwrap_or_default()).as_bytes(),
            );
        }
        head.extend_from_slice(b"\r\n");
    }

    let body: ResourceBody = Box::pin(response.bytes_stream().map(|r| r.map_err(anyhow::Error::new)));

    // Resume bookkeeping. A 416 means the file is already fully downloaded; a
    // 206 means the server honoured the Range request and we append; any other
    // status means the server ignored the Range header, so we restart the file
    // from scratch rather than appending a duplicate full body.
    let offset = job.resume_offset.unwrap_or(0);
    let already_complete = offset > 0 && status_code == 416;
    let resume = if offset > 0 && status_code == 206 {
        Some(offset)
    } else {
        None
    };

    Ok(Resource {
        length: total,
        filename,
        status: Some(status_code.to_string()),
        final_url: Some(current_url),
        content_type,
        num_redirects: redirects as u32,
        head,
        body,
        resume,
        already_complete,
    })
}

/// Turn a fetch failure into the right terminal outcome.
#[allow(clippy::too_many_arguments)]
fn fetch_fail(
    e: FetchError,
    pb: &ProgressBar,
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    palette: &Palette,
    job: &Job,
    l10n: &L10n,
) -> JobOutcome {
    match e {
        FetchError::Interrupted => {
            pb.finish_and_clear();
            emit(
                mp,
                live,
                format!("{} {}", palette.red(l10n.stopping()), palette.cyan(&job.url)),
            );
            JobOutcome::Interrupted
        }
        FetchError::Failed(msg) => fail(pb, mp, live, silent, palette, job, msg),
    }
}

/// Auto-fetch a sidecar checksum file for `--verify`, trying the common
/// extensions in order and returning the first one that resolves to a hex
/// digest. Returns `None` when no sidecar exists or none parses.
async fn fetch_sidecar_checksum(client: &Client, url: &str) -> Option<(HashAlgo, String)> {
    for (ext, algo) in [
        (".sha256", HashAlgo::Sha256),
        (".sha1", HashAlgo::Sha1),
        (".md5", HashAlgo::Md5),
        (".sha512", HashAlgo::Sha512),
    ] {
        let resp = client.get(format!("{url}{ext}")).send().await.ok()?;
        if !resp.status().is_success() {
            continue;
        }
        let text = resp.text().await.ok()?;
        // A sidecar is one or more lines of `HEX  filename` / `HEX *filename`;
        // the digest is always the first whitespace-delimited token.
        if let Some(hex) = text.split_whitespace().next()
            && !hex.is_empty()
            && hex.len() % 2 == 0
            && hex.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Some((algo, hex.to_ascii_lowercase()));
        }
    }
    None
}

/// Download a single byte range into its part file, returning the number of
/// bytes written.
#[allow(clippy::too_many_arguments)]
async fn fetch_segment(
    client: &Client,
    args: &Args,
    job: &Job,
    start: u64,
    end: u64,
    part: &Path,
    pb: &ProgressBar,
    done_bytes: &AtomicU64,
    rx: watch::Receiver<bool>,
) -> Result<u64, String> {
    let builder = build_request(
        client,
        args,
        &job.method,
        &job.url,
        false,
        false,
        Some(format!("bytes={start}-{end}")),
    )
    .map_err(|e| e.to_string())?;
    let resp = tokio::select! {
        biased;
        _ = interrupted(rx.clone()) => return Err("interrupted".to_string()),
        r = builder.send() => r.map_err(|e| err_full(&e))?,
    };
    if resp.status().as_u16() != 206 {
        return Err(format!("segment {start}-{end}: unexpected HTTP {}", resp.status()));
    }
    let mut file = tokio::fs::File::create(part)
        .await
        .map_err(|e| e.to_string())?;
    let mut stream = resp.bytes_stream();
    let mut written = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| err_full(&e))?;
        file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        written += chunk.len() as u64;
        done_bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        pb.inc(chunk.len() as u64);
    }
    file.flush().await.map_err(|e| e.to_string())?;
    Ok(written)
}

/// Remove the temporary part files left behind by a segmented download.
async fn cleanup_parts(path: &Path, count: usize) {
    for i in 0..count {
        let _ = tokio::fs::remove_file(PathBuf::from(format!("{}.part{i}", path.display()))).await;
    }
}

/// Parallel segmented download: probe the total size with a one-byte range
/// request, then fetch `n` byte ranges concurrently into `.partN` files and
/// reassemble them. Returns `None` to fall back to the single-connection
/// transfer (no range support, or a zero/unknown length).
#[allow(clippy::too_many_arguments)]
async fn segmented_download(
    client: &Client,
    args: &Args,
    job: &Job,
    n: usize,
    started: Instant,
    pb: &ProgressBar,
    palette: &Palette,
    l10n: &L10n,
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    done_bytes: &AtomicU64,
    total_bytes: &AtomicU64,
    used_outputs: &ClaimedOutputs,
    rx: watch::Receiver<bool>,
) -> Option<JobOutcome> {
    let path = match &job.output {
        Some(OutputMode::File(p)) => claim_output_path(p.clone(), job.id, used_outputs).await,
        _ => return None,
    };

    // Probe: request one byte to learn the total size and confirm range support.
    let builder =
        build_request(client, args, &job.method, &job.url, false, false, Some("bytes=0-0".into()))
            .ok()?;
    let resp = tokio::select! {
        biased;
        _ = interrupted(rx.clone()) => return Some(JobOutcome::Interrupted),
        r = builder.send() => r.ok()?,
    };
    if resp.status().as_u16() != 206 {
        return None;
    }
    let total = resp
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit('/').next())
        .and_then(|t| t.parse::<u64>().ok())?;
    drop(resp);
    if total == 0 {
        return None;
    }

    // Split the file into roughly equal byte ranges.
    let segments = n.min(total as usize).max(1);
    let per = total.div_ceil(segments as u64);
    let mut ranges = Vec::with_capacity(segments);
    let mut start = 0u64;
    while start < total {
        let end = (start + per - 1).min(total - 1);
        ranges.push((start, end));
        start = end + 1;
    }
    let part_count = ranges.len();

    total_bytes.fetch_add(total, Ordering::Relaxed);
    pb.set_style(bar_style());
    pb.set_length(total);
    pb.set_position(0);
    info_line(
        mp,
        live,
        silent,
        palette,
        format!("{} {} ({part_count} segments)", l10n.fetching(), job.url),
    );

    // Fetch every range concurrently into its own part file.
    let mut results: Vec<(usize, Result<u64, String>)> = futures_util::stream::iter(
        ranges.into_iter().enumerate(),
    )
    .map(|(i, (start, end))| {
        let part = PathBuf::from(format!("{}.part{i}", path.display()));
        let rx = rx.clone();
        async move {
            let written =
                fetch_segment(client, args, job, start, end, &part, pb, done_bytes, rx).await;
            (i, written)
        }
    })
    .buffer_unordered(segments)
    .collect()
    .await;

    // `buffer_unordered` yields parts in completion order; sort back into byte
    // order before reassembling.
    results.sort_by_key(|(i, _)| *i);

    // Reassemble the parts in order, then drop them.
    for (_i, res) in &results {
        if let Err(e) = res {
            cleanup_parts(&path, part_count).await;
            return Some(fail(pb, mp, live, silent, palette, job, e.clone()));
        }
    }
    if *rx.borrow() {
        cleanup_parts(&path, part_count).await;
        return Some(JobOutcome::Interrupted);
    }

    let mut out = match tokio::fs::File::create(&path).await {
        Ok(f) => f,
        Err(e) => {
            cleanup_parts(&path, part_count).await;
            return Some(fail(pb, mp, live, silent, palette, job, e.to_string()));
        }
    };
    for (i, _) in &results {
        let part = PathBuf::from(format!("{}.part{i}", path.display()));
        let mut f = match tokio::fs::File::open(&part).await {
            Ok(f) => f,
            Err(e) => {
                cleanup_parts(&path, part_count).await;
                return Some(fail(pb, mp, live, silent, palette, job, e.to_string()));
            }
        };
        if let Err(e) = tokio::io::copy(&mut f, &mut out).await {
            cleanup_parts(&path, part_count).await;
            return Some(fail(pb, mp, live, silent, palette, job, e.to_string()));
        }
        drop(f);
        let _ = tokio::fs::remove_file(&part).await;
    }
    drop(out);

    finish_bar(pb, total);

    // Verify the reassembled file against any requested checksums.
    if let Some(outcome) =
        verify_hashes(&path, &job.expected_hashes, pb, mp, live, silent, palette, job, l10n).await
    {
        return Some(outcome);
    }

    let report = |status: Option<&str>, body_bytes: u64| {
        summary_done(
            mp, live, silent, palette, l10n, &job.url, status, body_bytes, Some(&path),
        );
        if let Some(fmt) = &args.write_out {
            let w = WriteOut {
                status,
                body_bytes,
                head_bytes: 0,
                elapsed: started.elapsed(),
                final_url: &job.url,
                content_type: None,
                num_redirects: 0,
                saved_to: Some(&path),
            };
            emit(mp, live, write_out_line(fmt, &w));
        }
    };
    report(Some("200"), total);
    Some(JobOutcome::Done)
}

/// Stream a fetched [`Resource`] to a file or stdout, with progress, output
/// naming, and lock handling. Shared by every protocol.
#[allow(clippy::too_many_arguments)]
async fn transfer(
    resource: Resource,
    job: &Job,
    head_only: bool,
    args: &Args,
    started: Instant,
    pb: &ProgressBar,
    palette: &Palette,
    l10n: &L10n,
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    done_bytes: &AtomicU64,
    total_bytes: &AtomicU64,
    used_outputs: &ClaimedOutputs,
    expected: Vec<(HashAlgo, String)>,
    rx: watch::Receiver<bool>,
) -> JobOutcome {
    let Resource {
        length,
        filename,
        status,
        final_url,
        content_type,
        num_redirects,
        head,
        body,
        resume,
        already_complete,
    } = resource;

    // Byte offset this transfer appends at (HTTP resume). `0` is a fresh
    // download (the output file is truncated).
    let offset = resume.unwrap_or(0);

    // Resolve the concrete output path. An explicit `--output=FILE` is known
    // up front; a bare `-o`/`-O` defers naming until the resource tells us its
    // file name (Content-Disposition, URL segment, or protocol path). Claim it
    // so a second job that resolves to the same name gets a numeric suffix
    // instead of overwriting this one.
    let output_path: Option<PathBuf> = match &job.output {
        None => None,
        Some(OutputMode::File(path)) => Some(claim_output_path(path.clone(), job.id, used_outputs).await),
        Some(OutputMode::Auto) => {
            let name = filename
                .as_deref()
                .and_then(safe_name)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(remote_name(&job.url)));
            Some(claim_output_path(name, job.id, used_outputs).await)
        }
    };

    // Resuming onto an already-complete file is a success, not an error.
    if already_complete {
        pb.finish_and_clear();
        emit(
            mp,
            live,
            format!(
                "{} {}",
                palette.cyan(&job.url),
                palette.dim(l10n.already_complete())
            ),
        );
        return JobOutcome::Done;
    }

    // `--no-clobber`: refuse to overwrite an existing file (except when
    // resuming, which appends rather than overwrites).
    if args.no_clobber
        && offset == 0
        && let Some(path) = &output_path
        && tokio::fs::try_exists(path).await.unwrap_or(false)
    {
        return fail(
            pb,
            mp,
            live,
            silent,
            palette,
            job,
            format!("won't overwrite existing file: {}", path.display()),
        );
    }

    // Print the completion line and any `--write-out` output.
    let report = |status: Option<&str>, body_bytes: u64, saved_to: Option<&Path>| {
        summary_done(
            mp,
            live,
            silent,
            palette,
            l10n,
            &job.url,
            status,
            head.len() as u64 + offset + body_bytes,
            saved_to,
        );
        if let Some(fmt) = &args.write_out {
            let w = WriteOut {
                status,
                body_bytes,
                head_bytes: head.len() as u64,
                elapsed: started.elapsed(),
                final_url: final_url.as_deref().unwrap_or(&job.url),
                content_type: content_type.as_deref(),
                num_redirects,
                saved_to,
            };
            emit(mp, live, write_out_line(fmt, &w));
        }
    };

    // `--fail`: on an HTTP error (>= 400), fail fast without writing the body
    // (or head) to the destination.
    if args.fail
        && status
            .as_deref()
            .and_then(|s| s.parse::<u16>().ok())
            .is_some_and(|c| c >= 400)
    {
        pb.finish_and_clear();
        report(status.as_deref(), 0, None);
        return JobOutcome::Failed(22);
    }

    if head_only {
        // HEAD: write the document head only, no body.
        if let Some(path) = &output_path {
            match write_all_to_file(path, &head, &rx, |p| {
                info_line(
                    mp,
                    live,
                    silent,
                    palette,
                    l10n.waiting_for_lock(&p.display().to_string()),
                );
                if live && cfg!(windows) {
                    crate::ui::win_term::indeterminate();
                }
            })
            .await
            {
                Ok(()) => {}
                Err(SaveError::Interrupted) => {
                    pb.finish_and_clear();
                    emit(
                        mp,
                        live,
                        format!("{} {}", palette.red(l10n.stopping()), palette.cyan(&job.url)),
                    );
                    return JobOutcome::Interrupted;
                }
                Err(SaveError::Failed(e)) => {
                    return fail(pb, mp, live, silent, palette, job, e);
                }
            }
        } else if let Err(e) = write_stdout(&head).await {
            return fail(pb, mp, live, silent, palette, job, e.to_string());
        }
        pb.finish_and_clear();
        report(status.as_deref(), 0, output_path.as_deref());
        return JobOutcome::Done;
    }

    // Prepare the progress bar once we know the length. The determinate bar and
    // the aggregate `total_bytes` accounting are deferred until the file is
    // actually opened, so while we wait on a file lock the spinner stays
    // indeterminate (and the Windows Terminal tab ring spins) instead of
    // showing a stuck 0% bar.
    let known_len = length.unwrap_or(0);

    if let Some(path) = &output_path {
        // Download to a file, waiting for a lock on it to be released first.
        let mut file = match open_output_file(path, &rx, offset > 0, |p| {
            info_line(
                mp,
                live,
                silent,
                palette,
                l10n.waiting_for_lock(&p.display().to_string()),
            );
            if live && cfg!(windows) {
                crate::ui::win_term::indeterminate();
            }
        })
        .await
        {
            Ok(f) => f,
            Err(SaveError::Interrupted) => {
                pb.finish_and_clear();
                emit(
                    mp,
                    live,
                    format!("{} {}", palette.red(l10n.stopping()), palette.cyan(&job.url)),
                );
                return JobOutcome::Interrupted;
            }
            Err(SaveError::Failed(e)) => {
                return fail(pb, mp, live, silent, palette, job, e);
            }
        };

        // The file is now actually open. Start the determinate bar and count
        // this download toward the aggregate total.
        if known_len > 0 {
            total_bytes.fetch_add(known_len, Ordering::Relaxed);
            pb.set_style(bar_style());
            pb.set_length(offset + known_len);
            pb.set_position(offset);
        }

        // For large downloads, swap "fetching" for "streaming to <path>".
        if length.is_some_and(|t| t >= LARGE_FILE_THRESHOLD) {
            let msg = l10n.streaming_to(&path.display().to_string());
            info_line(mp, live, silent, palette, msg.clone());
            pb.set_message(format!(
                "{} {}",
                palette.cyan(&job.url),
                palette.dim(msg),
            ));
        }

        if offset == 0 && !head.is_empty() {
            if let Err(e) = file.write_all(&head).await {
                return fail(pb, mp, live, silent, palette, job, e.to_string());
            }
        }
        let body_bytes = match drain_to(body, &mut file, pb, done_bytes, rx).await {
            Drain::Complete => {
                let _ = file.flush().await;
                pb.position().saturating_sub(offset)
            }
            Drain::Error(e) => {
                return fail(pb, mp, live, silent, palette, job, e);
            }
            Drain::Interrupted => {
                pb.finish_and_clear();
                emit(
                    mp,
                    live,
                    format!("{} {}", palette.red(l10n.stopping()), palette.cyan(&job.url)),
                );
                return JobOutcome::Interrupted;
            }
        };
        finish_bar(pb, known_len);

        // Verify the finished file against any requested checksums. The write
        // handle is dropped first so the read sees the fully-flushed bytes.
        drop(file);
        if let Some(outcome) =
            verify_hashes(path, &expected, pb, mp, live, silent, palette, job, l10n).await
        {
            return outcome;
        }

        report(status.as_deref(), body_bytes, Some(path));
        return JobOutcome::Done;
    }

    // Stream to stdout. There is no file lock to wait on, so start the
    // determinate bar right away.
    if known_len > 0 {
        total_bytes.fetch_add(known_len, Ordering::Relaxed);
        pb.set_style(bar_style());
        pb.set_length(known_len);
        pb.set_position(0);
    }

    let mut stdout = tokio::io::stdout();
    if !head.is_empty() {
        if let Err(e) = stdout.write_all(&head).await {
            return fail(pb, mp, live, silent, palette, job, e.to_string());
        }
    }
    let body_bytes = match drain_to(body, &mut stdout, pb, done_bytes, rx).await {
        Drain::Complete => {
            let _ = stdout.flush().await;
            pb.position()
        }
        Drain::Error(e) => {
            return fail(pb, mp, live, silent, palette, job, e);
        }
        Drain::Interrupted => {
            pb.finish_and_clear();
            emit(
                mp,
                live,
                format!("{} {}", palette.red(l10n.stopping()), palette.cyan(&job.url)),
            );
            return JobOutcome::Interrupted;
        }
    };
    finish_bar(pb, known_len);
    report(status.as_deref(), body_bytes, None);
    JobOutcome::Done
}

/// Leave the finished download bar line visible (rustup style), or clear the
/// spinner when the length was unknown.
fn finish_bar(pb: &ProgressBar, known_len: u64) {
    if known_len > 0 {
        pb.finish();
    } else {
        pb.finish_and_clear();
    }
}

/// The rustup-style completion line, e.g.
/// `https://…/file.zip request complete - 54.5 MiB (200) -> file.zip`.
fn summary_done(
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    palette: &Palette,
    l10n: &L10n,
    url: &str,
    status: Option<&str>,
    bytes: u64,
    saved_to: Option<&Path>,
) {
    if silent {
        return;
    }
    let mut line = format!(
        "{} {} - {}",
        palette.cyan(url),
        palette.dim(l10n.completed()),
        palette.dim(format_bytes(bytes)),
    );
    if let Some(status) = status {
        let styled = match status.parse::<u16>() {
            Ok(code) => palette.status(code),
            Err(_) => palette.dim(status),
        };
        line.push_str(&format!(" ({styled})"));
    }
    if let Some(path) = saved_to {
        line.push_str(&format!(" -> {}", palette.cyan(path.display())));
    }
    emit(mp, live, line);
}

/// Data available to a `--write-out` format string.
struct WriteOut<'a> {
    status: Option<&'a str>,
    body_bytes: u64,
    head_bytes: u64,
    elapsed: Duration,
    final_url: &'a str,
    content_type: Option<&'a str>,
    num_redirects: u32,
    saved_to: Option<&'a Path>,
}

/// Expand a curl-style `--write-out` format string: `%{name}` variables, `%%`
/// for a literal `%`, and `\n`/`\t`/`\r`/`\\` escapes.
fn write_out_line(format: &str, w: &WriteOut<'_>) -> String {
    let mut out = String::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' if chars.peek() == Some(&'{') => {
                chars.next();
                let mut name = String::new();
                let mut closed = false;
                for n in chars.by_ref() {
                    if n == '}' {
                        closed = true;
                        break;
                    }
                    name.push(n);
                }
                if closed {
                    out.push_str(&write_out_value(&name, w));
                } else {
                    out.push('%');
                    out.push('{');
                    out.push_str(&name);
                }
            }
            '%' if chars.peek() == Some(&'%') => {
                chars.next();
                out.push('%');
            }
            '\\' => {
                if let Some(&n) = chars.peek() {
                    match n {
                        'n' => {
                            chars.next();
                            out.push('\n');
                        }
                        't' => {
                            chars.next();
                            out.push('\t');
                        }
                        'r' => {
                            chars.next();
                            out.push('\r');
                        }
                        '\\' => {
                            chars.next();
                            out.push('\\');
                        }
                        _ => out.push('\\'),
                    }
                } else {
                    out.push('\\');
                }
            }
            other => out.push(other),
        }
    }
    out
}

fn write_out_value(name: &str, w: &WriteOut<'_>) -> String {
    match name {
        "http_code" | "response_code" => w.status.unwrap_or("000").to_string(),
        "size_download" => w.body_bytes.to_string(),
        "size_header" => w.head_bytes.to_string(),
        "time_total" => format!("{:.6}", w.elapsed.as_secs_f64()),
        "url_effective" => w.final_url.to_string(),
        "content_type" => w.content_type.unwrap_or("").to_string(),
        "num_redirects" => w.num_redirects.to_string(),
        "filename_effective" => w.saved_to.map(|p| p.display().to_string()).unwrap_or_default(),
        other => format!("%{{{other}}}"),
    }
}

/// Render an error with its full `source` chain, so exit-code classification
/// can see the underlying cause (connection refused, timeout, DNS failure)
/// instead of only reqwest's "error sending request for url" wrapper.
fn err_full(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// Map a failure message to a curl-style exit code.
fn error_code(msg: &str) -> u8 {
    let m = msg.to_ascii_lowercase();
    if m.contains("timed out") || m.contains("timeout") || m.contains("deadline") || m.contains("elapsed") {
        28
    } else if m.contains("proxy") {
        5
    } else if m.contains("dns") || m.contains("resolve") || m.contains("lookup address") {
        6
    } else if m.contains("connect") || m.contains("refused") || m.contains("reset") || m.contains("unreachable") {
        7
    } else if m.contains("invalid url") || m.contains("invalid uri") || m.contains("relative url") || m.contains("builder error") {
        3
    } else {
        1
    }
}

fn fail(
    pb: &ProgressBar,
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    palette: &Palette,
    job: &Job,
    error: String,
) -> JobOutcome {
    let code = error_code(&error);
    fail_with(pb, mp, live, silent, palette, job, error, code)
}

/// Like [`fail`], but with an explicit curl-style exit code.
#[allow(clippy::too_many_arguments)]
fn fail_with(
    pb: &ProgressBar,
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    palette: &Palette,
    job: &Job,
    error: String,
    code: u8,
) -> JobOutcome {
    pb.finish_and_clear();
    error_line(
        mp,
        live,
        silent,
        palette,
        format!("{} {}", palette.cyan(&job.url), error),
    );
    JobOutcome::Failed(code)
}

/// Verify `path` against the requested checksums, returning the failure
/// outcome on the first mismatch (and emitting a success line when all pass).
#[allow(clippy::too_many_arguments)]
async fn verify_hashes(
    path: &Path,
    expected: &[(HashAlgo, String)],
    pb: &ProgressBar,
    mp: &MultiProgress,
    live: bool,
    silent: bool,
    palette: &Palette,
    job: &Job,
    l10n: &L10n,
) -> Option<JobOutcome> {
    for (algo, wanted) in expected {
        let actual = match hash_path(*algo, path).await {
            Ok(h) => h,
            Err(e) => {
                return Some(fail(
                    pb,
                    mp,
                    live,
                    silent,
                    palette,
                    job,
                    format!("hashing {}: {e}", path.display()),
                ))
            }
        };
        if actual != *wanted {
            return Some(fail_with(
                pb,
                mp,
                live,
                silent,
                palette,
                job,
                format!(
                    "{} checksum mismatch: expected {wanted}, got {actual}",
                    algo.name()
                ),
                EXIT_CHECKSUM_MISMATCH,
            ));
        }
    }
    if !expected.is_empty() && !silent {
        emit(
            mp,
            live,
            format!(
                "{} {}",
                palette.cyan(&job.url),
                palette.dim(l10n.checksum_verified())
            ),
        );
    }
    None
}

async fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut out = tokio::io::stdout();
    out.write_all(bytes).await.context("writing to stdout")?;
    out.flush().await.context("flushing stdout")?;
    Ok(())
}

/// Why a file write did not complete.
enum SaveError {
    /// The user interrupted while we were waiting on a file lock.
    Interrupted,
    /// A genuine I/O failure.
    Failed(String),
}

/// Whether an I/O error is a transient "file is locked by another process"
/// failure. On Windows this is a sharing violation (`ERROR_SHARING_VIOLATION`,
/// 32) or a byte-range lock (`ERROR_LOCK_VIOLATION`, 33); elsewhere there is no
/// equivalent, so we never retry.
fn is_lock_error(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        matches!(e.raw_os_error(), Some(32) | Some(33))
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        false
    }
}

/// Claim a unique output path. If another job already claimed `path`, append a
/// numeric suffix (`file.ext` -> `file.1.ext`, `file.2.ext`, …) so two jobs
/// never stream into the same file.
async fn claim_output_path(path: PathBuf, job_id: usize, used: &ClaimedOutputs) -> PathBuf {
    let mut used = used.lock().await;
    // A job re-claiming its own path (a retry) must get the identical path,
    // otherwise a retried download would land in `file.1` instead of `file`.
    if used.get(&path) == Some(&job_id) {
        return path;
    }
    if used.insert(path.clone(), job_id).is_none() {
        return path;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let mut i = 1usize;
    loop {
        let candidate = parent.join(format!("{stem}.{i}{ext}"));
        if used.insert(candidate.clone(), job_id).is_none() {
            return candidate;
        }
        i += 1;
    }
}

/// Open `path` for writing, waiting while another process holds a lock on it.
///
/// A locked file is treated as transient: we back off and retry until the lock
/// is released, or the user interrupts. `on_wait` is called once, the first
/// time a lock is detected, so the caller can tell the user what is happening.
async fn open_output_file(
    path: &Path,
    rx: &watch::Receiver<bool>,
    append: bool,
    mut on_wait: impl FnMut(&Path),
) -> Result<tokio::fs::File, SaveError> {
    let mut delay = Duration::from_millis(100);
    let mut reported = false;
    loop {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true);
        if append {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        match opts.open(path).await {
            Ok(file) => return Ok(file),
            Err(e) if is_lock_error(&e) => {
                if !reported {
                    on_wait(path);
                    reported = true;
                }
                tokio::select! {
                    _ = interrupted(rx.clone()) => return Err(SaveError::Interrupted),
                    _ = tokio::time::sleep(delay) => {}
                }
                delay = (delay * 2).min(Duration::from_secs(2));
            }
            Err(e) => return Err(SaveError::Failed(e.to_string())),
        }
    }
}

async fn write_all_to_file(
    path: &Path,
    bytes: &[u8],
    rx: &watch::Receiver<bool>,
    on_wait: impl FnMut(&Path),
) -> Result<(), SaveError> {
    let mut file = open_output_file(path, rx, false, on_wait).await?;
    file.write_all(bytes)
        .await
        .map_err(|e| SaveError::Failed(format!("writing {}: {e}", path.display())))?;
    file.flush()
        .await
        .map_err(|e| SaveError::Failed(format!("flushing {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_algo_parse_and_digest() {
        assert_eq!(HashAlgo::parse("sha256"), Some(HashAlgo::Sha256));
        assert_eq!(HashAlgo::parse("SHA-1"), Some(HashAlgo::Sha1));
        assert_eq!(HashAlgo::parse("md5"), Some(HashAlgo::Md5));
        assert_eq!(HashAlgo::parse("sha-512"), Some(HashAlgo::Sha512));
        assert_eq!(HashAlgo::parse("crc32"), None);

        // Known SHA-256 of "abc".
        let mut hasher = Hasher::new(HashAlgo::Sha256);
        hasher.update(b"abc");
        assert_eq!(
            hasher.finish_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn expected_hash_parsing() {
        let (algo, hex) = parse_expected_hash("sha256:ABC123").unwrap();
        assert_eq!(algo, HashAlgo::Sha256);
        assert_eq!(hex, "abc123");

        assert!(parse_expected_hash("sha256").is_err());
        assert!(parse_expected_hash("crc32:abcd").is_err());
        assert!(parse_expected_hash("sha256:xyz").is_err());
        assert!(parse_expected_hash("sha256:abc").is_err()); // odd length
    }

    #[test]
    fn error_code_classification() {
        assert_eq!(error_code("connection timed out"), 28);
        assert_eq!(error_code("proxy connect failed"), 5);
        assert_eq!(error_code("dns lookup failed"), 6);
        assert_eq!(error_code("connection refused"), 7);
        assert_eq!(error_code("invalid url"), 3);
        assert_eq!(error_code("something else entirely"), 1);
    }

    #[test]
    fn safe_and_remote_names() {
        assert_eq!(safe_name("../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(safe_name("dir/file.txt").as_deref(), Some("file.txt"));
        assert_eq!(safe_name("."), None);
        assert_eq!(safe_name(".."), None);

        assert_eq!(remote_name("http://example.com/a/b/c.zip"), "c.zip");
        assert_eq!(remote_name("http://example.com/"), "index.html");
    }

    #[test]
    fn redirect_method_rules() {
        assert_eq!(redirect_method(303, &Method::POST), Method::GET);
        assert_eq!(redirect_method(302, &Method::POST), Method::GET);
        assert_eq!(redirect_method(302, &Method::GET), Method::GET);
        assert_eq!(redirect_method(307, &Method::POST), Method::POST);
        assert_eq!(redirect_method(308, &Method::PUT), Method::PUT);
    }

    #[test]
    fn cross_host_detection() {
        assert!(!is_cross_host("http://a.com/x", "http://a.com/y"));
        assert!(is_cross_host("http://a.com", "http://b.com"));
        assert!(is_cross_host("http://a.com", "https://a.com"));
        assert!(is_cross_host("http://a.com", "http://a.com:8080"));
    }

    #[test]
    fn content_disposition_filename_parsing() {
        assert_eq!(
            content_disposition_filename("attachment; filename=\"a.txt\"").as_deref(),
            Some("a.txt")
        );
        assert_eq!(
            content_disposition_filename("attachment; filename*=utf-8''caf%C3%A9.txt").as_deref(),
            Some("café.txt")
        );
        assert_eq!(content_disposition_filename("inline"), None);
    }

    #[test]
    fn write_out_formatting() {
        let w = WriteOut {
            status: Some("200"),
            body_bytes: 1024,
            head_bytes: 64,
            elapsed: Duration::from_secs(2),
            final_url: "http://example.com/",
            content_type: Some("text/plain"),
            num_redirects: 1,
            saved_to: None,
        };
        assert_eq!(
            write_out_line("code=%{http_code} size=%{size_download}", &w),
            "code=200 size=1024"
        );
        assert_eq!(write_out_line("100%%", &w), "100%");
        assert_eq!(write_out_line("a\\nb", &w), "a\nb");
        assert_eq!(write_out_line("%{http_code}", &w), "200");
    }
}
