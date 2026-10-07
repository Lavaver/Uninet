//! Protocol-agnostic resource abstraction and the non-HTTP fetchers.
//!
//! Every supported scheme is funnelled into the same download pipeline
//! (`http::transfer`): a [`Resource`] carries the length, a suggested file
//! name, an optional status label and a byte stream, and the transfer code
//! writes that stream to a file or stdout with progress and lock handling.
//! This module defines the abstraction and the fetchers for schemes other
//! than HTTP.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::cli::Args;

use suppaftp::tokio::{
    AsyncNoTlsStream, AsyncRustlsConnector, AsyncRustlsStream, ImplAsyncFtpStream,
    TokioTlsStream, TransferStream,
};

use russh_sftp::client::SftpSession;

/// A byte stream for one fetched resource.
pub type ResourceBody = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

/// A resource ready to stream to a file or stdout, independent of the protocol
/// that produced it.
pub struct Resource {
    /// Total length in bytes, if known (drives the determinate progress bar).
    pub length: Option<u64>,
    /// Suggested file name (Content-Disposition, URL segment, or protocol path).
    pub filename: Option<String>,
    /// Status label for the summary line, e.g. `"200"`; `None` for protocols
    /// without a status code.
    pub status: Option<String>,
    /// The effective URL after following redirects (`None` to fall back to the
    /// request URL).
    pub final_url: Option<String>,
    /// The `Content-Type` of the response, if known.
    pub content_type: Option<String>,
    /// Number of redirects followed.
    pub num_redirects: u32,
    /// Leading bytes written before the body (the HTTP status line + headers
    /// for `-i`/`-I`); empty for other protocols.
    pub head: Vec<u8>,
    /// Byte offset this resource is appended at (HTTP resume); `None` for a
    /// fresh download or when the server ignored the Range request.
    pub resume: Option<u64>,
    /// True when the server answered 416: the output file is already complete.
    pub already_complete: bool,
    /// The body.
    pub body: ResourceBody,
}

/// Why a fetch did not produce a resource.
pub enum FetchError {
    /// The user interrupted while the request was in flight.
    Interrupted,
    /// A genuine failure, with a human-readable message.
    Failed(String),
}

/// Resolve once the interrupt signal has been observed.
pub(crate) async fn interrupted(mut rx: watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    let _ = rx.changed().await;
}

/// Turn an async reader into a byte stream, one 8 KiB chunk at a time.
fn reader_stream<R>(reader: R) -> ResourceBody
where
    R: AsyncRead + Send + Unpin + 'static,
{
    Box::pin(futures_util::stream::try_unfold(
        reader,
        |mut reader| async move {
            let mut buf = vec![0u8; 8192];
            let n = reader.read(&mut buf).await.map_err(anyhow::Error::new)?;
            if n == 0 {
                Ok(None)
            } else {
                buf.truncate(n);
                Ok(Some((Bytes::from(buf), reader)))
            }
        },
    ))
}

/// Fetch a local file (`file://`).
pub async fn fetch_file(url: &str, rx: watch::Receiver<bool>) -> Result<Resource, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Failed(e.to_string()))?;
    let path = parsed
        .to_file_path()
        .map_err(|_| FetchError::Failed(format!("invalid file URL: {url}")))?;

    let file = tokio::select! {
        biased;
        _ = interrupted(rx.clone()) => return Err(FetchError::Interrupted),
        r = tokio::fs::File::open(&path) => r,
    };
    let file = file.map_err(|e| FetchError::Failed(format!("{}: {e}", path.display())))?;

    let length = file
        .metadata()
        .await
        .map(|m| m.len())
        .map_err(|e| FetchError::Failed(format!("{}: {e}", path.display())))?;
    let filename = path.file_name().map(|s| s.to_string_lossy().into_owned());

    Ok(Resource {
        length: Some(length),
        filename,
        status: None,
        final_url: None,
        content_type: None,
        num_redirects: 0,
        head: Vec::new(),
        resume: None,
        already_complete: false,
        body: reader_stream(file),
    })
}

/// Fetch an inline `data:` URL.
pub async fn fetch_data(url: &str) -> Result<Resource, FetchError> {
    // The first `:` is the scheme separator; everything after it is the data.
    let (_scheme, data) = url
        .split_once(':')
        .ok_or_else(|| FetchError::Failed(format!("invalid data URL: {url}")))?;
    let (meta, payload) = data
        .split_once(',')
        .ok_or_else(|| FetchError::Failed(format!("invalid data URL: {url}")))?;

    let mut fields = meta.split(';');
    let mediatype = fields.next().unwrap_or("text/plain");
    let is_base64 = fields.any(|f| f.eq_ignore_ascii_case("base64"));

    // The payload may be percent-encoded; base64 data is percent-decoded first,
    // then base64-decoded.
    let decoded = percent_encoding::percent_decode_str(payload).collect::<Vec<u8>>();
    let bytes = if is_base64 {
        base64::engine::general_purpose::STANDARD
            .decode(&decoded)
            .map_err(|e| FetchError::Failed(format!("invalid base64 in data URL: {e}")))?
    } else {
        decoded
    };

    let length = bytes.len() as u64;
    let filename = Some(data_file_name(mediatype));
    let body: ResourceBody = Box::pin(futures_util::stream::once(async move {
        Ok::<Bytes, anyhow::Error>(Bytes::from(bytes))
    }));

    Ok(Resource {
        length: Some(length),
        filename,
        status: None,
        final_url: None,
        content_type: None,
        num_redirects: 0,
        head: Vec::new(),
        resume: None,
        already_complete: false,
        body,
    })
}

/// Pick a `data.<ext>` name from a media type.
fn data_file_name(mediatype: &str) -> String {
    let ext = match mediatype {
        "text/plain" => "txt",
        "text/html" => "html",
        "text/css" => "css",
        "text/csv" => "csv",
        "application/json" => "json",
        "application/xml" | "text/xml" => "xml",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/gzip" => "gz",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/svg+xml" => "svg",
        "image/webp" => "webp",
        _ => "bin",
    };
    format!("data.{ext}")
}

/// Fetch a gopher resource (`gopher://`).
pub async fn fetch_gopher(
    url: &str,
    args: &Args,
    rx: watch::Receiver<bool>,
) -> Result<Resource, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Failed(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::Failed(format!("invalid gopher URL: {url}")))?;
    let port = parsed.port().unwrap_or(70);
    // The path is `/item-type/selector`; send it without the leading slash.
    let selector = parsed.path().trim_start_matches('/');

    let addr = format!("{host}:{port}");
    let connect = tokio::net::TcpStream::connect((host, port));
    let stream = if let Some(secs) = args.connect_timeout {
        match tokio::time::timeout(Duration::from_secs(secs), connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(FetchError::Failed(format!("{addr}: {e}"))),
            Err(_) => return Err(FetchError::Failed(format!("connect timed out: {addr}"))),
        }
    } else {
        connect
            .await
            .map_err(|e| FetchError::Failed(format!("{addr}: {e}")))?
    };

    let (reader, mut writer) = stream.into_split();
    let request = format!("{selector}\r\n");
    tokio::select! {
        biased;
        _ = interrupted(rx.clone()) => return Err(FetchError::Interrupted),
        r = writer.write_all(request.as_bytes()) => {
            r.map_err(|e| FetchError::Failed(format!("{addr}: {e}")))?;
        }
    }

    let filename = selector
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| percent_encoding::percent_decode_str(s).decode_utf8_lossy().to_string());

    Ok(Resource {
        length: None,
        filename,
        status: None,
        final_url: None,
        content_type: None,
        num_redirects: 0,
        head: Vec::new(),
        resume: None,
        already_complete: false,
        body: reader_stream(reader),
    })
}

/// Fetch a file over FTP or FTPS (`ftp://` / `ftps://`).
///
/// `ftps://` is treated as *explicit* FTPS (AUTH TLS on the standard control
/// port), matching how curl upgrades the connection.
pub async fn fetch_ftp(
    url: &str,
    args: &Args,
    rx: watch::Receiver<bool>,
) -> Result<Resource, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Failed(e.to_string()))?;
    let is_ftps = parsed.scheme() == "ftps";
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::Failed(format!("invalid FTP URL: {url}")))?;

    // Anonymous login unless the URL carries credentials.
    let user = if parsed.username().is_empty() {
        "anonymous"
    } else {
        parsed.username()
    };
    let password = parsed.password().unwrap_or("webclient@example.com");
    // The path is the remote file, percent-decoded and with a leading slash
    // (the URL path) already stripped by `retr_as_stream`'s server-side CWD.
    let path = percent_encoding::percent_decode_str(parsed.path())
        .decode_utf8_lossy()
        .into_owned();
    let filename = path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let (length, body) = if is_ftps {
        let connector = ftps_connector().map_err(FetchError::Failed)?;
        let ftp = ftp_connect::<AsyncRustlsStream>(&parsed, args, rx.clone()).await?;
        let ftp = ftp
            .into_secure(connector, host)
            .await
            .map_err(|e| FetchError::Failed(e.to_string()))?;
        ftp_retrieve(ftp, user, password, &path).await?
    } else {
        let ftp = ftp_connect::<AsyncNoTlsStream>(&parsed, args, rx.clone()).await?;
        ftp_retrieve(ftp, user, password, &path).await?
    };

    Ok(Resource {
        length,
        filename,
        status: None,
        final_url: None,
        content_type: None,
        num_redirects: 0,
        head: Vec::new(),
        resume: None,
        already_complete: false,
        body,
    })
}

/// Open the control connection, honouring `--connect-timeout` and the interrupt
/// signal.
async fn ftp_connect<T>(
    parsed: &url::Url,
    args: &Args,
    rx: watch::Receiver<bool>,
) -> Result<ImplAsyncFtpStream<T>, FetchError>
where
    T: TokioTlsStream + Send,
{
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::Failed(format!("invalid FTP URL: {parsed}")))?;
    let port = parsed.port().unwrap_or(21);
    let addr = format!("{host}:{port}");
    let connect = ImplAsyncFtpStream::<T>::connect((host, port));

    let ftp = if let Some(secs) = args.connect_timeout {
        match tokio::time::timeout(Duration::from_secs(secs), connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(FetchError::Failed(format!("{addr}: {e}"))),
            Err(_) => return Err(FetchError::Failed(format!("connect timed out: {addr}"))),
        }
    } else {
        tokio::select! {
            biased;
            _ = interrupted(rx) => return Err(FetchError::Interrupted),
            r = connect => r.map_err(|e| FetchError::Failed(format!("{addr}: {e}")))?,
        }
    };

    Ok(ftp)
}

/// Log in and open the download stream, reporting size when the server
/// supports `SIZE`.
async fn ftp_retrieve<T>(
    mut ftp: ImplAsyncFtpStream<T>,
    user: &str,
    password: &str,
    path: &str,
) -> Result<(Option<u64>, ResourceBody), FetchError>
where
    T: TokioTlsStream + Send + 'static,
{
    ftp.login(user, password)
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;

    // Best-effort: not every server answers SIZE, and a miss only degrades the
    // progress bar to indeterminate.
    let length = ftp.size(path).await.ok().map(|n| n as u64);

    let stream = ftp
        .retr_as_stream(path)
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;

    Ok((length, ftp_body_stream(stream)))
}

/// Stream an FTP [`TransferStream`] to EOF, then drain its completion reply so
/// the control channel is left clean for the next command.
fn ftp_body_stream<T>(stream: TransferStream<T>) -> ResourceBody
where
    T: TokioTlsStream + Send + 'static,
{
    Box::pin(futures_util::stream::try_unfold(stream, |mut stream| async move {
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.map_err(anyhow::Error::new)?;
        if n == 0 {
            let _ = stream.finish().await;
            Ok(None)
        } else {
            buf.truncate(n);
            Ok(Some((Bytes::from(buf), stream)))
        }
    }))
}

/// Build an explicit-FTPS TLS connector backed by the Mozilla root store.
fn ftps_connector() -> Result<AsyncRustlsConnector, String> {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    Ok(AsyncRustlsConnector::from(connector))
}

/// SSH client handler: accept the server host key without verification
/// (equivalent to OpenSSH's `StrictHostKeyChecking=no`). A full download tool
/// would pin keys via `known_hosts`, but for best-effort support we trade that
/// for simplicity.
struct SshClient;

impl russh::client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Fetch a file over SFTP (`sftp://`) or, as a best-effort fallback, `scp://`
/// (served over the SFTP subsystem, which most modern servers expose).
pub async fn fetch_sftp(
    url: &str,
    args: &Args,
    rx: watch::Receiver<bool>,
) -> Result<Resource, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Failed(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::Failed(format!("invalid SFTP URL: {url}")))?;
    let port = parsed.port().unwrap_or(22);
    let user = if parsed.username().is_empty() {
        default_ssh_user()
    } else {
        parsed.username().to_string()
    };
    let password = parsed.password().map(str::to_owned);
    let path = percent_encoding::percent_decode_str(parsed.path())
        .decode_utf8_lossy()
        .into_owned();
    let filename = path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let config = Arc::new(russh::client::Config::default());
    let addr = format!("{host}:{port}");

    // Connect (honouring `--connect-timeout` and the interrupt signal) and
    // authenticate. `scp://` uses the same SFTP subsystem.
    let connect = russh::client::connect(config, (host, port), SshClient);
    let mut session = if let Some(secs) = args.connect_timeout {
        match tokio::time::timeout(Duration::from_secs(secs), connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(FetchError::Failed(format!("{addr}: {e}"))),
            Err(_) => return Err(FetchError::Failed(format!("connect timed out: {addr}"))),
        }
    } else {
        tokio::select! {
            biased;
            _ = interrupted(rx.clone()) => return Err(FetchError::Interrupted),
            r = connect => r.map_err(|e| FetchError::Failed(format!("{addr}: {e}")))?,
        }
    };

    let authed = match &password {
        Some(pw) => session
            .authenticate_password(user.as_str(), pw.as_str())
            .await
            .map_err(|e| FetchError::Failed(e.to_string()))?,
        None => session
            .authenticate_none(user.as_str())
            .await
            .map_err(|e| FetchError::Failed(e.to_string()))?,
    };
    if !authed.success() {
        return Err(FetchError::Failed(format!(
            "authentication failed for {user}@{addr}"
        )));
    }

    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;

    let meta = sftp
        .metadata(&path)
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;
    if !meta.is_regular() {
        return Err(FetchError::Failed(format!("not a regular file: {path}")));
    }
    let length = meta.size;

    let file = sftp
        .open(&path)
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;

    Ok(Resource {
        length,
        filename,
        status: None,
        final_url: None,
        content_type: None,
        num_redirects: 0,
        head: Vec::new(),
        resume: None,
        already_complete: false,
        body: reader_stream(file),
    })
}

/// Pick a default SSH user name from the environment, falling back to
/// `anonymous`.
fn default_ssh_user() -> String {
    ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .unwrap_or_else(|| "anonymous".to_string())
}
