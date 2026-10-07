//! Command-line interface definition.

use std::path::PathBuf;

use clap::{ArgAction, Parser};

/// A standard style HTTP client.
#[derive(Debug, Parser)]
#[command(
    name = "webclient",
    version,
    about = "Uninet Client - a curl/Invoke-WebRequest compatible client for HTTP, WebSocket, UDP, FTP, SFTP and more",
    long_about = None
)]
pub struct Args {
    /// One or more URLs to request.
    #[arg(value_name = "URL", required = true, num_args = 1..)]
    pub urls: Vec<String>,

    /// HTTP method to use. Defaults to GET (POST when a body is supplied, HEAD with -I).
    #[arg(short = 'X', long = "request", value_name = "METHOD")]
    pub method: Option<String>,

    /// Add a request header, e.g. "Content-Type: application/json". Repeatable.
    #[arg(short = 'H', long = "header", value_name = "HEADER", action = ArgAction::Append)]
    pub headers: Vec<String>,

    /// Request body (supports "@file" to read from a file).
    #[arg(short = 'd', long = "data", value_name = "DATA")]
    pub data: Option<String>,

    /// Raw request body (no "@file" interpretation).
    #[arg(long = "data-raw", value_name = "DATA")]
    pub data_raw: Option<String>,

    /// Binary request body (supports "@file").
    #[arg(long = "data-binary", value_name = "DATA")]
    pub data_binary: Option<String>,

    /// JSON request body; sets "Content-Type: application/json".
    #[arg(long = "json", value_name = "JSON")]
    pub json: Option<String>,

    /// Multipart form field: "name=value" or "name=@file". Repeatable.
    #[arg(short = 'F', long = "form", value_name = "FIELD", action = ArgAction::Append)]
    pub form: Vec<String>,

    /// Write the response body to FILE instead of stdout. With no FILE (a bare
    /// `-o`/`--output`), the name is derived from the Content-Disposition
    /// header, falling back to the URL's last path segment. Give an explicit
    /// name with `--output=FILE` or `-o=FILE`.
    #[arg(
        short = 'o',
        long = "output",
        value_name = "FILE",
        num_args = 0..=1,
        require_equals = true
    )]
    pub output: Option<Option<PathBuf>>,

    /// Save to a file named after the remote URL / Content-Disposition.
    #[arg(short = 'O', long = "remote-name")]
    pub remote_name: bool,

    /// Refuse to overwrite an existing output file.
    #[arg(long = "no-clobber")]
    pub no_clobber: bool,

    /// Follow HTTP redirects (enabled by default; kept for curl compatibility).
    #[arg(short = 'L', long = "location")]
    pub location: bool,

    /// Fail with exit code 22 (instead of 0) when the server returns an HTTP
    /// error (4xx/5xx), and do not write the error body to the output.
    #[arg(short = 'f', long = "fail")]
    pub fail: bool,

    /// Include the response status line and headers in the output.
    #[arg(short = 'i', long = "include")]
    pub include: bool,

    /// Fetch headers only (HEAD request).
    #[arg(short = 'I', long = "head")]
    pub head: bool,

    /// Silent mode: print only the response body.
    #[arg(short = 's', long = "silent")]
    pub silent: bool,

    /// Verbose output (request and response details on stderr).
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Show request status (requesting / connected / redirecting, progress and
    /// the summary) alongside the body. By default, stdout output is just the body.
    #[arg(long = "detail")]
    pub detail: bool,

    /// Print transfer info to stderr after the download. Supports %{...}
    /// variables: http_code, size_download, size_header, time_total,
    /// url_effective, content_type, num_redirects, filename_effective.
    #[arg(short = 'w', long = "write-out", value_name = "FORMAT")]
    pub write_out: Option<String>,

    /// Disable colored output.
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Set the User-Agent header.
    #[arg(short = 'A', long = "user-agent", value_name = "UA")]
    pub user_agent: Option<String>,

    /// HTTP basic auth credentials, "user:password".
    #[arg(short = 'u', long = "user", value_name = "USER:PASS")]
    pub user: Option<String>,

    /// Set the Referer header.
    #[arg(short = 'e', long = "referer", value_name = "URL")]
    pub referer: Option<String>,

    /// Fetch a byte range, e.g. "0-1023" or "512-".
    #[arg(short = 'r', long = "range", value_name = "RANGE")]
    pub range: Option<String>,

    /// Skip TLS certificate verification.
    #[arg(short = 'k', long = "insecure")]
    pub insecure: bool,

    /// Use a custom CA certificate bundle (PEM) to verify TLS connections.
    #[arg(long = "cacert", value_name = "FILE")]
    pub cacert: Option<String>,

    /// Route requests through an HTTP proxy, e.g. "http://127.0.0.1:8080".
    #[arg(short = 'x', long = "proxy", value_name = "URL")]
    pub proxy: Option<String>,

    /// Send a Cookie header.
    #[arg(short = 'b', long = "cookie", value_name = "COOKIE")]
    pub cookie: Option<String>,

    /// Maximum total time for the transfer, in seconds.
    #[arg(short = 'm', long = "max-time", value_name = "SECS")]
    pub max_time: Option<u64>,

    /// Retry failed transfers this many times (on transient network errors).
    #[arg(long = "retry", value_name = "N")]
    pub retry: Option<u32>,

    /// Seconds to wait between retries (default 1).
    #[arg(long = "retry-delay", value_name = "SECS", default_value_t = 1)]
    pub retry_delay: u64,

    /// Resume a partial download. `-C -` resumes from the current file size;
    /// `-C N` resumes from byte offset N. Requires an explicit `-o=FILE`.
    #[arg(short = 'C', long = "continue-at", value_name = "OFFSET")]
    pub continue_at: Option<String>,

    /// Verify the downloaded file against a hash ("sha256", "sha1", "md5" or
    /// "sha512" followed by ":" and the hex digest). Repeatable; requires -o=FILE.
    #[arg(long = "expected-hash", value_name = "ALGO:HEX", action = ArgAction::Append)]
    pub expected_hash: Vec<String>,

    /// Auto-fetch a sidecar checksum file (<url>.sha256, .sha1, .md5, .sha512)
    /// and verify the download against it. Requires -o=FILE.
    #[arg(long = "verify")]
    pub verify: bool,

    /// Split the download into N parallel byte-range requests and reassemble
    /// them (HTTP/HTTPS only). Falls back to a single connection when the
    /// server does not advertise byte ranges.
    #[arg(long = "segments", value_name = "N")]
    pub segments: Option<usize>,

    /// UDP: keep receiving datagrams until interrupted (streaming mode, e.g.
    /// real-time audio/RTP). Without this flag, a single datagram is received
    /// (after sending `--data` if one was given).
    #[arg(long = "udp-listen")]
    pub udp_listen: bool,

    /// UDP: seconds to wait for a reply datagram (default 5).
    #[arg(long = "udp-timeout", value_name = "SECS", default_value_t = 5)]
    pub udp_timeout: u64,

    /// Connection timeout, in seconds.
    #[arg(long = "connect-timeout", value_name = "SECS")]
    pub connect_timeout: Option<u64>,

    /// Maximum number of requests to run concurrently.
    #[arg(short = 'Z', long = "parallel", value_name = "N", default_value_t = 1)]
    pub parallel: usize,

    /// Force the interface language ("en" or "zh"). Detected automatically when omitted.
    #[arg(long = "lang", value_name = "LANG")]
    pub lang: Option<String>,
}

impl Args {
    /// Whether the response body is written to stdout (no `-o`/`-O`).
    pub fn to_stdout(&self) -> bool {
        self.output.is_none() && !self.remote_name
    }

    /// Suppress all non-body chatter: `-s`, or streaming to stdout without
    /// `--detail`/`-v`.
    pub fn quiet(&self) -> bool {
        self.silent || (self.to_stdout() && !self.detail && !self.verbose)
    }
}
