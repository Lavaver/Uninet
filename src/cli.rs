//! Command-line interface definition.

use std::path::PathBuf;

use clap::{ArgAction, CommandFactory, FromArgMatches, Parser};

use crate::i18n::Lang;

/// A standard style HTTP client.
#[derive(Debug, Parser)]
#[command(
    name = "webclient",
    version,
    about = "Uninet Client - A simple yet powerful web Swiss Army knife",
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

    /// Disable the zero-width-space (U+200B) guard that, by default, separates
    /// every character of an HTTP(S) text body written to stdout. The guard breaks
    /// `uninet[.exe] <url>` followed by `| sh` (for Bash, Zsh, etc.) / `| iex` (for PowerShell) / `| cmd.exe /Q` (for Windows Command Prompt) / Other Shell script-injection while leaving the text
    /// visually identical; pass this flag only for sources you trust.
    #[arg(long = "no-control-characters")]
    pub no_control_characters: bool,

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

    /// Seconds to wait between retries.
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

    /// UDP: seconds to wait for a reply datagram.
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

    /// Parse the command line, localizing `--help` to the requested or
    /// detected interface language.
    pub fn parse_localized() -> Self {
        let cmd = localize_help(Self::command(), initial_lang());
        match Self::from_arg_matches(&cmd.get_matches()) {
            Ok(args) => args,
            Err(err) => err.exit(),
        }
    }
}

/// Override the derived `--help` text with the Chinese translation when the
/// interface language is Chinese. English is the default (the doc comments), so
/// this is a no-op for [`Lang::En`].
pub fn localize_help(mut cmd: clap::Command, lang: Lang) -> clap::Command {
    if lang == Lang::En {
        return cmd;
    }
    cmd = cmd.about(
        "Uninet Client - 一个简单但又不简单的网络瑞士军刀",
    );
    for (id, help) in ZH_HELP {
        cmd = cmd.mut_arg(*id, |a| a.help(*help));
    }
    cmd
}

/// Resolve the interface language before clap builds its `--help`, honouring an
/// explicit `--lang`/`--lang=<v>` on the command line and otherwise falling back
/// to the OS locale.
fn initial_lang() -> Lang {
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        if let Some(value) = arg.strip_prefix("--lang=")
            && let Some(lang) = Lang::from_str(value)
        {
            return lang;
        } else if arg == "--lang"
            && let Some(value) = argv.next()
            && let Some(lang) = Lang::from_str(&value)
        {
            return lang;
        }
    }
    Lang::detect()
}

/// Chinese `--help` text for every argument, keyed by its clap id (the field
/// name). Applied only when the interface language is Chinese.
const ZH_HELP: &[(&str, &str)] = &[
    ("urls", "一个或多个要请求的 URL。"),
    ("method", "要使用的 HTTP 方法。默认为 GET（提供请求体时为 POST，-I 时为 HEAD）。"),
    ("headers", "添加请求头，如 \"Content-Type: application/json\"。可重复。"),
    ("data", "请求体（支持 \"@file\" 从文件读取）。"),
    ("data_raw", "原始请求体（不解析 \"@file\"）。"),
    ("data_binary", "二进制请求体（支持 \"@file\"）。"),
    ("json", "JSON 请求体；会设置 \"Content-Type: application/json\"。"),
    ("form", "多部分表单字段：\"name=value\" 或 \"name=@file\"。可重复。"),
    ("output", "将响应体写入 FILE 而非 stdout。不带 FILE（裸 -o/--output）时，名称取自 Content-Disposition 头，回退到 URL 的最后一段路径。用 --output=FILE 或 -o=FILE 指定名称。"),
    ("remote_name", "按远程 URL / Content-Disposition 命名保存到文件。"),
    ("no_clobber", "拒绝覆盖已存在的输出文件。"),
    ("no_control_characters", "禁用默认情况下用于分隔写入标准输出（stdout）的 HTTP(S) 文本正文中每个字符的零宽度空格（U+200B）分隔符。该保护机制会破坏 `uninet[.exe] <url>` 后跟 `| sh`（适用于 Bash、Zsh 等）/ `| iex`（适用于 PowerShell）/ `| cmd.exe /Q`（适用于 Windows 命令提示符）/ 其他 Shell 脚本注入，同时使文本在视觉上保持不变；仅对您信任的来源使用此标志。"),
    ("location", "跟随 HTTP 重定向（默认启用；为兼容 curl 而保留）。"),
    ("fail", "服务器返回 HTTP 错误（4xx/5xx）时以退出码 22 失败（而非 0），且不把错误体写入输出。"),
    ("include", "在输出中包含响应状态行和响应头。"),
    ("head", "仅获取响应头（HEAD 请求）。"),
    ("silent", "静默模式：仅输出响应体。"),
    ("verbose", "详细输出（在 stderr 输出请求与响应详情）。"),
    ("detail", "在正文旁显示请求状态（正在请求 / 已连接 / 正在重定向、进度与摘要）。默认 stdout 只输出正文。"),
    ("write_out", "下载完成后将传输信息输出到 stderr。支持 %{...} 变量：http_code、size_download、size_header、time_total、url_effective、content_type、num_redirects、filename_effective。"),
    ("no_color", "禁用彩色输出。"),
    ("user_agent", "设置 User-Agent 头。"),
    ("user", "HTTP 基本认证凭据，\"user:password\"。"),
    ("referer", "设置 Referer 头。"),
    ("range", "获取字节范围，如 \"0-1023\" 或 \"512-\"。"),
    ("insecure", "跳过 TLS 证书校验。"),
    ("cacert", "使用自定义 CA 证书包（PEM）校验 TLS 连接。"),
    ("proxy", "通过 HTTP 代理路由请求，如 \"http://127.0.0.1:8080\"。"),
    ("cookie", "发送 Cookie 头。"),
    ("max_time", "传输的最大总时长，单位秒。"),
    ("retry", "传输失败时重试的次数（针对临时性网络错误）。"),
    ("retry_delay", "两次重试之间的等待秒数。"),
    ("continue_at", "续传部分下载。-C - 从当前文件大小续传；-C N 从字节偏移 N 续传。需要显式 -o=FILE。"),
    ("expected_hash", "用哈希校验下载的文件（\"sha256\"、\"sha1\"、\"md5\" 或 \"sha512\"，后接 \":\" 和十六进制摘要）。可重复；需要 -o=FILE。"),
    ("verify", "自动获取 sidecar 校验文件（<url>.sha256、.sha1、.md5、.sha512）并据此校验下载。需要 -o=FILE。"),
    ("segments", "将下载拆分为 N 个并行字节范围请求并按序重组（仅 HTTP/HTTPS）。服务器不支持字节范围时回退到单连接。"),
    ("udp_listen", "UDP：持续接收数据报直到被中断（流式模式，如实时音频/RTP）。不带此标志时只接收单个数据报（如提供了 --data 则先发送）。"),
    ("udp_timeout", "UDP：等待回复数据报的秒数。"),
    ("connect_timeout", "连接超时，单位秒。"),
    ("parallel", "并发运行的最大请求数。"),
    ("lang", "强制指定界面语言（\"en\" 或 \"zh\"）。省略时自动检测。"),
];
