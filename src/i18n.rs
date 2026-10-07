//! Internationalization support.
//!
//! The language is detected from the operating system locale and can be
//! overridden with `--lang`. English and Chinese are provided out of the box.

/// A supported language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

impl Lang {
    /// Detect the language from the OS locale, then from the usual POSIX
    /// environment variables as a fallback.
    pub fn detect() -> Self {
        if let Some(locale) = sys_locale::get_locale() {
            if let Some(lang) = Self::from_str(&locale) {
                return lang;
            }
        }
        for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
            if let Ok(value) = std::env::var(var) {
                if let Some(lang) = Self::from_str(&value) {
                    return lang;
                }
            }
        }
        Lang::En
    }

    /// Parse a language tag or name such as `"zh"`, `"zh-CN"`, `"en"`, `"en-US"`.
    pub fn from_str(s: &str) -> Option<Self> {
        let low = s.trim().to_ascii_lowercase();
        if low.starts_with("zh") || low.starts_with("cn") || low.contains("chinese") {
            Some(Lang::Zh)
        } else if low.starts_with("en") {
            Some(Lang::En)
        } else {
            None
        }
    }
}

/// Localized strings for a chosen language.
#[derive(Debug, Clone, Copy)]
pub struct L10n {
    lang: Lang,
}

impl L10n {
    pub fn new(lang: Lang) -> Self {
        Self { lang }
    }

    /// Shown while a request is waiting for a free connection slot.
    pub fn queued(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "排队中",
            Lang::En => "Queued",
        }
    }

    /// Shown while a request is in flight.
    pub fn fetching(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "请求中",
            Lang::En => "Fetching",
        }
    }

    /// The message shown on Ctrl+C for requests that are still in flight or
    /// have not started yet.

    pub fn stopping(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "正在停止请求...",
            Lang::En => "Stopping request...",
        }
    }

    /// Shown as `info: requesting <url>` when a request starts.
    pub fn requesting(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "正在请求",
            Lang::En => "requesting",
        }
    }

    /// Shown as `info: connected to <ip>:<port>` once the socket is resolved.
    pub fn connected_to(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "已连接到",
            Lang::En => "connected to",
        }
    }

    /// Shown as `info: redirecting to <url>` when following a 301/302/….
    pub fn redirecting(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "正在重定向到",
            Lang::En => "redirecting to",
        }
    }

    /// Replaces the "fetching" status for large downloads saved to a file.
    pub fn streaming_to(&self, path: &str) -> String {
        match self.lang {
            Lang::Zh => format!("正在向 {path} 写入流"),
            Lang::En => format!("streaming to {path}"),
        }
    }

    /// Shown while waiting for another process to release a lock on a file.
    pub fn waiting_for_lock(&self, path: &str) -> String {
        match self.lang {
            Lang::Zh => format!("等待文件锁释放：{path}"),
            Lang::En => format!("waiting for lock on {path}"),
        }
    }

    /// Verb used in the final summary: `request complete - 54.5 MiB (200)`.
    pub fn completed(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "请求完成",
            Lang::En => "requested",
        }
    }

    /// Shown when `-C` resumes onto a file that is already fully downloaded.
    pub fn already_complete(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "文件已完整，无需续传",
            Lang::En => "already completely downloaded",
        }
    }

    /// Shown between retries: `retrying in 1s (attempt 2/5)`.
    pub fn retrying(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "重试",
            Lang::En => "retrying",
        }
    }

    /// Shown after a download whose checksum matched.
    pub fn checksum_verified(&self) -> &'static str {
        match self.lang {
            Lang::Zh => "校验通过",
            Lang::En => "checksum verified",
        }
    }

    /// Column headers for the `dns://` results table: (host, target, type).
    pub fn dns_table_header(&self) -> (&'static str, &'static str, &'static str) {
        match self.lang {
            Lang::Zh => ("主机域名", "主机目标", "记录类型"),
            Lang::En => ("Hostname", "Target", "Record type"),
        }
    }

    /// Label for one row's record type in the `dns://` results table, given its
    /// type code (`"A"`, `"AAAA"`, `"MX"`, …).
    pub fn dns_record_type(&self, code: &str) -> String {
        match self.lang {
            Lang::Zh => format!("{code} 类型"),
            Lang::En => format!("{code} record"),
        }
    }
}
