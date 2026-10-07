//! Terminal color and formatting helpers.
//!
//! Colors are emitted as ANSI escape sequences and routed through `anstream`,
//! which enables virtual-terminal processing on Windows and strips codes when
//! the stream is not a terminal.

use std::fmt::Display;

use anstyle::{AnsiColor, Color, Style};

/// Braille "loading circle" characters, used as the spinner animation frames.
pub const BRAILLE: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";

/// Wraps color decisions so every call site is consistent.
#[derive(Debug, Clone)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    pub fn new(enabled: bool) -> Self {
        // Respect the de-facto `NO_COLOR` standard unless explicitly disabled.
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Self {
            enabled: enabled && !no_color,
        }
    }

    fn paint(&self, text: impl Display, style: Style) -> String {
        if self.enabled {
            format!("{style}{text}{}", anstyle::Reset)
        } else {
            text.to_string()
        }
    }

    pub fn red(&self, t: impl Display) -> String {
        self.paint(t, Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red))))
    }
    pub fn bright_red(&self, t: impl Display) -> String {
        self.paint(t, Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightRed))))
    }
    pub fn cyan(&self, t: impl Display) -> String {
        self.paint(t, Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))))
    }
    pub fn dim(&self, t: impl Display) -> String {
        self.paint(t, Style::new().dimmed())
    }
    pub fn bold(&self, t: impl Display) -> String {
        self.paint(t, Style::new().bold())
    }

    /// The `info:` log prefix, matching rustup's bright-green banner.
    pub fn info(&self) -> String {
        self.paint(
            "info:",
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightGreen)))
                .bold(),
        )
    }

    /// The `error:` log prefix, matching rustup's bright-red banner.
    pub fn error(&self) -> String {
        self.paint(
            "error:",
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightRed)))
                .bold(),
        )
    }

    /// Style for an HTTP status code, coloured by its class.
    pub fn status_style(&self, code: u16) -> Style {
        let color = match code {
            100..=199 => AnsiColor::White,
            200..=299 => AnsiColor::Green,
            300..=399 => AnsiColor::Cyan,
            400..=499 => AnsiColor::Yellow,
            _ => AnsiColor::BrightRed,
        };
        Style::new()
            .fg_color(Some(Color::Ansi(color)))
            .bold()
    }

    pub fn status(&self, code: u16) -> String {
        self.paint(code.to_string(), self.status_style(code))
    }
}

/// Format a byte count into a human-friendly string (`B`, `KiB`, `MiB`, ...),
/// using the same binary units as rustup and indicatif.
pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Emit the Windows Terminal / ConEmu progress sequence (`OSC 9;4`) that makes
/// the tab show a progress ring, the same mechanism winget uses. The sequences
/// are harmless no-ops on terminals that do not understand them.
pub mod win_term {
    /// Set the tab progress ring to a determinate percentage (0-100).
    pub fn set(pct: u8) {
        anstream::eprint!("\x1b]9;4;1;{}\x07", pct.clamp(0, 100));
    }

    /// Set the tab progress ring to an indeterminate (spinning) state.
    /// The trailing `;0` is the (ignored) progress value, keeping the sequence
    /// in the full `ESC ] 9 ; 4 ; State ; Progress BEL` form.
    pub fn indeterminate() {
        anstream::eprint!("\x1b]9;4;3\x07");
    }

    /// Clear the tab progress ring.
    pub fn clear() {
        anstream::eprint!("\x1b]9;4;0\x07");
    }
}
