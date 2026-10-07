//! Uninet Client — a curl / Invoke-WebRequest compatible client that also
//! speaks WebSocket, UDP, DNS, FTP, SFTP and more.

mod cli;
mod dns;
mod http;
mod i18n;
mod protocol;
mod trust;
mod udp;
mod ui;
mod ws;

use std::io::IsTerminal;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use indicatif::{MultiProgress, ProgressDrawTarget};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use cli::Args;
use http::{build_client, build_jobs, execute, new_spinner, reset_spinner, ClaimedOutputs, Job, JobOutcome};
use i18n::{Lang, L10n};
use ui::Palette;

/// Shared, immutable state handed to every request task.
struct Ctx {
    palette: Palette,
    l10n: L10n,
    mp: MultiProgress,
    live: bool,
    /// Aggregate bytes written across all jobs, for the Windows Terminal
    /// tab-progress ring.
    done_bytes: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    /// Output paths already claimed by a job, so concurrent downloads never
    /// write to the same file.
    used_outputs: ClaimedOutputs,
}

#[tokio::main]
async fn main() {
    let args = Args::parse_localized();
    std::process::exit(run(args).await);
}

async fn run(args: Args) -> i32 {
    let lang = match args.lang.as_deref() {
        Some(s) => Lang::from_str(s).unwrap_or_else(Lang::detect),
        None => Lang::detect(),
    };
    let l10n = L10n::new(lang);
    let palette = Palette::new(!args.no_color);

    // Live animated spinners are only useful on a real terminal and outside
    // silent mode.
    let live = !args.quiet() && std::io::stderr().is_terminal();

    let client = match build_client(&args) {
        Ok(c) => c,
        Err(e) => {
            anstream::eprintln!("{}", palette.bright_red(format!("{e}")));
            return 2;
        }
    };

    let jobs = match build_jobs(&args) {
        Ok(j) => j,
        Err(e) => {
            anstream::eprintln!("{}", palette.bright_red(format!("{e}")));
            return 2;
        }
    };
    let total = jobs.len();

    let draw = if live {
        ProgressDrawTarget::stderr()
    } else {
        ProgressDrawTarget::hidden()
    };
    let mp = MultiProgress::with_draw_target(draw);

    // Ctrl+C handler: broadcast the interrupt to every task via a watch channel.
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = tx.send(true);
        }
    });

    let semaphore = Arc::new(Semaphore::new(args.parallel.max(1)));
    let done_bytes = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));

    // Feature: like winget, drive the Windows Terminal tab-progress ring from
    // the aggregate download position.
    if live && cfg!(windows) {
        let done = done_bytes.clone();
        let total = total_bytes.clone();
        tokio::spawn(async move {
            watch_win_term(done, total).await;
        });
    }

    let ctx = Arc::new(Ctx {
        palette: palette.clone(),
        l10n,
        mp: mp.clone(),
        live,
        done_bytes,
        total_bytes,
        used_outputs: ClaimedOutputs::default(),
    });
    let args = Arc::new(args);

    let mut set = JoinSet::new();
    for job in jobs {
        let ctx = ctx.clone();
        let client = client.clone();
        let sem = semaphore.clone();
        let rx = rx.clone();
        let args = args.clone();
        set.spawn(async move {
            run_job(job, client, args, ctx, sem, rx).await
        });
    }

    let mut outcomes: Vec<JobOutcome> = Vec::with_capacity(total);
    let mut interrupted = false;
    let guard = rx;

    loop {
        if set.is_empty() {
            break;
        }
        if interrupted {
            if let Some(res) = set.join_next().await {
                if let Ok(outcome) = res {
                    outcomes.push(outcome);
                }
            }
        } else {
            tokio::select! {
                _ = wait_interrupt(guard.clone()) => {
                    interrupted = true;
                }
                res = set.join_next() => {
                    if let Some(Ok(outcome)) = res {
                        outcomes.push(outcome);
                    }
                }
            }
        }
    }

    // Clear the tab-progress ring.
    if live && cfg!(windows) {
        ui::win_term::clear();
    }

    if interrupted {
        130
    } else if let Some(code) = outcomes
        .iter()
        .filter_map(|o| match o {
            JobOutcome::Failed(c) => Some(*c),
            _ => None,
        })
        .max()
    {
        code as i32
    } else {
        0
    }
}

/// Periodically reflect the aggregate download progress into the Windows
/// Terminal tab-progress ring (`OSC 9;4`).
async fn watch_win_term(done: Arc<AtomicU64>, total: Arc<AtomicU64>) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let total = total.load(Ordering::Relaxed);
        let done = done.load(Ordering::Relaxed);
        if total > 0 {
            let pct = ((done * 100) / total).min(100) as u8;
            ui::win_term::set(pct);
        } else if done > 0 {
            ui::win_term::indeterminate();
        }
    }
}

async fn run_job(
    job: Job,
    client: reqwest::Client,
    args: Arc<Args>,
    ctx: Arc<Ctx>,
    sem: Arc<Semaphore>,
    rx: watch::Receiver<bool>,
) -> JobOutcome {
    let pb = ctx.mp.add(new_spinner());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(format!(
        "{} {} {}",
        ctx.palette.dim("⏳"),
        ctx.palette.cyan(&job.url),
        ctx.palette.dim(ctx.l10n.queued()),
    ));

    // Wait for a concurrency slot; abort cleanly if interrupted while queued.
    let _permit = tokio::select! {
        biased;
        _ = wait_interrupt(rx.clone()) => {
            pb.finish_with_message(format!(
                "{} {}",
                ctx.palette.red(ctx.l10n.stopping()),
                ctx.palette.cyan(&job.url),
            ));
            return JobOutcome::Interrupted;
        }
        permit = sem.clone().acquire_owned() => match permit {
            Ok(p) => p,
            Err(_) => {
                return JobOutcome::Interrupted;
            }
        },
    };

    pb.set_message(format!(
        "{} {}",
        ctx.palette.cyan(&job.url),
        ctx.palette.dim(ctx.l10n.fetching()),
    ));

    let attempts = args.retry.unwrap_or(0).saturating_add(1) as usize;
    let mut attempt = 0usize;
    loop {
        let outcome = execute(
            &client,
            &args,
            &job,
            &pb,
            &ctx.palette,
            &ctx.l10n,
            &ctx.mp,
            ctx.live,
            &ctx.done_bytes,
            &ctx.total_bytes,
            &ctx.used_outputs,
            rx.clone(),
        )
        .await;

        attempt += 1;
        if let JobOutcome::Failed(code) = outcome
            && attempt < attempts
            && is_retryable(code)
        {
            reset_spinner(&pb);
            pb.set_message(format!(
                "{} {} {} {}/{}",
                ctx.palette.cyan(&job.url),
                ctx.palette.dim(ctx.l10n.retrying()),
                ctx.palette.dim(format!("in {}s", args.retry_delay)),
                attempt + 1,
                attempts,
            ));
            tokio::time::sleep(Duration::from_secs(args.retry_delay)).await;
            pb.set_message(format!(
                "{} {}",
                ctx.palette.cyan(&job.url),
                ctx.palette.dim(ctx.l10n.fetching()),
            ));
            continue;
        }
        return outcome;
    }
}

/// Whether a curl-style exit code indicates a transient failure worth retrying.
fn is_retryable(code: u8) -> bool {
    matches!(code, 5 | 6 | 7 | 28)
}

/// Resolve once the interrupt signal has been observed.
async fn wait_interrupt(mut rx: watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    let _ = rx.changed().await;
}
