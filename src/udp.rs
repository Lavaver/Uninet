//! Generic UDP client (`udp://` scheme).
//!
//! `udp://host:port` sends the `--data` payload (if any) as one datagram, then
//! receives. With `--udp-listen` it keeps receiving datagrams until
//! interrupted — useful for real-time streams such as RTP audio. Without a
//! payload it simply receives (a single datagram, or a stream in listen mode).

use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::cli::Args;
use crate::http::outgoing_payload;
use crate::protocol::{interrupted, FetchError, Resource, ResourceBody};

/// Fetch a UDP exchange (`udp://`) as a [`Resource`].
pub async fn fetch_udp(
    url: &str,
    args: &Args,
    rx: watch::Receiver<bool>,
) -> Result<Resource, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Failed(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::Failed(format!("invalid udp URL: {url}")))?;
    let port = parsed
        .port()
        .ok_or_else(|| FetchError::Failed(format!("udp URL needs a port: {url}")))?;
    let addr = format!("{host}:{port}");

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| FetchError::Failed(format!("{addr}: {e}")))?;
    socket
        .connect((host, port))
        .await
        .map_err(|e| FetchError::Failed(format!("{addr}: {e}")))?;

    // Send the outgoing datagram, if the user supplied a payload.
    if let Some(payload) = outgoing_payload(args).map_err(|e| FetchError::Failed(e.to_string()))? {
        tokio::select! {
            biased;
            _ = interrupted(rx.clone()) => return Err(FetchError::Interrupted),
            r = socket.send(&payload) => {
                r.map_err(|e| FetchError::Failed(format!("{addr}: {e}")))?;
            }
        }
    }

    let timeout = (!args.udp_listen).then(|| Duration::from_secs(args.udp_timeout));
    let body = udp_stream(socket, timeout);

    Ok(Resource {
        length: None,
        filename: None,
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

/// Stream received datagrams. `timeout` bounds a single-datagram receive; `None`
/// receives until the stream is dropped (interrupt or end of the pipeline).
fn udp_stream(socket: UdpSocket, timeout: Option<Duration>) -> ResourceBody {
    Box::pin(futures_util::stream::try_unfold(
        (socket, timeout),
        |(socket, timeout)| async move {
            let mut buf = vec![0u8; 65535];
            let recv = socket.recv(&mut buf);
            let n = match timeout {
                Some(d) => match tokio::time::timeout(d, recv).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(anyhow::Error::new(e)),
                    Err(_) => return Ok(None), // timed out
                },
                None => recv.await.map_err(anyhow::Error::new)?,
            };
            buf.truncate(n);
            Ok(Some((Bytes::from(buf), (socket, timeout))))
        },
    ))
}
