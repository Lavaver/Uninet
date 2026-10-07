//! WebSocket client (`ws://` / `wss://` schemes).
//!
//! Connects, sends the `--data` payload (if any) as the first message, then
//! streams every received text/binary message to the output pipeline. Pings are
//! answered with pongs automatically. TLS for `wss://` uses the Mozilla root
//! store (the HTTP `--insecure`/`--cacert` flags do not apply here).

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::cli::Args;
use crate::http::outgoing_payload;
use crate::protocol::{interrupted, FetchError, Resource, ResourceBody};

/// Fetch a WebSocket conversation as a [`Resource`] stream.
pub async fn fetch_ws(
    url: &str,
    args: &Args,
    rx: watch::Receiver<bool>,
) -> Result<Resource, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Failed(e.to_string()))?;
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return Err(FetchError::Failed(format!("unsupported websocket scheme: {url}")));
    }

    let (mut ws, _resp) = tokio::select! {
        biased;
        _ = interrupted(rx.clone()) => return Err(FetchError::Interrupted),
        r = tokio_tungstenite::connect_async(url) => {
            r.map_err(|e| FetchError::Failed(e.to_string()))?
        }
    };

    // Send the initial message when the user supplied a payload: `--data` /
    // `--data-raw` as text, `--data-binary` as binary.
    if let Some(payload) = outgoing_payload(args).map_err(|e| FetchError::Failed(e.to_string()))? {
        let msg = if args.data_binary.is_some() {
            Message::binary(payload)
        } else {
            match String::from_utf8(payload) {
                Ok(text) => Message::text(text),
                Err(e) => Message::binary(e.into_bytes()),
            }
        };
        ws.send(msg).await.map_err(|e| FetchError::Failed(e.to_string()))?;
    }

    Ok(Resource {
        length: None,
        filename: None,
        status: Some("101".to_string()),
        final_url: None,
        content_type: None,
        num_redirects: 0,
        head: Vec::new(),
        resume: None,
        already_complete: false,
        body: ws_stream(ws),
    })
}

/// Stream received text/binary messages as bytes, answering pings and stopping
/// on close.
fn ws_stream(ws: WebSocketStream<MaybeTlsStream<TcpStream>>) -> ResourceBody {
    Box::pin(futures_util::stream::unfold(Some(ws), |ws| async move {
        let mut ws = ws?;
        loop {
            match ws.next().await {
                Some(Ok(msg)) => match msg {
                    Message::Text(_) | Message::Binary(_) => {
                        return Some((Ok(msg.into_data()), Some(ws)));
                    }
                    Message::Ping(payload) => {
                        let _ = ws.send(Message::Pong(payload)).await;
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => {
                        let _ = ws.send(Message::Close(None)).await;
                        return None;
                    }
                    Message::Frame(_) => {}
                },
                Some(Err(e)) => return Some((Err(anyhow::Error::new(e)), None)),
                None => return None,
            }
        }
    }))
}
