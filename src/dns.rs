//! Minimal DNS-over-UDP client (`dns://` scheme).
//!
//! `dns://resolver/name` sends an A (and AAAA) query over UDP and renders the
//! resolved addresses as text. When the URL has no path — `dns://example.com`
//! — the host is treated as the name and a public resolver is used. The wire
//! encode/decode helpers are exposed for unit testing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::watch;

use crate::cli::Args;
use crate::protocol::{interrupted, FetchError, Resource, ResourceBody};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const DEFAULT_RESOLVER: &str = "8.8.8.8";
const MAX_DNS_PACKET: usize = 4096;

/// Monotonic query ID, so concurrent lookups never reuse an ID mid-flight.
static NEXT_ID: AtomicU16 = AtomicU16::new(0x4a21);

/// Human-readable name for a DNS response code.
fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

/// Encode a DNS query for `name` (QNAME + QTYPE + QCLASS=IN), with recursion
/// desired.
pub fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// The addresses carried by a DNS response, plus its response code.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub rcode: u8,
    pub addresses: Vec<IpAddr>,
}

/// Parse a DNS response message, following compression pointers and collecting
/// A and AAAA records (CNAMEs and other record types are skipped).
pub fn parse_response(bytes: &[u8]) -> Option<DnsAnswer> {
    if bytes.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let rcode = (flags & 0x000f) as u8;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(bytes, pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
    }

    let mut addresses = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(bytes, pos)?;
        let rdata = pos.checked_add(10)?; // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        if rdata > bytes.len() {
            return Some(DnsAnswer { rcode, addresses });
        }
        let atype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let rdlength = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        let body = rdata.checked_add(rdlength)?;
        if body > bytes.len() {
            return Some(DnsAnswer { rcode, addresses });
        }
        match atype {
            TYPE_A if rdlength == 4 => {
                addresses.push(IpAddr::V4(Ipv4Addr::new(
                    bytes[rdata],
                    bytes[rdata + 1],
                    bytes[rdata + 2],
                    bytes[rdata + 3],
                )));
            }
            TYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[rdata..rdata + 16]);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos = body;
    }
    Some(DnsAnswer { rcode, addresses })
}

/// Advance past a (possibly compressed) DNS name, returning the byte offset of
/// the first byte after it.
fn skip_name(bytes: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *bytes.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer: two bytes total.
            return Some(pos + 2);
        }
        pos = pos.checked_add(1)?.checked_add(len)?;
    }
}

/// Resolve the (resolver, name) pair from a `dns://` URL.
fn split_url(parsed: &url::Url) -> (String, String) {
    let host = parsed.host_str().unwrap_or("");
    let path = parsed.path().trim_start_matches('/');
    if path.is_empty() {
        // `dns://example.com`: the host is the name to resolve.
        (
            DEFAULT_RESOLVER.to_string(),
            host.to_string(),
        )
    } else if host.is_empty() {
        (DEFAULT_RESOLVER.to_string(), path.to_string())
    } else {
        (host.to_string(), path.to_string())
    }
}

/// Fetch a DNS lookup (`dns://`) as a text [`Resource`].
pub async fn fetch_dns(
    url: &str,
    args: &Args,
    rx: watch::Receiver<bool>,
) -> Result<Resource, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Failed(e.to_string()))?;
    let (resolver, name) = split_url(&parsed);
    let name = percent_encoding::percent_decode_str(&name)
        .decode_utf8_lossy()
        .into_owned();
    if name.is_empty() {
        return Err(FetchError::Failed(format!("dns URL needs a name: {url}")));
    }
    let port = parsed.port().unwrap_or(53);

    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| FetchError::Failed(e.to_string()))?;
    socket
        .connect((resolver.as_str(), port))
        .await
        .map_err(|e| FetchError::Failed(format!("{resolver}:{port}: {e}")))?;

    // Query A, then AAAA, merging whatever comes back.
    let mut rcode = 0u8;
    let mut addresses = Vec::new();
    for qtype in [TYPE_A, TYPE_AAAA] {
        let query = encode_query(NEXT_ID.fetch_add(1, Ordering::Relaxed), &name, qtype);
        if let Err(e) = socket.send(&query).await {
            return Err(FetchError::Failed(format!("{resolver}:{port}: {e}")));
        }
        let mut buf = [0u8; MAX_DNS_PACKET];
        let n = tokio::select! {
            biased;
            _ = interrupted(rx.clone()) => return Err(FetchError::Interrupted),
            r = tokio::time::timeout(Duration::from_secs(args.udp_timeout), socket.recv(&mut buf)) => {
                match r {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(FetchError::Failed(format!("{resolver}:{port}: {e}"))),
                    Err(_) => continue, // no answer for this type
                }
            }
        };
        if let Some(ans) = parse_response(&buf[..n]) {
            rcode = ans.rcode;
            addresses.extend(ans.addresses);
        }
    }

    let text = if addresses.is_empty() {
        format!("{name}: no A/AAAA records ({})\n", rcode_name(rcode))
    } else {
        addresses
            .iter()
            .map(|a| format!("{name} -> {a}\n"))
            .collect::<String>()
    };

    let bytes = text.into_bytes();
    let length = bytes.len() as u64;
    let body: ResourceBody = Box::pin(futures_util::stream::once(async move {
        Ok::<Bytes, anyhow::Error>(Bytes::from(bytes))
    }));

    Ok(Resource {
        length: Some(length),
        filename: None,
        status: Some(rcode_name(rcode).to_string()),
        final_url: None,
        content_type: None,
        num_redirects: 0,
        head: Vec::new(),
        resume: None,
        already_complete: false,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_query() {
        let q = encode_query(0x1234, "example.com", TYPE_A);
        assert_eq!(&q[..12], &[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // QNAME: 7 "example" 3 "com" 0, then QTYPE A and QCLASS IN.
        assert_eq!(&q[12..], &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
            0x00, 0x01, // TYPE A
            0x00, 0x01, // CLASS IN
        ]);
    }

    #[test]
    fn parses_an_a_record() {
        // Header: ID=0, flags=0x8180 (QR|RD|RA, rcode 0), QD=1, AN=1.
        let mut msg = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        // Question: "example.com" A IN
        msg.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01]);
        // Answer: name pointer to 0x0c, TYPE A, CLASS IN, TTL, RDLENGTH 4, 93.184.216.34
        msg.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 93, 184, 216, 34]);
        let ans = parse_response(&msg).expect("valid response");
        assert_eq!(ans.rcode, 0);
        assert_eq!(ans.addresses, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[test]
    fn parses_nxdomain() {
        let mut msg = vec![0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        msg.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01]);
        let ans = parse_response(&msg).expect("valid response");
        assert_eq!(ans.rcode, 3);
        assert!(ans.addresses.is_empty());
    }

    #[test]
    fn splits_url_forms() {
        let u = url::Url::parse("dns://8.8.8.8/example.com").unwrap();
        assert_eq!(split_url(&u), ("8.8.8.8".to_string(), "example.com".to_string()));
        let u = url::Url::parse("dns://example.com").unwrap();
        assert_eq!(split_url(&u), (DEFAULT_RESOLVER.to_string(), "example.com".to_string()));
        let u = url::Url::parse("dns:///example.com").unwrap();
        assert_eq!(split_url(&u), (DEFAULT_RESOLVER.to_string(), "example.com".to_string()));
    }
}
