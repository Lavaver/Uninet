//! Minimal DNS-over-UDP client (`dns://` scheme).
//!
//! `dns://resolver/name` queries a resolver for the common record types
//! (A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV/CAA) and renders every answer as a
//! box-drawing table. When the URL has no path — `dns://example.com` — the host
//! is treated as the name and a public resolver is used. The wire encode/decode
//! helpers are exposed for unit testing.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::watch;

use crate::cli::Args;
use crate::i18n::L10n;
use crate::protocol::{interrupted, FetchError, Resource, ResourceBody};

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_CAA: u16 = 257;
const CLASS_IN: u16 = 1;
const DEFAULT_RESOLVER: &str = "8.8.8.8";
const MAX_DNS_PACKET: usize = 4096;

/// The narrowest a table column's content is allowed to become when the table
/// is squeezed to fit a terminal.
const MIN_COL_WIDTH: usize = 4;

/// The record types queried for a name, in presentation order.
const QUERY_TYPES: [u16; 10] = [
    TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_TXT, TYPE_NS, TYPE_SOA, TYPE_PTR, TYPE_SRV, TYPE_CAA,
];

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

/// The IANA name for a record type, used as the table's type label.
fn type_name(rtype: u16) -> String {
    let code = match rtype {
        TYPE_A => "A",
        TYPE_NS => "NS",
        TYPE_CNAME => "CNAME",
        TYPE_SOA => "SOA",
        TYPE_PTR => "PTR",
        TYPE_MX => "MX",
        TYPE_TXT => "TXT",
        TYPE_AAAA => "AAAA",
        TYPE_SRV => "SRV",
        TYPE_CAA => "CAA",
        other => return format!("TYPE{other}"),
    };
    code.to_string()
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

/// A single resource record, decoded for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// The record's owner name, e.g. `"example.com"`.
    pub name: String,
    /// The record type (A=1, AAAA=28, CNAME=5, …).
    pub rtype: u16,
    /// The rendered RDATA: an address, a target name, quoted text, etc.
    pub data: String,
}

/// The records carried by a DNS response, plus its response code.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub rcode: u8,
    pub records: Vec<DnsRecord>,
}

/// Decode a (possibly compressed) domain name at `pos`, returning the name and
/// the offset of the first byte after it in the original message.
fn decode_name(bytes: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = pos;
    let mut next = None;
    loop {
        let len = *bytes.get(cursor)? as usize;
        if len & 0xc0 == 0xc0 {
            // Compression pointer: the name continues at the pointed-to offset,
            // but the next field still follows this two-byte pointer.
            if next.is_none() {
                next = Some(cursor + 2);
            }
            let ptr = (len & 0x3f) << 8 | (*bytes.get(cursor + 1)? as usize);
            cursor = ptr;
        } else if len == 0 {
            if next.is_none() {
                next = Some(cursor + 1);
            }
            break;
        } else {
            cursor += 1;
            let label = bytes.get(cursor..cursor + len)?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            cursor += len;
        }
    }
    // An empty label sequence is the DNS root, conventionally rendered as ".".
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Some((name, next?))
}

/// Render one record's RDATA (at absolute offset `rdata`, `rdlength` bytes long)
/// into a human-readable string, or `None` for a type we don't understand.
fn decode_rdata(bytes: &[u8], rtype: u16, rdata: usize, rdlength: usize) -> Option<String> {
    let raw = bytes.get(rdata..rdata + rdlength)?;
    match rtype {
        TYPE_A if rdlength == 4 => {
            Some(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string())
        }
        TYPE_AAAA if rdlength == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Some(Ipv6Addr::from(octets).to_string())
        }
        TYPE_CNAME | TYPE_NS | TYPE_PTR => decode_name(bytes, rdata).map(|(n, _)| n),
        TYPE_MX if rdlength >= 3 => {
            let pref = u16::from_be_bytes([raw[0], raw[1]]);
            let target = decode_name(bytes, rdata + 2).map(|(n, _)| n)?;
            Some(format!("{pref} {target}"))
        }
        TYPE_TXT => {
            // One or more `<length><bytes>` character-strings.
            let mut parts: Vec<String> = Vec::new();
            let mut pos = 0usize;
            while pos < raw.len() {
                let len = *raw.get(pos)? as usize;
                pos += 1;
                parts.push(String::from_utf8_lossy(raw.get(pos..pos + len)?).into_owned());
                pos += len;
            }
            Some(format!("\"{}\"", parts.concat()))
        }
        TYPE_SOA => {
            let (mname, next) = decode_name(bytes, rdata)?;
            let (rname, next) = decode_name(bytes, next)?;
            let nums = bytes.get(next..next + 20)?;
            let serial = u32::from_be_bytes([nums[0], nums[1], nums[2], nums[3]]);
            Some(format!("{mname} {rname} {serial}"))
        }
        TYPE_SRV if rdlength >= 7 => {
            let pri = u16::from_be_bytes([raw[0], raw[1]]);
            let weight = u16::from_be_bytes([raw[2], raw[3]]);
            let port = u16::from_be_bytes([raw[4], raw[5]]);
            let target = decode_name(bytes, rdata + 6).map(|(n, _)| n)?;
            Some(format!("{pri} {weight} {port} {target}"))
        }
        TYPE_CAA if rdlength >= 2 => {
            let taglen = raw[1] as usize;
            let tag = String::from_utf8_lossy(raw.get(2..2 + taglen)?).into_owned();
            let value = String::from_utf8_lossy(raw.get(2 + taglen..)?).into_owned();
            Some(format!("{tag} \"{value}\""))
        }
        _ => None,
    }
}

/// Parse a DNS response message, following compression pointers and decoding
/// every supported record type in the answer section.
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
        let (_, next) = decode_name(bytes, pos)?;
        pos = next.checked_add(4)?; // QTYPE + QCLASS
    }

    let mut records = Vec::new();
    for _ in 0..ancount {
        let Some((name, next)) = decode_name(bytes, pos) else {
            break;
        };
        pos = next;
        let Some(rdata) = pos.checked_add(10) else {
            break; // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        };
        if rdata > bytes.len() {
            break;
        }
        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let rdlength = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        let Some(body) = rdata.checked_add(rdlength) else {
            break;
        };
        if body > bytes.len() {
            break;
        }
        if let Some(data) = decode_rdata(bytes, rtype, rdata, rdlength) {
            records.push(DnsRecord { name, rtype, data });
        }
        pos = body;
    }
    Some(DnsAnswer { rcode, records })
}

/// Resolve the (resolver, name) pair from a `dns://` URL.
fn split_url(parsed: &url::Url) -> (String, String) {
    let host = parsed.host_str().unwrap_or("");
    let path = parsed.path().trim_start_matches('/');
    if path.is_empty() {
        // `dns://example.com`: the host is the name to resolve.
        (DEFAULT_RESOLVER.to_string(), host.to_string())
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
    l10n: &L10n,
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

    // Query each record type in turn, merging and de-duplicating the answers.
    let mut rcode = 0u8;
    let mut records: Vec<DnsRecord> = Vec::new();
    for qtype in QUERY_TYPES {
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
            for rec in ans.records {
                if !records.contains(&rec) {
                    records.push(rec);
                }
            }
        }
    }

    let text = if records.is_empty() {
        format!("{name}: no records ({})\n", rcode_name(rcode))
    } else {
        render_table(&records, l10n, terminal_width())
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

/// Display width of a string in terminal cells: ASCII and the ellipsis are one
/// column wide, everything else (CJK, full-width punctuation) is two.
fn display_width(s: &str) -> usize {
    s.chars().map(|c| if c.is_ascii() || c == '…' { 1 } else { 2 }).sum()
}

/// Truncate `s` to at most `width` display cells, appending an ellipsis when
/// anything is cut off.
fn truncate(s: &str, width: usize) -> String {
    if display_width(s) <= width {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0usize;
    // Leave one cell for the trailing ellipsis.
    let limit = width.saturating_sub(1);
    for c in s.chars() {
        let cw = if c.is_ascii() { 1 } else { 2 };
        if used + cw > limit {
            break;
        }
        out.push(c);
        used += cw;
    }
    out.push('…');
    out
}

/// Pad `s` with trailing spaces to the given display width.
fn pad(s: &str, width: usize) -> String {
    let mut out = s.to_string();
    for _ in display_width(s)..width {
        out.push(' ');
    }
    out
}

/// Shrink the widest columns (down to [`MIN_COL_WIDTH`]) until the table fits
/// within `max_width` display cells.
fn fit_widths(widths: &mut [usize; 3], max_width: usize) {
    loop {
        let total = widths.iter().sum::<usize>() + 10; // 4 bars + 6 spaces
        if total <= max_width {
            break;
        }
        let widest = (0..3)
            .filter(|&i| widths[i] > MIN_COL_WIDTH)
            .max_by_key(|&i| widths[i]);
        match widest {
            Some(i) => widths[i] -= 1,
            None => break, // every column is already at its minimum
        }
    }
}

/// The width of the terminal the table will be written to, when stdout is a
/// terminal. Returns `None` when stdout is redirected (no width constraint).
fn terminal_width() -> Option<usize> {
    terminal_size::terminal_size().map(|(w, _)| w.0 as usize)
}

/// Render the records as a Unicode box-drawing table, one row per record. When
/// `max_width` is given, the columns are narrowed (and their contents
/// truncated) so the table fits within that many terminal cells.
fn render_table(records: &[DnsRecord], l10n: &L10n, max_width: Option<usize>) -> String {
    let (host_h, target_h, kind_h) = l10n.dns_table_header();
    let mut rows: Vec<[String; 3]> = Vec::with_capacity(1 + records.len());
    rows.push([
        host_h.to_string(),
        target_h.to_string(),
        kind_h.to_string(),
    ]);
    for rec in records {
        rows.push([
            rec.name.clone(),
            rec.data.clone(),
            l10n.dns_record_type(&type_name(rec.rtype)),
        ]);
    }

    let mut widths = [0usize; 3];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(display_width(cell));
        }
    }
    if let Some(max) = max_width {
        fit_widths(&mut widths, max);
    }

    // A horizontal border line between the given corner/joiner characters,
    // each column spanned by `width + 2` dashes (content plus one space on
    // each side).
    let border = |left: char, mid: char, right: char| -> String {
        let mut s = String::from(left);
        for (i, w) in widths.iter().enumerate() {
            if i > 0 {
                s.push(mid);
            }
            for _ in 0..(w + 2) {
                s.push('─');
            }
        }
        s.push(right);
        s.push('\n');
        s
    };

    let mut out = border('┌', '┬', '┐');
    for (ri, row) in rows.iter().enumerate() {
        out.push('│');
        for (i, cell) in row.iter().enumerate() {
            out.push(' ');
            out.push_str(&pad(&truncate(cell, widths[i]), widths[i]));
            out.push(' ');
            out.push('│');
        }
        out.push('\n');
        if ri + 1 < rows.len() {
            out.push_str(&border('├', '┼', '┤'));
        }
    }
    out.push_str(&border('└', '┴', '┘'));
    out
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
    fn decodes_names_with_and_without_compression() {
        // "example.com" at offset 0, "www." + pointer-to-0 at offset 13.
        let msg = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            3, b'w', b'w', b'w', 0xc0, 0x00,
        ];
        assert_eq!(decode_name(&msg, 0), Some(("example.com".to_string(), 13)));
        assert_eq!(decode_name(&msg, 13), Some(("www.example.com".to_string(), 19)));
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
        assert_eq!(
            ans.records,
            vec![DnsRecord {
                name: "example.com".to_string(),
                rtype: TYPE_A,
                data: "93.184.216.34".to_string(),
            }]
        );
    }

    #[test]
    fn parses_nxdomain() {
        let mut msg = vec![0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        msg.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01]);
        let ans = parse_response(&msg).expect("valid response");
        assert_eq!(ans.rcode, 3);
        assert!(ans.records.is_empty());
    }

    #[test]
    fn decodes_mx_rdata() {
        // Preference 10, then the name "mail.example.com".
        let msg = [
            0x00, 0x0a,
            4, b'm', b'a', b'i', b'l',
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
        ];
        let data = decode_rdata(&msg, TYPE_MX, 0, msg.len()).expect("valid MX");
        assert_eq!(data, "10 mail.example.com");
    }

    #[test]
    fn decodes_txt_rdata() {
        // Two character-strings: "hello" and " world".
        let msg = [5, b'h', b'e', b'l', b'l', b'o', 6, b' ', b'w', b'o', b'r', b'l', b'd'];
        let data = decode_rdata(&msg, TYPE_TXT, 0, msg.len()).expect("valid TXT");
        assert_eq!(data, "\"hello world\"");
    }

    #[test]
    fn maps_record_type_names() {
        assert_eq!(type_name(TYPE_A), "A");
        assert_eq!(type_name(TYPE_AAAA), "AAAA");
        assert_eq!(type_name(TYPE_MX), "MX");
        assert_eq!(type_name(9999), "TYPE9999");
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

    #[test]
    fn display_width_counts_cjk_as_two() {
        assert_eq!(display_width("baidu.com"), 9);
        assert_eq!(display_width("主机域名"), 8);
        assert_eq!(display_width("A 类型"), 6);
        assert_eq!(display_width("AAAA 类型"), 9);
    }

    #[test]
    fn renders_box_table() {
        let records = vec![
            DnsRecord { name: "baidu.com".to_string(), rtype: TYPE_A, data: "110.242.74.102".to_string() },
            DnsRecord { name: "baidu.com".to_string(), rtype: TYPE_AAAA, data: "::1".to_string() },
        ];
        let zh = crate::i18n::L10n::new(crate::i18n::Lang::Zh);
        let table = render_table(&records, &zh, None);
        assert!(table.starts_with('┌'));
        assert!(table.trim_end().ends_with('┘'));
        assert!(table.contains("主机域名"));
        assert!(table.contains("主机目标"));
        assert!(table.contains("记录类型"));
        assert!(table.contains("baidu.com"));
        assert!(table.contains("110.242.74.102"));
        assert!(table.contains("::1"));
        assert!(table.contains("A 类型"));
        assert!(table.contains("AAAA 类型"));
        // Every body row is framed by exactly four vertical bars.
        for line in table.lines() {
            if line.starts_with('│') {
                assert_eq!(line.matches('│').count(), 4);
            }
        }

        let en = crate::i18n::L10n::new(crate::i18n::Lang::En);
        let table = render_table(&records, &en, None);
        assert!(table.contains("Hostname"));
        assert!(table.contains("Target"));
        assert!(table.contains("Record type"));
        assert!(table.contains("A record"));
        assert!(table.contains("AAAA record"));
    }

    #[test]
    fn truncates_with_ellipsis() {
        assert_eq!(truncate("hello world", 20), "hello world");
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("主机域名", 6), "主机…");
        assert_eq!(truncate("baidu.com", 9), "baidu.com");
    }

    #[test]
    fn fit_widths_never_exceeds_limit() {
        let mut w = [30, 20, 10];
        fit_widths(&mut w, 40);
        assert!(w.iter().sum::<usize>() + 10 <= 40);
        assert!(w.iter().all(|&x| x >= MIN_COL_WIDTH));
    }

    #[test]
    fn table_truncates_to_fit_width() {
        let long = "a very long text record value that would overflow the terminal";
        let records = vec![DnsRecord {
            name: "example.com".to_string(),
            rtype: TYPE_TXT,
            data: long.to_string(),
        }];
        let l10n = crate::i18n::L10n::new(crate::i18n::Lang::En);
        // No width limit: the full value is shown untruncated.
        let full = render_table(&records, &l10n, None);
        assert!(full.contains(long));
        assert!(!full.contains('…'));
        // A narrow limit truncates the long cell with an ellipsis.
        let fitted = render_table(&records, &l10n, Some(30));
        assert!(fitted.contains('…'));
        assert!(!fitted.contains("overflow the terminal"));
        // Every line stays within the requested width (box chars are 1 wide).
        let line_width = |line: &str| {
            line.chars()
                .map(|c| match c {
                    '─' | '│' | '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' | '…' => 1,
                    c if c.is_ascii() => 1,
                    _ => 2,
                })
                .sum::<usize>()
        };
        for line in fitted.lines() {
            assert!(line_width(line) <= 30, "line too wide: {line}");
        }
    }
}
