//! Client-to-server half of the transparent proxy: passes a TCP byte stream
//! through and, while it carries HTTP/1.x requests, replaces the value of
//! every `User-Agent` header and drops configured headers.
//!
//! Only request heads are rewritten. Request bodies are copied unchanged; the
//! parser follows `Content-Length` and chunked framing just far enough to know
//! where the next request head starts. Anything that is not recognisably
//! HTTP/1.x (TLS, SSH, HTTP/2, a malformed head, an upgraded connection) turns
//! the rest of the connection into a plain byte copy, so the proxy never
//! breaks a protocol it does not understand.

/// Longest request head that is buffered for rewriting. Longer heads are
/// passed through untouched.
const MAX_HEAD: usize = 64 * 1024;
/// Longest chunk-size or trailer line.
const MAX_LINE: usize = 4 * 1024;

const METHODS: &[&[u8]] = &[
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ",
    b"CONNECT ",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// Reading a chunk-size line.
    Size,
    /// Copying chunk data, then its CRLF.
    Data(u64),
    /// Reading the CRLF after chunk data.
    DataEnd,
    /// Reading trailer lines up to the empty line.
    Trailer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Start of the connection, protocol not known yet.
    Detect,
    /// Collecting a request head.
    Head,
    /// Copying this many more body bytes.
    Body(u64),
    Chunked(Chunk),
    /// Not (or no longer) HTTP/1.x: copy everything.
    Raw,
}

pub struct Rewriter {
    ua: Vec<u8>,
    /// Lower-case names of headers to drop.
    strip: Vec<Vec<u8>>,
    state: State,
    /// Bytes held back: a partial head, chunk-size or trailer line.
    pending: Vec<u8>,
    /// Requests whose head was parsed.
    pub requests: u64,
    /// Requests whose head was changed.
    pub rewritten: u64,
}

/// What detection makes of the first bytes of a connection.
#[derive(Debug, PartialEq, Eq)]
enum Detect {
    Http,
    Other,
    NeedMore,
}

fn detect(buf: &[u8]) -> Detect {
    let mut maybe = false;
    for m in METHODS {
        if buf.len() >= m.len() {
            if buf.starts_with(m) {
                return Detect::Http;
            }
        } else if m.starts_with(buf) {
            maybe = true;
        }
    }
    if maybe {
        Detect::NeedMore
    } else {
        Detect::Other
    }
}

/// Length of the request head at the start of `buf` (up to and including the
/// empty line), if it is complete. Bare LF line ends are accepted, as most
/// servers do.
fn head_len(buf: &[u8]) -> Option<usize> {
    let mut start = 0;
    while let Some(i) = buf[start..].iter().position(|&b| b == b'\n') {
        let end = start + i;
        let line = &buf[start..end];
        if line.is_empty() || line == b"\r" {
            return Some(end + 1);
        }
        start = end + 1;
    }
    None
}

/// Splits `buf` into lines, each with its line end.
fn lines(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    buf.split_inclusive(|&b| b == b'\n')
}

/// The line without its line end.
fn content(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// The line end of `line` ("\r\n", "\n" or "").
fn line_end(line: &[u8]) -> &[u8] {
    &line[content(line).len()..]
}

fn trim(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(v.len());
    let end = v.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |i| i + 1);
    &v[start..end]
}

fn parse_u64(v: &[u8], radix: u32) -> Option<u64> {
    if v.is_empty() || v.len() > 16 {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(v).ok()?, radix).ok()
}

/// What follows a request head.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    Head,
    Body(u64),
    Chunked,
    Raw,
}

impl Rewriter {
    pub fn new(ua: &str, strip: &[String]) -> Self {
        Rewriter {
            ua: ua.as_bytes().to_vec(),
            strip: strip.iter().map(|s| s.trim().to_ascii_lowercase().into_bytes()).collect(),
            state: State::Detect,
            pending: Vec::new(),
            requests: 0,
            rewritten: 0,
        }
    }

    /// True while the first bytes of the connection are held back to tell
    /// whether it is HTTP. The caller gives up after a short time with
    /// [`Rewriter::give_up`], for protocols whose client sends a few bytes and
    /// then waits.
    pub fn detecting(&self) -> bool {
        self.state == State::Detect && !self.pending.is_empty()
    }

    /// Stops rewriting and emits whatever is held back.
    pub fn give_up(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.pending);
        self.state = State::Raw;
    }

    /// Feeds bytes read from the client; appends the bytes to send to the
    /// server to `out`. Bytes may be held back until more input arrives.
    pub fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() {
            match self.state {
                State::Raw => {
                    out.extend_from_slice(input);
                    return;
                }
                State::Body(n) => {
                    let take = (n.min(input.len() as u64)) as usize;
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    self.state = if n == take as u64 { State::Head } else { State::Body(n - take as u64) };
                }
                State::Chunked(Chunk::Data(n)) => {
                    let take = (n.min(input.len() as u64)) as usize;
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    self.state = State::Chunked(if n == take as u64 { Chunk::DataEnd } else { Chunk::Data(n - take as u64) });
                }
                State::Chunked(c) => {
                    // Line-oriented: size line, the CRLF after data, trailers.
                    let Some(i) = input.iter().position(|&b| b == b'\n') else {
                        self.pending.extend_from_slice(input);
                        if self.pending.len() > MAX_LINE {
                            self.give_up(out);
                        }
                        return;
                    };
                    self.pending.extend_from_slice(&input[..=i]);
                    input = &input[i + 1..];
                    let line = std::mem::take(&mut self.pending);
                    out.extend_from_slice(&line);
                    let text = content(&line);
                    self.state = match c {
                        Chunk::Size => {
                            let size = text.split(|&b| b == b';').next().map(trim).unwrap_or_default();
                            match parse_u64(size, 16) {
                                Some(0) => State::Chunked(Chunk::Trailer),
                                Some(n) => State::Chunked(Chunk::Data(n)),
                                None => State::Raw,
                            }
                        }
                        Chunk::DataEnd if text.is_empty() => State::Chunked(Chunk::Size),
                        Chunk::DataEnd => State::Raw,
                        Chunk::Trailer if text.is_empty() => State::Head,
                        Chunk::Trailer => State::Chunked(Chunk::Trailer),
                        Chunk::Data(_) => unreachable!(),
                    };
                }
                State::Detect | State::Head => {
                    // Empty lines between requests (some clients send a CRLF
                    // after a body) are passed on.
                    if self.state == State::Head && self.pending.is_empty() {
                        let n = input.iter().take_while(|&&b| b == b'\r' || b == b'\n').count();
                        out.extend_from_slice(&input[..n]);
                        input = &input[n..];
                        if input.is_empty() {
                            return;
                        }
                    }

                    let before = self.pending.len();
                    self.pending.extend_from_slice(input);

                    if self.state == State::Detect {
                        match detect(&self.pending) {
                            Detect::NeedMore => return,
                            Detect::Other => {
                                self.give_up(out);
                                return;
                            }
                            Detect::Http => self.state = State::Head,
                        }
                    }

                    let Some(len) = head_len(&self.pending) else {
                        if self.pending.len() > MAX_HEAD {
                            self.give_up(out);
                        }
                        return;
                    };
                    if len > MAX_HEAD {
                        self.give_up(out);
                        return;
                    }

                    // The rest of the input comes after this head.
                    let used = len - before;
                    input = &input[used..];
                    let mut head = std::mem::take(&mut self.pending);
                    head.truncate(len);

                    match self.rewrite_head(&head, out) {
                        Next::Head => self.state = State::Head,
                        Next::Body(0) => self.state = State::Head,
                        Next::Body(n) => self.state = State::Body(n),
                        Next::Chunked => self.state = State::Chunked(Chunk::Size),
                        Next::Raw => self.state = State::Raw,
                    }
                }
            }
        }
    }

    /// Writes the rewritten head to `out` and tells what follows it.
    fn rewrite_head(&mut self, head: &[u8], out: &mut Vec<u8>) -> Next {
        let mut it = lines(head);
        let request_line = it.next().unwrap_or_default();

        // METHOD SP target SP HTTP/x.y
        let mut parts = content(request_line).split(|&b| b == b' ');
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        if target.is_empty() || !version.starts_with(b"HTTP/1.") || parts.next().is_some() {
            out.extend_from_slice(head);
            return Next::Raw;
        }

        self.requests += 1;
        let start = out.len();
        out.extend_from_slice(request_line);

        let mut changed = false;
        let mut content_length: Option<u64> = None;
        let mut bad_length = false;
        let mut transfer_encoding: Option<Vec<u8>> = None;
        let mut upgrade = method == b"CONNECT";
        // Whether continuation lines (obsolete line folding) of the current
        // header are dropped along with it.
        let mut skipping = false;

        for line in it {
            let text = content(line);
            if text.is_empty() {
                out.extend_from_slice(line);
                break;
            }
            if text[0] == b' ' || text[0] == b'\t' {
                if !skipping {
                    out.extend_from_slice(line);
                }
                continue;
            }
            skipping = false;

            let Some(colon) = text.iter().position(|&b| b == b':') else {
                // Not a header line: leave the request alone from here on.
                out.truncate(start);
                out.extend_from_slice(head);
                return Next::Raw;
            };
            let name = &text[..colon];
            let value = trim(&text[colon + 1..]);
            let lower = name.to_ascii_lowercase();

            if self.strip.contains(&lower) {
                skipping = true;
                changed = true;
                continue;
            }

            match lower.as_slice() {
                b"user-agent" if !self.ua.is_empty() => {
                    skipping = true;
                    if value != self.ua.as_slice() {
                        changed = true;
                    }
                    out.extend_from_slice(name);
                    out.extend_from_slice(b": ");
                    out.extend_from_slice(&self.ua);
                    out.extend_from_slice(line_end(line));
                    continue;
                }
                b"content-length" => match parse_u64(value, 10) {
                    Some(n) if content_length.is_none() || content_length == Some(n) => content_length = Some(n),
                    _ => bad_length = true,
                },
                b"transfer-encoding" => {
                    let mut te = transfer_encoding.take().unwrap_or_default();
                    if !te.is_empty() {
                        te.push(b',');
                    }
                    te.extend_from_slice(value);
                    transfer_encoding = Some(te);
                }
                b"upgrade" => upgrade = true,
                _ => {}
            }
            out.extend_from_slice(line);
        }

        if changed {
            self.rewritten += 1;
        }

        if upgrade {
            // CONNECT, or a protocol switch (WebSocket, h2c): what follows is
            // not HTTP/1.x any more once the server agrees.
            return Next::Raw;
        }
        if let Some(te) = transfer_encoding {
            // In a request, a transfer coding other than a final "chunked"
            // makes the length unknowable (RFC 9112 6.3); the server answers
            // 400 and closes, so just copy.
            let last = te.rsplit(|&b| b == b',').next().map(trim).unwrap_or_default();
            return if last.eq_ignore_ascii_case(b"chunked") { Next::Chunked } else { Next::Raw };
        }
        if bad_length {
            return Next::Raw;
        }
        match content_length {
            Some(n) => Next::Body(n),
            None => Next::Head,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UA: &str = "Mozilla/5.0 (Test)";

    fn run(rw: &mut Rewriter, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            rw.feed(c, &mut out);
        }
        out
    }

    fn all(input: &[u8]) -> (Vec<u8>, Rewriter) {
        let mut rw = Rewriter::new(UA, &["X-Requested-With".to_string()]);
        let out = run(&mut rw, &[input]);
        (out, rw)
    }

    /// Feeds the input one byte at a time.
    fn bytewise(input: &[u8]) -> Vec<u8> {
        let mut rw = Rewriter::new(UA, &["X-Requested-With".to_string()]);
        let chunks: Vec<&[u8]> = input.chunks(1).collect();
        run(&mut rw, &chunks)
    }

    #[test]
    fn replaces_user_agent() {
        let req = b"GET /a HTTP/1.1\r\nHost: example.com\r\nuser-agent: curl/8.0\r\nAccept: */*\r\n\r\n";
        let want = b"GET /a HTTP/1.1\r\nHost: example.com\r\nuser-agent: Mozilla/5.0 (Test)\r\nAccept: */*\r\n\r\n";
        let (out, rw) = all(req);
        assert_eq!(out, want);
        assert_eq!((rw.requests, rw.rewritten), (1, 1));
        assert_eq!(bytewise(req), want);
    }

    #[test]
    fn strips_headers_with_continuation_lines() {
        let req = b"GET / HTTP/1.1\r\nX-Requested-With: com.example.app\r\n  folded\r\nHost: h\r\n\r\n";
        let (out, _) = all(req);
        assert_eq!(out, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    #[test]
    fn keep_alive_with_bodies() {
        let input = b"POST /p HTTP/1.1\r\nUser-Agent: a\r\nContent-Length: 31\r\n\r\nGET / HTTP/1.1\r\nUser-Agent: b\r\nGET /2 HTTP/1.1\r\nUser-Agent: c\r\n\r\n";
        let want = b"POST /p HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Test)\r\nContent-Length: 31\r\n\r\nGET / HTTP/1.1\r\nUser-Agent: b\r\nGET /2 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Test)\r\n\r\n";
        let (out, rw) = all(input);
        // The body, which looks like a request, is copied as is.
        assert_eq!(out, want);
        assert_eq!(rw.requests, 2);
        assert_eq!(bytewise(input), want);
    }

    #[test]
    fn chunked_body() {
        let input = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\nUser-Agent: x\r\n\r\n\
5;ext=1\r\nUser-\r\n3\r\nAge\r\n0\r\nTrailer: v\r\n\r\n\
GET / HTTP/1.1\r\nUser-Agent: y\r\n\r\n";
        let want = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\nUser-Agent: Mozilla/5.0 (Test)\r\n\r\n\
5;ext=1\r\nUser-\r\n3\r\nAge\r\n0\r\nTrailer: v\r\n\r\n\
GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Test)\r\n\r\n";
        let (out, rw) = all(input);
        assert_eq!(out, want);
        assert_eq!(rw.requests, 2);
        assert_eq!(bytewise(input), want);
    }

    #[test]
    fn non_http_is_copied() {
        let tls = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfcUser-Agent: x\r\n\r\n";
        let (out, rw) = all(tls);
        assert_eq!(out, tls);
        assert_eq!(rw.requests, 0);
        assert_eq!(bytewise(tls), tls);

        let h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert_eq!(all(h2).0, h2);
    }

    #[test]
    fn partial_method_waits_then_gives_up() {
        let mut rw = Rewriter::new(UA, &[]);
        let mut out = Vec::new();
        rw.feed(b"PO", &mut out);
        assert!(out.is_empty());
        assert!(rw.detecting());
        rw.give_up(&mut out);
        assert_eq!(out, b"PO");
        rw.feed(b"ST / HTTP/1.1\r\nUser-Agent: z\r\n\r\n", &mut out);
        assert_eq!(out, b"POST / HTTP/1.1\r\nUser-Agent: z\r\n\r\n");
    }

    #[test]
    fn upgrade_and_connect_switch_to_copy() {
        let ws = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nUser-Agent: a\r\n\r\nGET / HTTP/1.1\r\nUser-Agent: b\r\n\r\n";
        let want = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nUser-Agent: Mozilla/5.0 (Test)\r\n\r\nGET / HTTP/1.1\r\nUser-Agent: b\r\n\r\n";
        assert_eq!(all(ws).0, want);

        let connect = b"CONNECT h:443 HTTP/1.1\r\nUser-Agent: a\r\n\r\n\x16\x03\x01";
        let want = b"CONNECT h:443 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Test)\r\n\r\n\x16\x03\x01";
        assert_eq!(all(connect).0, want);
    }

    #[test]
    fn bare_lf_and_leading_empty_lines() {
        let input = b"GET / HTTP/1.0\nUser-Agent: a\n\n\r\nGET /b HTTP/1.0\nUser-Agent: a\n\n";
        let want = b"GET / HTTP/1.0\nUser-Agent: Mozilla/5.0 (Test)\n\n\r\nGET /b HTTP/1.0\nUser-Agent: Mozilla/5.0 (Test)\n\n";
        assert_eq!(all(input).0, want);
        assert_eq!(bytewise(input), want);
    }

    #[test]
    fn malformed_heads_are_left_alone() {
        // HTTP/0.9 style, no version.
        let v09 = b"GET /\r\n\r\n";
        assert_eq!(all(v09).0, v09);
        // A line without a colon.
        let bad = b"GET / HTTP/1.1\r\nUser-Agent: a\r\nnonsense\r\n\r\nrest";
        assert_eq!(all(bad).0, bad);
        // Conflicting lengths.
        let cl = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\nUser-Agent: a\r\n\r\nGET / HTTP/1.1\r\nUser-Agent: a\r\n\r\n";
        let (out, _) = all(cl);
        assert!(out.ends_with(b"GET / HTTP/1.1\r\nUser-Agent: a\r\n\r\n"));
    }

    #[test]
    fn oversized_head_is_copied() {
        let mut req = b"GET / HTTP/1.1\r\nUser-Agent: a\r\nX: ".to_vec();
        req.extend(std::iter::repeat(b'a').take(MAX_HEAD + 10));
        req.extend_from_slice(b"\r\n\r\n");
        let (out, rw) = all(&req);
        assert_eq!(out, req);
        assert_eq!(rw.requests, 0);
    }

    #[test]
    fn missing_user_agent_is_not_added() {
        let req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let (out, rw) = all(req);
        assert_eq!(out, req);
        assert_eq!((rw.requests, rw.rewritten), (1, 0));
    }
}
