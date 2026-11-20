//! Minimal blocking HTTP/1.1 client for Portal drivers: plain `http://`,
//! `Connection: close`, no redirects, chunked bodies decoded.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use gswifi_core::{HttpRequest, HttpResponse};

const TIMEOUT: Duration = Duration::from_secs(10);
/// Portal pages are small; refuse anything larger.
const MAX_RESPONSE: usize = 1 << 20;

/// Host, port and path of an `http://` URL.
fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        if url.starts_with("https://") {
            format!("不支持 HTTPS: {}", url)
        } else {
            format!("不是 http:// 地址: {}", url)
        }
    })?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if authority.is_empty() {
        return Err(format!("地址里没有主机: {}", url));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, tail) = v6.split_once(']').ok_or_else(|| format!("IPv6 地址格式错误: {}", url))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("端口错误: {}", url))?,
            None => 80,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| format!("端口错误: {}", url))?),
            None => (authority.to_string(), 80),
        }
    };
    Ok((host, port, path))
}

fn request_bytes(req: &HttpRequest, host: &str, port: u16, path: &str) -> Vec<u8> {
    let host_header = match (host.contains(':'), port) {
        (true, 80) => format!("[{}]", host),
        (true, p) => format!("[{}]:{}", host, p),
        (false, 80) => host.to_string(),
        (false, p) => format!("{}:{}", host, p),
    };
    let mut head = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", req.method, path, host_header);
    for (k, v) in &req.headers {
        if ["host", "connection", "content-length"].iter().any(|h| k.eq_ignore_ascii_case(h)) {
            continue;
        }
        // Header injection guard.
        if k.contains(['\r', '\n', ':']) || v.contains(['\r', '\n']) {
            continue;
        }
        head.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !req.body.is_empty() || req.method.eq_ignore_ascii_case("POST") {
        head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&req.body);
    out
}

/// Parses a complete response read until the server closed.
pub(crate) fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("HTTP 响应头不完整")?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| "HTTP 响应头不是文本")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!("不是 HTTP/1.x 响应: {:?}", status_line));
    }
    let status: u16 =
        parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| format!("状态行错误: {:?}", status_line))?;
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    let mut body = raw[end + 4..].to_vec();
    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
    if header("Transfer-Encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        body = dechunk(&body)?;
    } else if let Some(n) = header("Content-Length").and_then(|v| v.parse::<usize>().ok()) {
        body.truncate(n);
    }
    Ok(HttpResponse { status, headers, body })
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n").ok_or("chunked 数据被截断")?;
        let size_text = std::str::from_utf8(&data[..line_end]).map_err(|_| "chunk 长度不是文本")?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| format!("chunk 长度错误: {:?}", size_text))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size {
            return Err("chunk 数据被截断".into());
        }
        out.extend_from_slice(&data[..size]);
        data = data.get(size + 2..).unwrap_or_default();
    }
}

/// Performs the request; any failure (DNS, connect, timeout, malformed
/// response) is an `Err` the driver sees in `on_http`.
pub fn fetch(req: &HttpRequest) -> Result<HttpResponse, String> {
    let (host, port, path) = split_url(&req.url)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("无法解析 {}: {}", host, e))?
        .next()
        .ok_or_else(|| format!("无法解析 {}", host))?;
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("无法连接 {}: {}", addr, e))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    stream.write_all(&request_bytes(req, &host, port, &path)).map_err(|e| format!("发送 HTTP 请求失败: {}", e))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_RESPONSE {
                    return Err("HTTP 响应过大".into());
                }
            }
            Err(e) => return Err(format!("读取 HTTP 响应失败: {}", e)),
        }
    }
    parse_response(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn urls() {
        assert_eq!(split_url("http://1.2.3.4/a?b=c").unwrap(), ("1.2.3.4".into(), 80, "/a?b=c".into()));
        assert_eq!(split_url("http://h:8080").unwrap(), ("h".into(), 8080, "/".into()));
        assert_eq!(split_url("http://h?x=1").unwrap(), ("h".into(), 80, "/?x=1".into()));
        assert_eq!(split_url("http://[::1]:81/p").unwrap(), ("::1".into(), 81, "/p".into()));
        assert!(split_url("https://h/").unwrap_err().contains("HTTPS"));
        assert!(split_url("http:///x").is_err());
        assert!(split_url("http://h:port/").is_err());
    }

    #[test]
    fn request_layout_and_injection_guard() {
        let req = HttpRequest {
            method: "POST".into(),
            url: String::new(),
            headers: vec![
                ("ClientVersion".into(), "Mdsc".into()),
                ("Host".into(), "evil".into()),
                ("X".into(), "a\r\nInjected: 1".into()),
            ],
            body: b"a=1".to_vec(),
        };
        let text = String::from_utf8(request_bytes(&req, "10.0.0.1", 8080, "/login")).unwrap();
        assert_eq!(
            text,
            "POST /login HTTP/1.1\r\nHost: 10.0.0.1:8080\r\nConnection: close\r\nClientVersion: Mdsc\r\nContent-Length: 3\r\n\r\na=1"
        );
    }

    #[test]
    fn responses() {
        let r = parse_response(b"HTTP/1.1 302 Found\r\nLocation: http://x/?a=1\r\nContent-Length: 2\r\n\r\nokEXTRA")
            .unwrap();
        assert_eq!((r.status, r.header("location"), &r.body[..]), (302, Some("http://x/?a=1"), &b"ok"[..]));
        let r = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.body, b"abcde");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(parse_response(b"SSH-2.0\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc").is_err());
    }

    #[test]
    fn loopback_fetch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap();
            req
        });
        let req = HttpRequest {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{}/x?y=1", port),
            headers: vec![],
            body: vec![],
        };
        let resp = fetch(&req).unwrap();
        assert_eq!((resp.status, &resp.body[..]), (200, &b"hello"[..]));
        assert!(server.join().unwrap().starts_with("GET /x?y=1 HTTP/1.1\r\nHost: 127.0.0.1:"));
    }
}
