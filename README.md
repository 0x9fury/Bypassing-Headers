# Technical Taxonomy and Architectural Analysis of HTTP Forwarding Headers, Access Control Enforcement, and Proxy Interception

## Table of Contents

- [Architectural Foundations of Distributed Request Processing](#architectural-foundations-of-distributed-request-processing)
- [Master Taxonomy of HTTP Forwarding and Routing Headers](#master-taxonomy-of-http-forwarding-and-routing-headers)
- [Header Payload Encoded Formats and Representation Vectors](#header-payload-encoded-formats-and-representation-vectors)
  - [IP Address Encoded Variations](#ip-address-encoded-variations)
  - [Host, URI, and Routing Representations](#host-uri-and-routing-representations)
- [Target Vulnerability Mechanics and Multi-Vector Exploitation](#target-vulnerability-mechanics-and-multi-vector-exploitation)
  - [Access Control and 403 Forbidden Bypasses](#access-control-and-403-forbidden-bypasses)
  - [Server-Side Request Forgery and Host Injection](#server-side-request-forgery-and-host-injection)
  - [Web Cache Poisoning and Cache Deception](#web-cache-poisoning-and-cache-deception)
  - [Rate Limit Bypasses and Memory Exhaustion](#rate-limit-bypasses-and-memory-exhaustion)
  - [HTTP Method Overriding and Verb Tampering](#http-method-overriding-and-verb-tampering)
- [Burp Suite Instrumentation, Repeater Workflows, and Interception Options](#burp-suite-instrumentation-repeater-workflows-and-interception-options)
  - [Burp Repeater Diagnostics Configuration](#burp-repeater-diagnostics-configuration)
  - [Automated Header Injection via Match and Replace](#automated-header-injection-via-match-and-replace)
  - [Out-of-Band Interactions with Burp Collaborator](#out-of-band-interactions-with-burp-collaborator)
  - [Burp Suite Configuration Quick Reference](#burp-suite-configuration-quick-reference)
- [Web Server, Reverse Proxy, CDN, and Framework Behavior Matrix](#web-server-reverse-proxy-cdn-and-framework-behavior-matrix)
  - [Web Servers and Ingress Proxies](#web-servers-and-ingress-proxies)
  - [Application Frameworks and Runtimes](#application-frameworks-and-runtimes)
  - [Server / Framework Security Posture Matrix](#server--framework-security-posture-matrix)
- [Defensive Engineering, Zero-Trust Hardening, and Remediation](#defensive-engineering-zero-trust-hardening-and-remediation)
  - [Edge Boundary Sanitization](#edge-boundary-sanitization)
  - [Strict Network Proxy Allowlisting](#strict-network-proxy-allowlisting)
  - [Secure IP Parsing Algorithms](#secure-ip-parsing-algorithms)
  - [Disabling Framework URI Overrides](#disabling-framework-uri-overrides)
- [Technical Conclusions](#technical-conclusions)
- [References](#references)

---

## Architectural Foundations of Distributed Request Processing

Modern web application architectures rely extensively on multi-tiered, distributed infrastructure topologies. Client requests originating from public networks rarely establish direct TCP connections with back-end application runtime environments. Instead, ingress traffic traverses multiple intermediary layers, including edge Content Delivery Networks (CDNs), Web Application Firewalls (WAFs), reverse proxies, load balancers, and internal API gateways. While these intermediary nodes optimize global content delivery, absorb distributed denial-of-service (DDoS) attacks, and enforce edge authorization policies, they fundamentally alter the lower-layer attributes of the HTTP transaction. Specifically, when a proxy terminates an incoming TCP connection and establishes a new upstream connection to a back-end origin server, the original client network parameters—such as the source IPv4/IPv6 address, source port, requested host header, and TLS protocol scheme—are lost at the socket layer.

To preserve transactional context across proxy boundaries, intermediaries inject HTTP extension headers that convey the original client metadata to downstream application layers. Historically, this context propagation developed organically through ad-hoc, vendor-specific header conventions. The most prominent de-facto standard that emerged was the `X-Forwarded-*` header suite, initially introduced by custom proxy software and subsequently adopted across the web engineering ecosystem. Because these custom headers lacked a formal specification, different proxy vendors, web servers, and framework developers implemented divergent parsing logic, header naming conventions, and trust models.

To address the interoperability and security challenges caused by non-standardized headers, the Internet Engineering Task Force (IETF) published RFC 7239, which formally established the standardized `Forwarded` HTTP header field. RFC 7239 defines a unified, parameter-based syntax capable of combining client, proxy, host, and protocol details into a single structured value chain. Despite the standardization defined in RFC 7239, legacy `X-Forwarded-*` headers and proprietary CDN headers remain deeply embedded in enterprise software stacks and cloud platform infrastructures.

A fundamental security boundary hazard arises when downstream web applications, API gateways, or access control modules trust client-influenced HTTP headers without validating the network provenance of the request. When edge proxies pass incoming HTTP requests to internal networks without stripping or sanitizing pre-existing forwarding headers, external attackers can inject forged headers. If downstream applications rely on these untrusted headers for security-critical decisions—such as restricting administrative interfaces to local loopback addresses, enforcing IP-based rate limits, or routing internal microservice requests—the application becomes vulnerable to access control bypasses, Server-Side Request Forgery (SSRF), cache poisoning, and authentication evasions.

## Master Taxonomy of HTTP Forwarding and Routing Headers

Analyzing HTTP forwarding mechanisms requires a comprehensive taxonomy of all headers used across web servers, reverse proxies, cloud edge providers, and application frameworks. These headers fall into functional classes based on whether they communicate IP attribution, host routing, protocol schemes, path overrides, proxy topologies, or custom authorization tokens.
Client Request (Injected Header) ──► Edge Proxy / WAF ──(Unsanitized)──► Backend Application ──► Security Bypass

text

| Header Category | Header Field Name | Standard / Vendor Source | Functional Specification and Operational Role |
|-----------------|-------------------|--------------------------|-----------------------------------------------|
| Standardized Context | `Forwarded` | IETF RFC 7239 | Standardized syntax encapsulating `for`, `by`, `host`, and `proto` parameters across proxy hops. |
| De-facto IP Attribution | `X-Forwarded-For` | Industry Standard | Comma-separated list tracking the client IP and intermediate proxy addresses. |
| De-facto IP Attribution | `X-Real-IP` | Nginx / General Proxies | Single IP string representing the connecting client or immediate upstream node. |
| De-facto Routing | `X-Forwarded-Host` | Industry Standard | Preserves the original Host request header presented by the client to the edge proxy. |
| De-facto Routing | `X-Forwarded-Proto` | Industry Standard | Identifies the protocol scheme (http or https) used by the client at the edge network. |
| De-facto Routing | `X-Forwarded-Scheme` | Industry Standard | Variant of `X-Forwarded-Proto` used by legacy load balancers to indicate connection scheme. |
| De-facto Routing | `X-Forwarded-Port` | Industry Standard | Transmits the destination TCP port requested by the client at the edge proxy. |
| De-facto Topology | `X-Forwarded-By` | Industry Standard | Identifies the IP address or socket identifier of the processing proxy component. |
| De-facto Topology | `X-Forwarded-Server` | Industry Standard | Discloses the hostname or identifier of the proxy server handling the request. |
| De-facto Topology | `X-Forwarded-For-Original` | Custom Proxies | Stores the initial un-modified `X-Forwarded-For` payload prior to downstream alterations. |
| Cloud / CDN Specific | `CF-Connecting-IP` | Cloudflare | Delivers the verified client source IP address captured at Cloudflare edge nodes. |
| Cloud / CDN Specific | `True-Client-IP` | Akamai / Cloudflare Ent. | Transmits the client IP observed by Akamai or Cloudflare Enterprise edge servers. |
| Cloud / CDN Specific | `Fastly-Client-IP` | Fastly CDN | Conveys the originating public client IP address captured at Fastly edge POPs. |
| Cloud / CDN Specific | `X-Azure-ClientIP` | Azure Front Door | Captures the client IP associated with the request at the Azure edge network. |
| Cloud / CDN Specific | `X-Azure-SocketIP` | Azure Front Door | Contains the exact TCP socket IP address originating the connection to Azure. |
| Cloud / CDN Specific | `Incap-Client-IP` | Imperva / Incapsula | Passes the original client IP through Imperva Web Application Firewall tiers. |
| Cloud / CDN Specific | `X-Sucuri-ClientIP` | Sucuri WAF | Conveys the validated client IP from Sucuri firewall nodes to origin targets. |
| Cloud / CDN Specific | `Ali-CDN-Real-IP` | Alibaba Cloud CDN | Transmits the verified client IP address across Alibaba Cloud CDN infrastructure. |
| Alternative IP Attribution | `Client-IP` / `X-Client-IP` | Legacy Proxies | Non-standard header historically populated by corporate proxies and enterprise firewalls. |
| Alternative IP Attribution | `X-Cluster-Client-IP` | Clustered Balancers | Communicates client IP addresses within clustered internal load balancing systems. |
| Alternative IP Attribution | `X-Originating-IP` | Custom Middleware | Transmits client source IPs across enterprise application gateway architectures. |
| Alternative IP Attribution | `X-True-IP` / `X-Source-IP` | Custom Firewalls | Discloses the originating client network address in specialized proxy deployments. |
| Alternative IP Attribution | `X-Remote-IP` / `X-Remote-Addr` | Application Runtimes | Represents internal socket or remote peer addresses in backend application environments. |
| Alternative IP Attribution | `X-ProxyUser-Ip` | Enterprise Proxies | Discloses authenticated user IP addresses behind internal enterprise proxy servers. |
| Alternative IP Attribution | `Proxy-Client-IP` / `WL-Proxy-Client-IP` | WebLogic / Apache | Proprietary headers used by Oracle WebLogic and Apache proxy modules for IP tracking. |
| URI & Path Overrides | `X-Original-URL` | Symfony, Spring, IIS | Overrides the requested URI path during internal framework request processing. |
| URI & Path Overrides | `X-Rewrite-URL` | IIS, Symfony | Re-writes the target URI path prior to routing within application middleware chains. |
| URI & Path Overrides | `X-Http-Destinationurl` | WebDAV / Gateways | Controls destination targets for HTTP verbs and internal application redirects. |
| URI & Path Overrides | `Destination` | RFC 2518 (WebDAV) | Dictates target resource URIs for WebDAV copy, move, and routing operations. |
| Host / Gateway Overrides | `X-Host` / `Proxy-Host` | Custom Gateways | Overrides the destination hostname within internal gateway and reverse proxy logic. |
| Host / Gateway Overrides | `X-Http-Host-Override` | Custom Gateways | Bypasses standard Host header evaluation in multi-tenant API gateway platforms. |
| URI Parsing Alternatives | `Request-Uri` / `Uri` / `Url` | Custom Middleware | Non-standard headers utilized by custom routers to extract request URI strings. |
| URI Parsing Alternatives | `Base-Url` / `Http-Url` | Framework Extensions | Defines base absolute URL paths for dynamic link generation and routing. |
| URI Parsing Alternatives | `Proxy-Url` / `X-Proxy-Url` | Forward Proxies | Directs forward proxy targets in chained proxy request handlers. |
| Proxy Flow Control | `Max-Forwards` | RFC 9110 / RFC 7230 | Limits the number of remaining proxy hops for TRACE and OPTIONS requests. |
| Proxy Flow Control | `Via` | RFC 9110 / RFC 7230 | Discloses proxy protocols and intermediate nodes along the request path. |
| Custom Authorization | `X-Custom-IP-Authorization` | Custom Middleware | Proprietary header field evaluated by custom code for IP-based access authorization. |

## Header Payload Encoded Formats and Representation Vectors

When web application firewalls (WAFs), input validation filters, or reverse proxies attempt to block malicious forwarding values, they often rely on rigid string-matching patterns (e.g., blocking literal `127.0.0.1` or `localhost` strings). However, low-level network stacks, operating system socket libraries, and programming language runtimes evaluate network representations flexibly. Exploiting these differences allows attackers to craft equivalent payloads in alternate numerical, string, or structural encodings that bypass security filters while resolving to loopback or private network spaces downstream.

### IP Address Encoded Variations

Operating system socket interfaces (such as `inet_aton` and `getaddrinfo`) accept non-standard IPv4 address representations. When an application server converts an IP string into a binary network address, alternative encodings resolve directly to `127.0.0.1` or local interfaces.

- **Shortened Dotted Formats**: Omitted octets in IPv4 dotted notation are automatically expanded by socket libraries. The input `127.1` expands to `127.0.0.1`, where the final octet fills the last position. Similarly, `127.0.0` resolves to `127.0.0.0` or `127.0.0.1` depending on OS implementation details.
- **Unassigned and Zero Address Representation**: The address `0.0.0.0` or its truncated form `0` binds to all local network interfaces in UNIX-like environments. When submitted in forwarding headers, backend servers often route these requests to local service listeners on loopback bindings.
- **Integer and Radix Variations**: IPv4 addresses can be represented as a single 32-bit integer or expressed in non-decimal bases:
  - Dotted Decimal Integer: `2130706433` represents `(127 × 2²⁴) + (0 × 2¹⁶) + (0 × 2⁸) + 1`.
  - Hexadecimal Format: `0x7f000001` converts directly to `127.0.0.1`. Dotted hexadecimal forms like `0x7f.0.0.1` are also accepted by many parsers.
  - Octal Dotted Format: Octal values require leading zeros. The string `0177.0000.0000.0001` translates to octal `177 = 127₁₀`. Continuous octal integers like `017700000001` achieve identical resolution.
- **IPv6 and Dual-Stack Representations**: IPv6 implementations support multiple loopback representations:
  - Standard Loopback: `[::1]` or fully expanded `[0:0:0:0:0:0:0:1]`.
  - Unspecified IPv6 Address: `[::]` binds locally across dual-stack sockets.
  - IPv4-Mapped IPv6 Address: `[::ffff:127.0.0.1]` allows IPv6 socket layers to target IPv4 loopback services.
- **Multi-IP Chain Injections**: In multi-proxy chains, applications that extract values from comma-separated `X-Forwarded-For` lists can be manipulated based on whether they read left-to-right or right-to-left. Submitting `127.0.0.1, 10.0.0.1` targets systems that naively select the leftmost entry. Submitting `10.0.0.1, 127.0.0.1` targets systems that evaluate the rightmost element in the chain.

### Host, URI, and Routing Representations

Headers expecting domain names, absolute URLs, or relative URI paths (`X-Forwarded-Host`, `X-Original-URL`, `Referer`) require specific payload variations to manipulate back-end routing logic.

- **Absolute URL Encodings**: Supplying scheme-prefixed targets (`http://127.0.0.1/`, `https://127.0.0.1/`) forces back-end HTTP clients or URL parsers to route requests internally.
- **Wildcard DNS Services**: Public DNS services automatically resolve wildcard subdomains to loopback addresses. Domain strings like `127.0.0.1.nip.io` or `127.0.0.1.sslip.io` bypass string-matching filters while resolving to `127.0.0.1` during back-end DNS lookup.
- **User-Info Authentication Abuse**: URL parsing ambiguities can be exploited using inline basic authentication syntax. The string `spoofed.com@127.0.0.1` causes flawed parsers to treat `spoofed.com` as the hostname while the actual network connection targets `127.0.0.1`.
- **Relative Path Traversal Mutations**: URI override headers (`X-Original-URL`, `X-Rewrite-URL`) accept relative path mutations to trick front-end proxy matching rules. Submitting paths like `/`, `/*`, `/admin`, `//admin`, `/./admin`, or `/admin/..;` exploits path normalization differences between edge proxies and back-end web frameworks.

| Payload Category | Format Type | Payload Representation | Parsing Engine Interpretation |
|------------------|-------------|------------------------|-------------------------------|
| IP Representation | Shortened Dotted IPv4 | `127.1` | OS socket expands to `127.0.0.1`. |
| IP Representation | Dotted Decimal Integer | `2130706433` | Converted to 32-bit unsigned int `127.0.0.1`. |
| IP Representation | Hexadecimal Notation | `0x7f000001` | Hexadecimal evaluation resolves to `127.0.0.1`. |
| IP Representation | Octal Dotted Format | `0177.0000.0000.0001` | Octal `177₈` converts to decimal `127₁₀`. |
| IP Representation | IPv6 Loopback Format | `[::1]` | IPv6 protocol stack targets loopback interface. |
| IP Representation | IPv4-Mapped IPv6 | `[::ffff:127.0.0.1]` | Dual-stack socket routes payload to IPv4 loopback. |
| IP Representation | Multi-IP Prepend Chain | `127.0.0.1, 10.0.0.1` | Targets naive leftmost IP extraction logic. |
| IP Representation | Multi-IP Append Chain | `10.0.0.1, 127.0.0.1` | Targets naive rightmost IP extraction logic. |
| Host / Path | Wildcard DNS Service | `127.0.0.1.nip.io` | Public DNS resolves domain directly to `127.0.0.1`. |
| Host / Path | User-Info Parsing Abuse | `spoofed.com@127.0.0.1` | Parser ambiguity isolates `127.0.0.1` destination. |
| Host / Path | Path Normalization Matrix | `/./admin` or `/admin/..;` | Bypasses WAF regex; backend normalizes path. |
| Port / Protocol | Port Injection | `8080` / `9000` / `5000` | Redirects request handling to internal management ports. |
| Port / Protocol | Protocol Scheme Override | `http` / `https` / `ws` | Triggers TLS offloading bypasses or WS upgrades. |

## Target Vulnerability Mechanics and Multi-Vector Exploitation

Manipulating HTTP forwarding, routing, and attribution headers allows security researchers to evaluate systems for several vulnerability classes. These vulnerabilities stem from structural design flaws in how multi-tiered systems process request metadata.

### Access Control and 403 Forbidden Bypasses

Access control mechanisms frequently rely on network location constraints, such as restricting administrative interfaces (`/admin`, `/management`) to local loopback IPs or internal subnets. If an application reads client network location from untrusted headers like `X-Forwarded-For`, `X-Real-IP`, or `X-Custom-IP-Authorization`, an attacker can bypass authorization controls by supplying a loopback address (`127.0.0.1`).

Similarly, framework path-override vulnerabilities occur when edge proxies evaluate access control policies against the raw HTTP request line, while backend web frameworks honor URI override headers. For example, sending a request with `GET /public HTTP/1.1` and `X-Original-URL: /admin` causes an edge WAF to permit the request (since `/public` is unrestricted). However, when the request reaches back-end framework engines like Spring or Symfony, the internal routing middleware rewrites the target URI to `/admin`, granting unauthorized access to restricted controllers.

### Server-Side Request Forgery and Host Injection

Server-Side Request Forgery (SSRF) vulnerabilities occur when back-end applications construct outgoing HTTP requests using header values provided in incoming client traffic. Forwarding headers such as `X-Forwarded-Host`, `X-Proxy-Url`, `Destination`, or `X-Http-Destinationurl` are often processed by back-end microservices, web-hook engines, or PDF rendering components.

If an application constructs an internal API call using the value of `X-Forwarded-Host`, supplying an internal IP address or cloud metadata endpoint (`169.254.169.254`) forces the back-end server to issue an unintended request to internal infrastructure. This allows attackers to access internal cloud credentials, administrative microservices, or local service endpoints.

### Web Cache Poisoning and Cache Deception

Web cache poisoning occurs when caching proxies (such as Varnish, Cloudflare, or Nginx) cache HTTP responses based on incomplete cache keys. If a back-end application uses unkeyed headers (such as `X-Forwarded-Host` or `X-Forwarded-Proto`) to generate dynamic response content—such as importing JavaScript bundles or generating absolute canonical links—an attacker can manipulate those headers in an initial request.

If the reverse proxy caches the resulting response without incorporating the header into its cache key, subsequent legitimate users requesting the same URL receive the poisoned response from the cache. This can lead to persistent cross-site scripting (XSS), open redirects, or sensitive data disclosure across all users served by the cache.

### Rate Limit Bypasses and Memory Exhaustion

API gateways and web applications often enforce rate limits based on client IP addresses to protect endpoints against brute-force attacks and resource exhaustion. When rate limiters extract client IP addresses from untrusted headers like `X-Forwarded-For` or `Client-IP` without validating upstream proxy configurations, attackers can bypass these protections.

By rotating the value of `X-Forwarded-For` on every request (e.g., sequentially incrementing IP strings), each request appears to originate from a unique client IP address. This prevents rate-limiting counters from triggering. Furthermore, in rate limiters that dynamically allocate in-memory state tracking structures for each new IP address, rapidly generating requests with unique IP strings can exhaust server memory, resulting in a denial-of-service (DoS) condition.

### HTTP Method Overriding and Verb Tampering

Intermediary security controls often restrict dangerous HTTP methods (such as `PUT`, `DELETE`, or `PATCH`) on sensitive endpoints, while allowing standard `GET` and `POST` requests. However, many web frameworks support HTTP method overriding to accommodate legacy clients that cannot issue non-standard verbs directly.

By submitting an allowed `POST` request accompanied by method override headers—such as `X-HTTP-Method-Override: PUT` or `X-HTTP-Method-Override: DELETE`—an attacker can pass through edge firewall filters while triggering sensitive modification or deletion logic on back-end application servers.

## Burp Suite Instrumentation, Repeater Workflows, and Interception Options

Auditing web application infrastructure for header-based vulnerabilities requires precise HTTP proxy configuration. Security testing suites like Burp Suite provide dedicated capabilities within Burp Repeater, Proxy Interceptor, and Match & Replace engines to automate header injection, analyze response behaviors, and monitor out-of-bound requests.

### Burp Repeater Diagnostics Configuration

When manually testing endpoints in Burp Repeater, specific session settings must be configured to ensure accurate interpretation of application responses.

- **Redirection Control**: Navigate to `Repeater > Options` and set **Follow Redirections** to **Never**. Automatic redirection handling can obscure immediate `200 OK` or `302 Found` responses generated by successful access control bypasses, causing the client to follow redirects to login pages prematurely.
- **Response Body Unpacking**: Enable **Unpack gzip / deflate / brotli** in proxy settings. Unpacking compressed response bodies ensures that header-influenced content changes (such as reflected host values, internal IP leaks, or changed access control payloads) are immediately searchable in raw response views.
- **Automatic Content-Length Management**: Keep **Update Content-Length automatically** enabled in Repeater settings. When transforming HTTP request methods (e.g., switching from `GET` to `POST`) or editing request bodies during path override testing, Burp automatically recalculates the `Content-Length` header. This prevents request framing errors that could cause the back-end server to reject the request with `400 Bad Request` or `411 Length Required` errors.

### Automated Header Injection via Match and Replace

Testing large application surfaces manually can be time-consuming. Burp Proxy's Match and Replace rules allow testers to automatically inject candidate forwarding headers into all browser traffic in real time.

To configure automated injection:

1. Navigate to `Proxy > Options > Match and Replace` (or `Proxy > Match and Replace`).
2. Click **Add** to open the rule configuration window.
3. Set **Type** to `Request header`.
4. Leave the **Match** field empty. When Match is left blank for a request header rule, Burp automatically appends the string specified in the Replace field as a new header on every request passing through the proxy.
5. In the **Replace** field, enter the target header name and payload string (for example, `X-Forwarded-For: 127.0.0.1` or `X-Original-URL: /admin`).
6. Enable **Is in target scope** under Proxy Intercept options to restrict automated header injection strictly to authorized target domains, preventing accidental header leakage to third-party services.

### Out-of-Band Interactions with Burp Collaborator

Verifying headers that trigger asynchronous or out-of-band behavior (such as `X-Forwarded-Host`, `Referer`, or `Proxy-Url`) requires an external listener.

1. Open `Burp > Burp Collaborator client` and generate a unique Collaborator payload domain (e.g., `xyz.oastify.com`).
2. Inject the Collaborator URL into routing headers across target requests (e.g., `X-Forwarded-Host: xyz.oastify.com`).
3. Poll the Collaborator server for incoming interactions. Receiving an out-of-band DNS lookup or HTTP/HTTPS request confirms that the back-end application evaluated the header value and issued an external request, establishing the presence of an SSRF or unkeyed cache-poisoning vulnerability.

### Burp Suite Configuration Quick Reference

| Burp Suite Module | Configuration Path | Operational Setting Value | Security Testing Utility |
|-------------------|--------------------|----------------------------|--------------------------|
| Repeater | `Repeater > Options` | Follow Redirections: **Never** | Prevents automated redirect execution; exposes raw `200 OK` bypasses. |
| Repeater | `Repeater > Options` | Unpack gzip / deflate: **Enabled** | Decompresses HTTP response bodies for real-time header reflection analysis. |
| Repeater | `Repeater > Options` | Update Content-Length: **Enabled** | Automatically updates `Content-Length` on payload mutations. |
| Proxy Intercept | `Proxy > Options > Intercept` | Is in target scope: **Checked** | Isolates proxy interceptions strictly to authorized target scope domains. |
| Match & Replace | `Proxy > Match and Replace` | Type: **Request header** | Specifies that the replacement rule applies to outgoing client request headers. |
| Match & Replace | `Proxy > Match and Replace` | Match: **[Empty]** | Blank match field causes Burp to append the replacement header to all requests. |
| Match & Replace | `Proxy > Match and Replace` | Replace: `X-Forwarded-For: 127.0.0.1` | Appends spoofed loopback IP header to all in-scope proxy traffic. |
| Match & Replace | `Proxy > Match and Replace` | Replace: `X-Original-URL: /admin` | Automatically injects path override header to test for framework routing bypasses. |
| Collaborator | `Burp > Collaborator client` | Poll Notifications: **Manual/Auto** | Captures out-of-band DNS and HTTP requests triggered by SSRF payloads. |

## Web Server, Reverse Proxy, CDN, and Framework Behavior Matrix

The security posture of an HTTP application depends directly on the alignment between front-end reverse proxies, web servers, and back-end web frameworks. Inconsistencies between how edge infrastructure passes headers and how downstream frameworks evaluate them create operational vulnerability windows.

### Web Servers and Ingress Proxies

#### Nginx (ngx_http_realip_module)

Nginx does not alter `$remote_addr` by default unless `ngx_http_realip_module` is enabled. To extract real client IPs safely, administrators must specify explicit `set_real_ip_from` directives containing the exact IP addresses or subnets of trusted upstream proxies, combined with a `real_ip_header` directive (e.g., `real_ip_header X-Forwarded-For`). If `set_real_ip_from` is configured with a wildcard (`0.0.0.0/0`), Nginx accepts untrusted forwarding headers from any internet source, enabling trivial IP spoofing.

#### Apache HTTP Server (mod_remoteip)

Apache uses `mod_remoteip` to replace the remote connection IP with the client IP reported in configured request headers. The `RemoteIPHeader` directive sets the target header, while `RemoteIPInternalProxy` or `RemoteIPTrustedProxy` specifies trusted upstream nodes. Apache evaluates comma-delimited header lists from right to left, stopping as soon as an untrusted proxy IP is encountered. If administrators fail to define trusted proxies, `mod_remoteip` ignores internal header values or trusts unvalidated client input, creating authorization bypass risks.

#### HAProxy

HAProxy provides robust header manipulation capabilities through ACLs and buffer processing rules. By default, HAProxy passes client-supplied headers directly to back-end servers unless configured to remove them. Secure HAProxy configurations use explicit deletion rules (`http-request del-header X-Forwarded-For if ! src-trusted_proxies`) before applying `option forwardfor`, which appends the verified client socket address.

### Application Frameworks and Runtimes

#### Spring Framework (Java)

Older versions of the Spring Framework (prior to Spring 5.3) enabled options like `useSuffixPatternMatch` by default and honored URI override headers such as `X-Original-URL` and `X-Rewrite-URL` when running behind web servers. This allowed attackers to bypass URL-based security filters in front-end firewalls while accessing restricted Spring controllers downstream. Modern Spring Boot applications require explicit registration of `ForwardedHeaderFilter` to safely process proxy headers.

#### Symfony / Laravel (PHP)

Symfony's `HttpFoundation` component historically evaluated `X-Original-URL` and `X-Rewrite-URL` headers in `Request::prepareRequestUri()` to support URL rewriting on IIS servers. This created web cache poisoning and access control bypass risks (tracked in CVE-2018-14773). Modern Symfony and Laravel applications require developers to explicitly configure trusted proxy IP ranges via `setTrustedProxies()`.

#### Express.js (Node.js)

Express.js ignores `X-Forwarded-*` headers by default, returning the socket connection IP for `req.ip`. When developers enable `app.set('trust proxy', true)`, Express trusts the leftmost IP in the `X-Forwarded-For` header from any connection source. To prevent IP spoofing, `trust proxy` must be configured with a specific IP subnet range or a trusted hop count (e.g., `app.set('trust proxy', 1)`).

#### ASP.NET Core (C#)

ASP.NET Core uses `ForwardedHeadersMiddleware` to process `X-Forwarded-For` and `X-Forwarded-Proto` headers. By default, the middleware only processes headers from local loopback addresses (`127.0.0.1`, `::1`). If developers clear the `KnownProxies` and `KnownNetworks` configuration collections to resolve proxy issues, the application trusts arbitrary client headers from any internet source.

### Server / Framework Security Posture Matrix

| Server / Framework | Relevant Headers | Default Trust Model | Configuration Directives | Security Hazard Scenario |
|--------------------|------------------|----------------------|--------------------------|---------------------------|
| Nginx | `X-Real-IP`, `X-Forwarded-For` | Ignores headers unless `realip` module is configured. | `real_ip_header`, `set_real_ip_from`, `real_ip_recursive`. | Wildcard `set_real_ip_from 0.0.0.0/0` accepts untrusted spoofed headers. |
| Apache HTTP | `X-Forwarded-For`, `X-Real-IP` | Ignores headers unless `mod_remoteip` is enabled. | `RemoteIPHeader`, `RemoteIPInternalProxy`, `RemoteIPTrustedProxy`. | Missing `RemoteIPInternalProxy` definitions cause internal header bypasses. |
| HAProxy | `X-Forwarded-For` | Passes client headers through to backends by default. | `option forwardfor`, `http-request del-header`. | Forwarding untrusted client headers without `del-header` cleanup rules. |
| Spring Framework | `X-Original-URL`, `X-Rewrite-URL` | Historically honored URI override headers by default. | `ForwardedHeaderFilter`, disable `useSuffixPatternMatch`. | Discrepancies between edge WAF rules and Spring controller mappings. |
| Symfony / Laravel | `X-Original-URL`, `X-Rewrite-URL` | Evaluated URI overrides in legacy versions (CVE-2018-14773). | `Request::setTrustedProxies()` with explicit proxy IP masks. | Unvalidated URI overrides allow access control bypasses. |
| Express.js | `X-Forwarded-For`, `X-Forwarded-Host` | Ignores headers by default (`app.get('trust proxy') == false`). | `app.set('trust proxy', 'loopback, 10.0.0.0/8')`. | Setting `trust proxy: true` trusts untrusted leftmost headers. |
| ASP.NET Core | `X-Forwarded-For`, `X-Forwarded-Proto` | Restricts trusted proxies to local loopback IPs by default. | `ForwardedHeadersOptions.KnownProxies`, `KnownNetworks`. | Clearing `KnownProxies` allows global IP spoofing across endpoints. |

## Defensive Engineering, Zero-Trust Hardening, and Remediation

Eliminating header-based vulnerabilities requires a defense-in-depth architecture based on zero-trust metadata validation. Applications must never make security decisions using HTTP request headers unless those headers originate from verified, trusted infrastructure.

### Edge Boundary Sanitization

The primary defense against header manipulation is enforcing strict sanitization boundaries at edge reverse proxies, CDNs, and WAFs. Edge proxies must strip or overwrite all known forwarding, IP attribution, and path override headers from incoming client requests before routing them to internal networks.

For example, an ingress HAProxy layer should explicitly remove pre-existing `X-Forwarded-For` headers from untrusted network sources before appending the verified socket connection address:

```haproxy
acl src_trusted_proxies src -f /etc/haproxy/trusted_proxies.acl
http-request del-header X-Forwarded-For if ! src_trusted_proxies
option forwardfor
Strict Network Proxy Allowlisting
Backend web servers and application frameworks must be configured with explicit allowlists containing the exact IP addresses or CIDR blocks of trusted upstream proxies. Web servers must reject forwarding headers received from connections outside these trusted ranges.

In Nginx architectures, this is enforced by combining set_real_ip_from with real_ip_recursive on:

nginx
# Configure trusted proxy ranges (e.g., internal load balancers)
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;

# Specify the header field carrying client IP data
real_ip_header X-Forwarded-For;

# Recursively search the header list for the first untrusted IP
real_ip_recursive on;
When real_ip_recursive on is enabled, Nginx inspects the X-Forwarded-For header list from right to left, skipping trusted proxy IPs defined in set_real_ip_from and selecting the first untrusted IP as the authentic client address.

Secure IP Parsing Algorithms
Applications that process multi-valued IP headers manually must implement right-to-left parsing algorithms (such as RightmostTrustedCountStrategy). Evaluating X-Forwarded-For from left to right exposes applications to spoofing because attackers can prepend arbitrary IP strings.

A secure right-to-left parsing implementation operates as follows:

Extract the array of IP addresses from the X-Forwarded-For header list.

Traverse the IP array starting from the rightmost (most recently appended) entry.

Validate each IP against the list of trusted internal proxies.

Return the first IP address that does not belong to the trusted proxy network as the authentic client IP.

Disabling Framework URI Overrides
Backend application frameworks must be configured to ignore non-standard path override headers (X-Original-URL, X-Rewrite-URL). Web frameworks should handle request routing exclusively using the standard HTTP request line URI. In legacy Symfony, Laravel, or Spring deployments, URI override processing must be explicitly disabled, and framework components updated to patched versions.

Technical Conclusions
HTTP forwarding, routing, and attribution headers are essential components of modern multi-tiered web architectures. They enable reverse proxies, load balancers, and CDNs to propagate client metadata across layer-7 network boundaries. However, the historical absence of uniform standards, combined with legacy support for non-standardized headers, has created significant security exposure across enterprise application stacks.

When edge proxies pass unsanitized client headers to backend networks, and applications evaluate those headers without validating proxy provenance, severe vulnerabilities emerge. Attackers can exploit these flaws using alternative numeric IP encodings, path traversal mutations, and multi-IP header chaining to bypass access controls, trigger SSRF, poison web caches, and evade rate limits.

Mitigating these security risks requires aligning configuration logic across all infrastructure tiers:

Organizations must implement zero-trust boundary sanitization at edge proxies, configure explicit proxy allowlists on web servers, enforce right-to-left IP parsing algorithms, and disable framework-level URI override mechanisms.

By establishing strict trust boundaries and validating request metadata, engineering teams can ensure robust access control enforcement across distributed web environments.

References
IETF RFC 7239 – Forwarded HTTP Extension

IETF RFC 9110 – HTTP Semantics

CVE-2018-14773 – Symfony URI Rewrite Header Bypass

Nginx ngx_http_realip_module Documentation

Apache mod_remoteip Documentation

HAProxy Configuration Manual

Spring Framework ForwardedHeaderFilter

Express.js Trust Proxy Setting

ASP.NET Core Forwarded Headers Middleware
