# Lab 01: Basic SSRF against the Local Server

## Category
SSRF (Server-Side Request Forgery) - Internal Service Access via URL Parameter

## Vulnerability Summary
The application exposes a stock-check feature that accepts a URL via the `stockApi` parameter and makes a server-side HTTP request to it. There is no validation or restriction on the destination of that request. By supplying `http://localhost/admin` as the value, the server fetches its own internal admin panel and returns the response — bypassing any front-end access controls that would normally block external users from reaching it.

## Attack Methodology
1. **Request Capture:** Intercepted the stock check POST request using Burp Suite Repeater. The request body contained `stockApi=<url>` pointing to the legitimate stock endpoint.
2. **Internal Probe:** Replaced the `stockApi` value with `http://localhost/admin` and sent the request. The response rendered the admin panel, confirming the server trusts loopback requests unconditionally.
3. **User Enumeration:** The admin panel response listed two users — `wiener` and `carlos` — each with a Delete link.
4. **Privilege Escalation:** Modified the `stockApi` value to `http://localhost/admin/delete?username=carlos` and sent the request. The server responded with `HTTP/2 302 Found`, redirecting to `/admin`, confirming the deletion was executed.

![screenshot1](screenshot1.png)

![screenshot2](screenshot2.png)

## Technical Root Cause
The server makes outbound HTTP requests based on a URL supplied directly by the user without any allowlist, blocklist, or scheme restriction. Requests originating from `localhost` are treated as trusted by the internal admin interface, which has no independent authentication layer. This is a classic SSRF pattern: the application acts as an unintended proxy, forwarding attacker-controlled requests to internal services that are otherwise inaccessible from the outside.

## Impact
An attacker can reach any service bound to the loopback interface or internal network that the application server can access. In this case, full admin functionality — including user deletion — was accessible without any credentials. In real environments this class of bug commonly leads to access to cloud metadata endpoints (e.g., `http://169.254.169.254`), internal dashboards, and unauthenticated management APIs.

## Remediation
- Validate and restrict the `stockApi` parameter to an explicit allowlist of trusted hostnames and paths.
- Block requests to loopback addresses (`127.0.0.1`, `localhost`, `::1`) and internal RFC-1918 ranges at the network or application layer.
- The internal admin panel should enforce its own authentication independent of network origin — never rely solely on "only reachable from localhost" as an access control.
- Use a dedicated egress proxy with strict allowlisting rather than allowing the application server to make arbitrary outbound requests.
