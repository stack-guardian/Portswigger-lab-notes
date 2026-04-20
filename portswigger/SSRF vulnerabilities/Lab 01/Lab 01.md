# Lab 01: Basic SSRF against the Local Server

## Category
SSRF (Server-Side Request Forgery)

## Vulnerability Summary
The application has a stock-check feature that sends a server-side HTTP request to a URL supplied by the user via the `stockApi` parameter. There is no validation on what that URL can point to. The internal admin panel at `/admin` trusts requests from localhost unconditionally and has no authentication of its own. By pointing `stockApi` at `http://localhost/admin`, the server fetches and returns the admin panel — and by pointing it at `http://localhost/admin/delete?username=carlos`, the server executes the deletion on the attacker's behalf.

## Steps

### Step 1: Intercept the stock check request
Opened a product page and clicked "Check stock". Intercepted the request in Burp Repeater:

```
POST /product/stock HTTP/2
Host: 0ab200430378474d8004171e00890072.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

stockApi=https://stock.weliketoshop.net/product/stock/check?productId=2&storeId=1
```

The `stockApi` parameter is the full URL the server will request. No token, no validation.

### Step 2: Probe the internal admin panel
Replaced the `stockApi` value with `http://localhost/admin` and sent the request. The response body contained the rendered admin panel — including a user list with `wiener` and `carlos`, each with a Delete link.

This confirms the server makes the request from its own loopback interface, and the admin panel grants full access to any request coming from localhost.

### Step 3: Delete the target user
Changed `stockApi` to `http://localhost/admin/delete?username=carlos` and sent the request.

```
HTTP/2 302 Found
Location: /admin
```

The server followed through with the deletion and redirected back to the admin panel. Lab solved.

![screenshot1](screenshot1.png)

![screenshot2](screenshot2.png)

## Root Cause
The application passes a user-supplied URL directly to a server-side HTTP client with no restrictions on scheme, host, or path. The internal admin panel relies entirely on network origin for access control — if the request comes from localhost, it's trusted. There is no authentication layer on the admin interface itself. These two weaknesses together mean any user who can reach the `stockApi` parameter can reach anything the server can reach internally.

## Impact
Full access to internal services that are otherwise unreachable from the internet. In this case that meant unauthenticated admin access and arbitrary user deletion. In real environments the same primitive is used to hit cloud metadata endpoints (`169.254.169.254`), internal dashboards, and management APIs that assume they're only reachable from trusted infrastructure.

## What to Fix
The `stockApi` parameter should be validated against an allowlist of permitted hosts and paths before the request is made. Requests to loopback addresses and internal RFC-1918 ranges should be blocked at the application layer. More importantly, the admin panel should not rely on network origin as its only access control — it needs its own authentication regardless of where the request comes from.

## Tools Used
- Burp Suite Professional (Repeater)
- Chromium

---

*Lab completed on: 2026-04-20*
*Writeup by vibhxr*
