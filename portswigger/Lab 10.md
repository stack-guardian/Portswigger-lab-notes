# Lab 10: Improper enforcement of URL-based authorization controls

## Category
Broken Access Control (Header-Based Bypass)

## Vulnerability Summary
Access to administrative URLs is restricted at the network or proxy level, but the backend server supports custom HTTP headers that can override the requested URL. This allows attackers to bypass the front-end restrictions.

## Attack Methodology
1. Attempted to access `/admin` and received an access denied message from the proxy/WAF.
2. Modified the request to a permitted endpoint but added a header such as `X-Original-URL: /admin`.
3. The backend server prioritized the header value and rendered the administrative interface.

## Technical Root Cause
The application environment relied on inconsistent URL parsing between the front-end proxy and the back-end application server, allowing the latter to be "tricked" into serving restricted content via header manipulation.

## Impact
Bypass of high-level security controls, granting unauthorized access to administrative functionality.
