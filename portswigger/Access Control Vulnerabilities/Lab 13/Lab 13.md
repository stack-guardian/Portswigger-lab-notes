# Lab 13: Referer-based authorization bypass

## Category
Broken Access Control (Insecure Referer Validation)

## Vulnerability Summary
The application attempts to secure administrative functions by checking the `Referer` header of the request. It assumes that if a request comes from an administrative page, it must be legitimate.

## Attack Methodology
![Lab 13 Screenshot](screenshot.png)

1. Identified an administrative action that was restricted.
2. Captured the request and manually added or modified the `Referer` header to match the administrative URL.
3. The server accepted the spoofed header and executed the privileged action.

## Technical Root Cause
The application used a client-controlled header (the Referer) for a security decision. Since headers can be trivialy modified by an attacker, they are not a reliable source for authorization.

## Impact
Attackers can perform administrative actions by simply spoofing the request origin, leading to unauthorized system changes and privilege escalation.
