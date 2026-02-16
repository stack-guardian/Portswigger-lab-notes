# Lab 07: Horizontal privilege escalation via IDOR with sensitive data disclosure

## Category
Insecure Direct Object Reference (IDOR)

## Vulnerability Summary
The application leaks sensitive information during a redirect process. When a user requests a resource they don't own, the server attempts to redirect them but includes the sensitive data in the response body before the redirect is handled by the browser.

## Attack Methodology
1. Intercepted the request to an account page and changed the user parameter to a target user.
2. Observed the server's response, which was a 302 redirect.
3. Inspected the body of the 302 response and found the target user's sensitive data (e.g., an API key) before the redirect occurred.

## Technical Root Cause
The application logic generated the sensitive content and included it in the response stream before finalizing the redirect, failing to perform an authorization check before the data was rendered.

## Impact
Disclosure of sensitive credentials or tokens, allowing an attacker to impersonate other users or access their data through secondary interfaces.
