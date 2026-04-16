# Lab 02: CSRF where token validation depends on request method

## Category
CSRF (Cross-Site Request Forgery)

## Vulnerability Summary
The application is vulnerable to CSRF because it fails to validate CSRF tokens on state-changing requests when the request method is altered.

## Attack Methodology
1. **Request Capture:** Intercepted the email change request in Burp Suite to analyze the parameters and CSRF token usage.
2. **Analysis:** Identified that the application expects a CSRF token in the request body for POST requests.
3. **Exploitation:** Crafted a malicious request and observed that the application processed the change request even without a valid token under certain conditions.
4. **Final Payload:** Executed the CSRF exploit by creating a crafted HTML page that triggers the state-changing request on the user's behalf.

![Lab 02 Screenshot 1](screenshot1.png)

![Lab 02 Screenshot 2](screenshot2.png)

## Technical Root Cause
The vulnerability stems from improper validation of state-changing requests, allowing attackers to perform unauthorized actions by manipulating request methods or headers to bypass intended CSRF protections.

## Impact
Unauthorized account changes, potentially leading to full account takeover.

## Remediation
- Implement strict CSRF token validation on all state-changing endpoints.
- Ensure that tokens are validated regardless of the request method.
- Follow OWASP best practices for CSRF prevention.
