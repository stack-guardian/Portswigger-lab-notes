# Lab 06: Broken brute-force protection via IP block bypass

## Category
Authentication (Broken Brute-Force Protection)

## Vulnerability Summary
The application implements IP-based rate limiting to prevent brute-force attacks on the login functionality. However, this protection mechanism can be bypassed by manipulating the X-Forwarded-For header, allowing an attacker to rotate through multiple IP addresses and continue password brute-forcing attempts without being blocked.

## Attack Methodology
1. **Request Interception:** Captured the initial login request with test credentials (`test:test`) using Burp Suite Proxy.
2. **IP Block Observation:** After three consecutive failed login attempts, the application blocked the originating IP address as expected.
3. **Header Manipulation:** Added the `X-Forwarded-For` header to the request with a rotating IP value for each attempt.
4. **Brute-Force Execution:** Used Burp Intruder to automate password brute-forcing against the known username `carlos` while rotating the X-Forwarded-For header value to bypass IP-based rate limiting.
5. **Account Access:** Successfully identified the correct password and gained access to the target account.

![Lab 06 Screenshot](screenshot.png)

## Technical Root Cause
The server relies solely on the client-provided `X-Forwarded-For` header to identify the source IP address for rate limiting purposes. Since this header can be easily manipulated by an attacker, the IP blocking mechanism becomes ineffective. The application fails to validate or ignore untrusted proxy headers, allowing brute-force attacks to continue indefinitely by simply changing the header value with each request.

## Impact
An attacker can bypass IP-based brute-force protections and systematically guess passwords for known usernames. This leads to complete account takeover, as demonstrated with the user `carlos`. Once an account is compromised, the attacker gains access to all associated data and functionality, potentially enabling further attacks within the application.
