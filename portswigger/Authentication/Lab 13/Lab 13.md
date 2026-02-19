# Lab 13: Broken Brute-Force Protection - Multiple Credentials Per Request

## Category
Authentication (Broken Brute-Force Protection, Multiple Credentials Per Request)

## Vulnerability Summary
The application implements brute-force protection mechanisms designed to block repeated login attempts after a certain threshold. However, this protection can be bypassed by exploiting a parameter pollution vulnerability. When the password parameter is submitted as an array of multiple credential strings in a single request, the application processes each password value sequentially instead of rejecting the malformed request. This allows an attacker to test hundreds of passwords in a single HTTP request, completely bypassing the rate-limiting and account lockout protections.

## Attack Methodology
1. **Reconnaissance:** Identified the login endpoint and observed that the application blocks IPs or accounts after multiple failed login attempts.
2. **Request Interception:** Captured a standard login POST request using Burp Suite Proxy.
3. **Parameter Manipulation:** Modified the `password` parameter from a single value to an array format by appending `[]` to the parameter name and including multiple password candidates.
4. **Payload Configuration:** Injected a list of candidate passwords as array elements (e.g., `password[]=123456&password[]=password&password[]=qwerty...`).
5. **Request Forwarding:** Sent the manipulated request to the server.
6. **Response Analysis:** The application processed each password value in the array against the target username, effectively testing all passwords in a single request.
7. **Success Identification:** Identified the correct password by analyzing response differences or error messages that revealed which password value was being validated.
8. **Account Compromise:** Used the discovered password to login normally and gain unauthorized access.

![Lab 13 Screenshot](screenshot.png)

## Technical Root Cause
The application has multiple critical security failures in its authentication mechanism:
- **Parameter Pollution Vulnerability:** The backend framework accepts array-style parameters for the password field and iterates through each value instead of expecting a single scalar value.
- **Broken Rate Limiting:** The brute-force protection counts requests rather than credential attempts, allowing multiple password guesses within a single request to bypass the threshold.
- **Insufficient Input Validation:** The server does not validate that the password parameter contains only a single value, trusting client-supplied input format.
- **Information Leakage:** Error responses or behavioral differences may reveal which password in the array was being processed, providing feedback to the attacker.
- **Missing Request Integrity Checks:** The application does not enforce strict parameter structure expectations for authentication requests.

## Impact
The targeted user account has been completely compromised through a single-request brute-force attack. An attacker can:
- Bypass all rate-limiting and account lockout protections by testing hundreds of passwords in one request
- Systematically discover user passwords without triggering security alerts or IP blocks
- Gain full unauthorized access to victim accounts while evading detection systems
- Exploit the vulnerability against multiple user accounts in rapid succession
- Completely undermine the security benefits of brute-force protection mechanisms
- Perform account takeover attacks at scale with minimal network footprint



# [Also it was the easiest lab in the entire authentication section. lol]
