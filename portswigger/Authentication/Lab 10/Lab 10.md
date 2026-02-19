# Lab 10: Offline Password Cracking

## Category
Authentication (Offline Password Cracking)

## Vulnerability Summary
The application contains a Cross-Site Scripting (XSS) vulnerability that exposes sensitive session cookies, including the "stay logged in" cookie. This cookie contains the user's password in a hashed format (MD5). An attacker can exploit the XSS vulnerability to steal the cookie, decode it, and perform offline password cracking to reveal the plaintext password, resulting in complete account compromise.

## Attack Methodology
1. **XSS Exploitation:** Leveraged the XSS vulnerability present in the application to extract sensitive cookie data.
2. **Cookie Capture:** Intercepted and captured the stay-logged-in cookie which follows the pattern: `username:hash` (e.g., `carlos:a5f8d3c9e2b1f4a7c8d9e0f1a2b3c4d5`).
3. **Hash Identification:** Identified the hash format as MD5 (32-character hexadecimal string).
4. **Offline Cracking:** Extracted the hash and used offline password cracking tools (such as Hashcat or John the Ripper) to brute-force the MD5 hash.
5. **Password Recovery:** Successfully cracked the hash to reveal the plaintext password for user `carlos`.
6. **Account Compromise:** Used the recovered credentials to gain full unauthorized access to Carlos's account.

![Lab 10 Screenshot](screenshot.png)

## Technical Root Cause
The application suffers from multiple critical security failures:
- **XSS Vulnerability:** Insufficient input validation and output encoding allows attackers to inject malicious scripts that can access sensitive cookie data.
- **Weak Hashing Algorithm:** The application uses MD5 for password hashing, which is cryptographically broken and unsuitable for password storage. MD5 is fast to compute and vulnerable to rainbow table attacks and brute-force cracking.
- **Insecure Cookie Storage:** Sensitive authentication data (including password hashes) is stored in client-side cookies without proper encryption or signing.
- **Lack of Salt:** Passwords are hashed without salt, making them vulnerable to precomputed rainbow table attacks.

## Impact
The user account of `carlos` has been completely compromised without any permission. An attacker can:
- Gain full unauthorized access to the victim's account through recovered credentials
- Perform any action as the compromised user, including data modification and deletion
- Potentially access sensitive personal information and session data
- Use the compromised account for further attacks or privilege escalation
- Permanently lock out the legitimate user by changing credentials
