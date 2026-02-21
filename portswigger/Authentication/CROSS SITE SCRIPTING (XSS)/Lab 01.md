# Lab 01: Reflected XSS into HTML context with nothing encoded

## Category
Cross-Site Scripting (XSS) - Reflected

## Vulnerability Summary
The website is vulnerable to **Reflected Cross-Site Scripting (XSS)**. The vulnerability was identified by submitting a malicious JavaScript payload `<script>alert(1)</script>` into user-controllable input, which was then reflected back and executed in the browser without any encoding or sanitization.

## Attack Methodology
1. **Reconnaissance:** Identified user-controllable input fields that reflect data back in the HTTP response.
2. **Payload Injection:** Submitted the basic XSS payload `<script>alert(1)</script>` to test for reflection.
3. **Execution:** The payload was successfully executed in the browser context, confirming the vulnerability.
4. **Verification:** Observed the alert box triggering, proving that arbitrary JavaScript can be injected and executed.

![Lab 01 Screenshot](screenshot.png)

## Technical Root Cause
The server failed to implement protective measures against malicious JavaScript input. Specifically:
- **No Input Validation:** User input was not validated or sanitized before being processed.
- **No Output Encoding:** The reflected content was not HTML-encoded when rendered in the response.
- **Missing Security Headers:** Absence of headers like `Content-Security-Policy (CSP)` or `X-XSS-Protection` that could mitigate such attacks.

## Impact
- **Session Hijacking:** Attackers can steal session cookies using JavaScript (e.g., `document.cookie`), leading to unauthorized account access.
- **Credential Theft:** Malicious scripts can capture keystrokes or redirect users to phishing pages.
- **Defacement:** Attackers can modify the appearance of the website to spread misinformation or damage reputation.
- **Malware Distribution:** Users can be redirected to malicious sites or forced to download malware.

## Mitigation
To prevent Reflected XSS vulnerabilities, implement the following security measures:

### 1. **Output Encoding**
Encode all user-controllable data before rendering it in HTML context:
- Use HTML entity encoding (`<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#x27;`, `&` → `&amp;`)

### 2. **Input Validation**
Validate and sanitize all user input on the server-side:
- Use allowlists for expected input patterns
- Reject or sanitize unexpected characters

### 3. **Content Security Policy (CSP)**
Implement a strong CSP header to restrict script execution:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### 4. **HTTP Security Headers**
Add protective headers:
```
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

### 5. **Use Framework Protections**
Leverage built-in XSS protections in modern web frameworks (e.g., React, Angular, Vue.js) that automatically encode output.

### 6. **Regular Security Testing**
- Perform automated vulnerability scanning
- Conduct manual penetration testing
- Implement security code reviews
