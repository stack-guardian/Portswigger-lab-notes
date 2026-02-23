# Lab 02: Stored XSS into HTML context with nothing encoded

## Category
Cross-Site Scripting (XSS) - Stored

## Vulnerability Summary
The website is vulnerable to stored cross-site scripting (XSS) in the comment section. This was discovered by submitting a malicious JavaScript payload `<script>alert(1)</script>` in a comment. The payload was permanently stored on the server and executed in the browser of any user viewing the comment without any encoding or sanitization applied.

## Attack Methodology
1. **Reconnaissance:** Identified the comment submission feature that stores user input on the server.
2. **Payload Injection:** Submitted the basic XSS payload `<script>alert(1)</script>` in the comment form.
3. **Storage:** The payload was stored permanently in the server's database.
4. **Execution:** When any user (including admin) views the blog post with the malicious comment, the payload executes in their browser context.
5. **Verification:** Observed the alert box triggering for all users viewing the compromised comment, proving persistent JavaScript injection.

![Lab 02 Screenshot](screenshot.png)

## Technical Root Cause
The server failed to implement protective measures against malicious JavaScript input in stored content. Specifically:
- **No Input Validation:** User-submitted comments were not validated or sanitized before being stored.
- **No Output Encoding:** The stored content was not HTML-encoded when rendered in the response page.
- **Missing Security Headers:** Absence of headers like Content-Security-Policy (CSP) or X-XSS-Protection that could mitigate such attacks.
- **Lack of Content Filtering:** No filtering of dangerous HTML tags or JavaScript event handlers in user submissions.

## Impact
- **Session Hijacking:** Attackers can steal session cookies using JavaScript (for example, `document.cookie`), leading to unauthorized account access.
- **Credential Theft:** Malicious scripts can capture keystrokes or redirect users to phishing pages.
- **Defacement:** Attackers can modify the appearance of the website to spread misinformation or damage reputation.
- **Malware Distribution:** Users can be redirected to malicious sites or forced to download malware.
- **Persistent Attack:** Unlike reflected XSS, the payload remains active until manually removed from the server.
- **Admin Compromise:** If administrators view the malicious comment, their accounts can be compromised.

## Mitigation
To prevent stored XSS vulnerabilities, implement the following security measures:

### 1. Output Encoding
Encode all user-controllable data before rendering it in HTML context. Use HTML entity encoding where special characters are converted to their safe equivalents (for example, `<` becomes `&lt;`, `>` becomes `&gt;`).

### 2. Input Validation
Validate and sanitize all user input on the server-side BEFORE storing it. Use allowlists for expected input patterns and reject or sanitize unexpected characters.

### 3. Content Security Policy (CSP)
Implement a strong CSP header to restrict script execution. For example:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### 4. HTTP Security Headers
Add protective headers to your responses:
```
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

### 5. Use Framework Protections
Leverage built-in XSS protections in modern web frameworks (such as React, Angular, Vue.js) that automatically encode output.

### 6. Comment Moderation
- Implement admin approval for comments before publishing
- Use automated content filtering systems
- Allow users to report suspicious content

### 7. Regular Security Testing
- Perform automated vulnerability scanning
- Conduct manual penetration testing
- Implement security code reviews
- Monitor stored user content for malicious payloads

### 8. Database Sanitization
- Sanitize data before storing in database
- Consider encoding at storage time for user-generated content
