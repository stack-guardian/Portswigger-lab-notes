# Lab 03: DOM XSS in document.write sink using source location.search

## Category
Cross-Site Scripting (XSS) - DOM-based

## Vulnerability Summary
The website is vulnerable to DOM-based cross-site scripting (XSS) through the search functionality. This was discovered by submitting a malicious JavaScript payload `"><svg onload=alert(1)>` in the search parameter. The payload was executed in the browser through client-side JavaScript that wrote unsanitized user input directly into the DOM using `document.write()`.

## Attack Methodology
1. **Reconnaissance:** Identified the search feature that takes input from the URL query parameter (`location.search`).
2. **Payload Injection:** Submitted the DOM XSS payload `"><svg onload=alert(1)>` through the search parameter in the URL.
3. **Sink Identification:** The vulnerable JavaScript code used `document.write()` to output the search term without proper sanitization.
4. **Execution:** The payload executed when the page loaded and the JavaScript wrote the malicious input into the DOM.
5. **Verification:** Observed the alert box triggering and the page displaying "0 search results for" followed by the injected payload, confirming the DOM XSS vulnerability.

![Lab 03 Screenshot](lab3-screenshot.png)

## Technical Root Cause
The client-side JavaScript code failed to properly handle user-controllable input from the URL. Specifically:
- **Unsafe Sink Usage:** The code used `document.write()` to inject user input directly into the DOM without sanitization.
- **Untrusted Source:** The input came from `location.search` (URL query parameters) which is fully controllable by attackers.
- **No Input Validation:** The search term was not validated or encoded before being written to the page.
- **Client-Side Only Protection:** Server-side protections are bypassed since the vulnerability exists in client-side JavaScript.

## Impact
- **Session Hijacking:** Attackers can steal session cookies using JavaScript (for example, `document.cookie`), leading to unauthorized account access.
- **Credential Theft:** Malicious scripts can capture keystrokes or redirect users to phishing pages.
- **Defacement:** Attackers can modify the appearance of the website to spread misinformation or damage reputation.
- **Malware Distribution:** Users can be redirected to malicious sites or forced to download malware.
- **Data Manipulation:** Attackers can modify page content dynamically to mislead users.
- **Hard to Detect:** DOM XSS vulnerabilities are often missed by server-side security scanners since the payload never reaches the server.

## Mitigation
To prevent DOM XSS vulnerabilities, implement the following security measures:

### 1. Avoid Dangerous Sinks
Avoid using `document.write()`, `innerHTML`, `outerHTML`, and `eval()` with user-controllable input. Use safer alternatives when possible.

### 2. Input Validation
Validate and sanitize all user input from URL parameters, fragments, and other client-side sources before using them in DOM operations.

### 3. Output Encoding
Encode data before writing it to the DOM. Use text-based methods instead of HTML-based methods:
```javascript
// Instead of:
element.innerHTML = userInput;

// Use:
element.textContent = userInput;
```

### 4. Content Security Policy (CSP)
Implement a strong CSP header to restrict script execution. For example:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

### 5. Use Safe JavaScript APIs
Use modern APIs that automatically handle encoding:
```javascript
// Safe approach
document.createTextNode(userInput);
element.appendChild(textNode);
```

### 6. Framework Protections
Leverage built-in XSS protections in modern JavaScript frameworks (such as React, Angular, Vue.js) that automatically encode output.

### 7. Security Testing
- Use automated DOM XSS scanners
- Perform manual code review of client-side JavaScript
- Test all URL parameters and fragments for injection points
- Use browser developer tools to identify unsafe sinks

### 8. Security Awareness
- Train developers on DOM XSS risks
- Document safe coding patterns
- Review third-party JavaScript libraries for vulnerabilities
