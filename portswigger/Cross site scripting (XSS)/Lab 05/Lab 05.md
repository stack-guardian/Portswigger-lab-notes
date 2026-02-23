# Lab 05: DOM XSS in jQuery Anchor href Attribute Sink Using location.search

## Category
Cross-Site Scripting (XSS) - DOM-based

## Vulnerability Summary
The website contains a DOM-based XSS vulnerability in how it handles links dynamically. The issue lies in the client-side code that reads data from the URL query parameters (`location.search`) and directly assigns it to jQuery anchor (`<a>`) href attributes without proper validation. This allows attackers to inject malicious JavaScript that executes when users interact with the manipulated links.

## Attack Methodology
1. **Reconnaissance:** Identified that the page dynamically builds links using URL query parameters.
2. **Source Identification:** Found that data is read from `location.search` (the URL query string).
3. **Sink Identification:** Discovered that jQuery is used to set the `href` attribute of anchor elements with untrusted data.
4. **Payload Injection:** Crafted a malicious URL with a JavaScript payload embedded in the query parameter (using `javascript:` protocol).
5. **Execution:** When a victim clicks the manipulated link, the injected JavaScript executes in their browser context.
6. **Verification:** Confirmed successful script execution through observable behavior or browser developer tools.

![Lab 05 Screenshot](screenshot.png)

## Technical Root Cause
The vulnerability exists due to unsafe DOM manipulation with jQuery:

- **Unsafe Attribute Assignment:** The application uses jQuery's `.attr('href', ...)` to set anchor href values with user-controlled data.
- **Untrusted Source:** Data comes from `location.search`, which attackers can fully control.
- **JavaScript Protocol Handler:** The `javascript:` protocol in href attributes allows script execution when the link is clicked.
- **No Validation:** The application doesn't validate or sanitize the URL before assigning it to the href attribute.

### Vulnerable Code Pattern
```javascript
// Dangerous pattern - DO NOT use
var query = location.search;
$('a.back-link').attr('href', query);
```

## Impact
- **Account Takeover:** Attackers can steal session cookies and authentication tokens to hijack user accounts.
- **Session Hijacking:** Malicious scripts can capture active sessions and impersonate victims.
- **Credential Theft:** Attackers can redirect users to fake login pages or capture keystrokes.
- **Phishing:** Users can be tricked into visiting malicious sites that appear legitimate.
- **Data Exfiltration:** Sensitive information from the page can be sent to attacker-controlled servers.

## Mitigation

### 1. Use Safe Assignment Methods
Instead of directly assigning user input to href attributes, validate and sanitize first:

```javascript
// Safe pattern - validate URL before assignment
var query = location.search;
if (isValidURL(query)) {
    $('a.back-link').attr('href', query);
}
```

### 2. Avoid javascript: Protocol
Block or sanitize any `javascript:` protocol in URLs:

```javascript
if (url.toLowerCase().startsWith('javascript:')) {
    // Reject or sanitize the URL
    return;
}
```

### 3. Use textContent for Dynamic Content
When displaying user data, use `.text()` instead of `.html()` in jQuery.

### 4. Implement Content Security Policy (CSP)
Add CSP headers to restrict script execution:
```
Content-Security-Policy: default-src 'self';
```

### 5. Validate URLs Server-Side
Never trust client-side validation alone. Validate all URLs on the server before processing.

### 6. Use Allowlists
Only allow expected URL patterns (like relative paths or specific domains).
