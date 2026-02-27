# Lab 27: Reflected XSS with event handlers and href attributes blocked

## Category
Cross-Site Scripting (XSS) - Reflected (Filter Bypass via SVG Animation)

## Vulnerability Summary
The website implements filters that block common XSS vectors including event handlers (like `onclick`, `onmouseover`) and `href` attributes with `javascript:` protocol. However, the filter is insufficient because it doesn't account for SVG animation elements. By using the `<animate>` element inside an `<svg>` tag, an attacker can dynamically change the `href` attribute to `javascript:` after the page loads, bypassing the static filter and executing arbitrary JavaScript when the victim clicks the malicious link.

## Attack Methodology
1. **Reconnaissance:** Identified that user input is reflected in the page and event handlers/href attributes are filtered.
2. **Filter Detection:** Found that `onclick`, `onerror`, `onload`, and direct `javascript:` hrefs are blocked.
3. **Bypass Discovery:** Discovered that SVG `<animate>` elements can dynamically modify attributes after page load.
4. **Payload Construction:** Crafted a payload using `<svg><a><animate>` to change the href to `javascript:alert(1)` dynamically.
5. **Execution:** When the victim clicks the rendered "Click me" text, the JavaScript executes.

![Lab 27 Screenshot](screenshot.png)

## Technical Root Cause
The filter only blocks static XSS patterns but fails to prevent dynamic attribute modification:

- **Static Filter Only:** The filter checks for blocked patterns at render time, not after DOM manipulation.
- **SVG Animation Bypass:** The `<animate>` element can change attribute values dynamically.
- **Delayed Execution:** The `javascript:` protocol is injected after the initial page load, bypassing static checks.
- **Incomplete Filter Coverage:** SVG elements and animation attributes are not included in the filter rules.

### Payload Used
```html
<svg><a><animate attributeName=href values=javascript:alert(1)+><text x=20 y=30>Click me</text></a></svg>
```

URL-encoded payload:
```
<svg><a><animate attributeName=href values=javascript:alert(1)+><text x=20 y=30>Click me</text></a></svg>
```

How it works:
- `<svg>` creates an SVG container.
- `<a>` creates a clickable link element.
- `<animate>` dynamically changes the `href` attribute to `javascript:alert(1)`.
- `<text>` displays "Click me" as clickable text.
- When clicked, the alert executes.

## Impact
- **Filter Bypass:** Attacker bypasses XSS filters that block event handlers and href attributes.
- **User Interaction Required:** Victim must click the malicious link for script execution.
- **Session Hijacking:** Attacker can steal session cookies and authentication tokens.
- **Account Takeover:** Malicious scripts can redirect to phishing pages or perform actions on behalf of the victim.
- **Full JavaScript Execution:** Attacker gains complete control over the page's JavaScript context.

## Mitigation
1. **Use Modern Frameworks:** Frameworks like React, Vue, or Angular automatically escape output and prevent XSS.
2. **Comprehensive Input Validation:** Block or sanitize SVG elements and animation attributes in user input.
3. **Content Security Policy (CSP):** Implement strict CSP to block inline scripts and `javascript:` URLs.
4. **Output Encoding:** Encode all user input based on context (HTML, attribute, JavaScript, URL).
5. **Defense in Depth:** Combine multiple layers of protection rather than relying on pattern-based filters.

---
*Lab completed on: 2026-02-27*
