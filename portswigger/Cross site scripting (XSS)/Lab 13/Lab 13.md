# Lab 13: Stored DOM XSS

## Category
Cross-Site Scripting (XSS) - Stored DOM-based

## What I Found
The website has a stored DOM XSS vulnerability in its comment/input storage feature. The site does sanitize angle brackets (`<>`), but only the first occurrence. When I added some dummy `<>` before my actual payload, the sanitization only removed the first pair and left my malicious script intact.

## How I Exploited It
1. Found an input field that stores data and displays it later
2. Noticed the site sanitizes `<>` characters
3. Added dummy `<>` tags before my payload to bypass the sanitization
4. The site only sanitized the first `<>`, leaving my script to execute

Example payload:
```
<> <img src=x onerror=alert(1)>
```

The first `<>` gets sanitized, but the rest passes through and executes.

![Lab 13 Screenshot](screenshot.png)

## Why It Happens
The developers used a simple `replace()` function that only replaces the first occurrence instead of all occurrences. In JavaScript, `string.replace('<>', '')` only removes the first match, not all of them.

## Impact
- Account takeover
- Session hijacking
- Attackers can steal cookies and session tokens
- Victims get affected just by visiting the page

## Fix
- Don't use `innerHTML` when inserting user data
- Use `textContent` instead
- Make sure replace functions use global flag (`/g`) to replace all occurrences, not just the first one
- Better to sanitize on server-side with proper libraries
