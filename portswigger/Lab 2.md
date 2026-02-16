# Lab 2: Unprotected admin functionality with unpredictable URL

## Category
Broken Access Control (Vertical Privilege Escalation)

## Vulnerability Summary
Administrative features were intended to be hidden via an unpredictable URL. However, this endpoint was disclosed in client-side code, allowing unauthorized access due to a lack of server-side authorization.

## Attack Methodology
1. Analyzed client-side JavaScript source code to identify references to administrative endpoints.
2. Discovered a non-standard administrative URL that was otherwise hidden from the UI.
3. Accessed the URL directly to gain administrative privileges and delete the target user.

## Technical Root Cause
The application relied on security by obscurity rather than actual authorization. The backend failed to validate the user's role, assuming that only an administrator would know the specific URL.

## Impact
Sensitive administrative panels can be accessed by any user who discovers the URL, leading to unauthorized account deletions and privilege escalation.
