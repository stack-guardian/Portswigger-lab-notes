# Lab 06: User ID controlled by request parameters with unpredictable IDs

## Category
Broken Access Control (Horizontal Privilege Escalation)

## Vulnerability Summary
The application uses unpredictable identifiers (like GUIDs) for users but still relies on them as the sole "security" mechanism. If an attacker discovers another user's ID, they can access their account data due to missing authorization checks.

## Attack Methodology
1. Discovered a target user's unique identifier through public-facing parts of the application (e.g., a blog post or comment).
2. Substituted the attacker's own ID with the discovered ID in a profile request.
3. Accessed the victim's account details.

## Technical Root Cause
The system used "security by obscurity" by assuming unpredictable IDs were equivalent to authorization. The backend failed to validate that the requested ID matched the authenticated user's identity.

## Impact
Horizontal privilege escalation, allowing any user to access the data of any other user once their unique identifier is known.
