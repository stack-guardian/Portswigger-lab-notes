# LAB 13

## Category:Broken Access Control – Referer-Based Authorization

## Issue:The application enforces access control for administrative functionality by validating the Referer HTTP header. Instead of verifying the user's privileges on the server side, the application checks whether the request originates from /admin.

## Attack:The attacker logs in as a low-privileged user (wiener).

By intercepting the administrative role-upgrade request in Burp Repeater
The server accepts the request because it trusts the Referer header, even though the user does not have administrative privileges.

## Technical Failure:The backend relies on a client-controlled HTTP header (Referer) to enforce authorization decisions.

HTTP headers such as: RefererUser-Agent Origin are fully controllable by the client and must never be used for security decisions.

There is no proper server-side role validation tied to the authenticated session.

## Impact:A low-privileged user can perform administrative actions (e.g., promote users) by manipulating HTTP headers.

This results in privilege escalation and complete compromise of admin-level functionality.
