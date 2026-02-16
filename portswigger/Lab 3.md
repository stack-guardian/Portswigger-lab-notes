# Lab 3: User role controlled by request parameter

## Category
Broken Access Control (Parameter Tampering)

## Vulnerability Summary
The application makes authorization decisions based on a parameter supplied by the client. By modifying this parameter, a user can trick the server into granting administrative access.

## Attack Methodology
1. Intercepted a standard authenticated request using a proxy.
2. Identified a parameter (such as a cookie or body field) that explicitly defined the user's role.
3. Modified the value from 'false' to 'true' (or similar) to indicate administrative status.
4. Forwarded the modified request and gained access to the admin panel.

## Technical Root Cause
The server trusted user-controlled input for security-critical decisions. Authorization logic should be handled server-side based on the session state, not on parameters that can be manipulated by the client.

## Impact
Attackers can easily escalate their own privileges to the highest level, gaining full control over administrative operations.
