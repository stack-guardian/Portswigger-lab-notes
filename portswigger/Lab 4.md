# Lab 4: User role manipulation via server-side authorization failure

## Category
Broken Access Control (Privilege Escalation)

## Vulnerability Summary
The application allows users to modify their own profile data, including role-related parameters. Because the server does not validate these specific changes, users can self-promote to an administrative role.

## Attack Methodology
1. Initiated a profile update request and captured it using a proxy.
2. Added or modified a parameter associated with the user's role within the request body.
3. Submitted the request to the server, which accepted the new role without verification.
4. Confirmed administrative access was granted.

## Technical Root Cause
The backend failed to implement a restricted schema for user profile updates. It allowed the modification of sensitive fields that should only be accessible by the system or higher-privileged users.

## Impact
This flaw leads to unauthorized role escalation, allowing any user to gain full administrative rights over the platform.
