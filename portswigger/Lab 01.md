# Lab 01: Unprotected admin functionality

## Category
Broken Access Control

## Vulnerability Summary
The application's administrative interface is exposed without any role-based validation. This allows any user to access sensitive management functionality simply by knowing or discovering the correct URL.

## Attack Methodology
1. Performed manual endpoint discovery and identified the `/admin` path.
2. Navigated directly to the endpoint without an administrative session.
3. Successfully executed an administrative command to delete the user account for 'carlos'.

## Technical Root Cause
The server lacked an authorization layer or middleware to intercept requests to privileged routes. It failed to verify if the requesting session possessed the required permissions before rendering the administrative interface.

## Impact
An unauthorized attacker can perform high-privilege actions, including user management and system configuration changes, leading to a complete compromise of the application's administrative functions.
