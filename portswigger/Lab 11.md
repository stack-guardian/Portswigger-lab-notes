# Lab 11: Method-based access control circumvention

## Category
Broken Access Control (Method Bypass)

## Vulnerability Summary
The application enforces access controls on certain HTTP methods (like POST) but fails to apply the same restrictions when the request is sent using a different method (like GET or a modified POST).

## Attack Methodology
1. Attempted a privileged action (e.g., changing a user's role) and observed the required POST request.
2. Noticed the action was blocked for low-privileged users.
3. Resubmitted the request but changed the HTTP method to GET or used a different method that the server still processed.
4. The server executed the action without validating the user's role for the alternative method.

## Technical Root Cause
Authorization checks were tied specifically to certain HTTP verbs rather than the endpoint or the action itself. This allowed for bypasses when the server was configured to be method-agnostic for certain functions.

## Impact
Attackers can perform restricted actions, such as changing user roles or permissions, by simply switching the HTTP method.
