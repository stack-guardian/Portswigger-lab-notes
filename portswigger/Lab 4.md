# LAB 4 — User Role Manipulation via Server-Side Authorization Failure

## Category:

User role can be modified through parameters within the user profile functionality.

## Issue:

Server-side authentication and authorization weakness. The application relies on client-controlled parameters for privilege management without enforcing proper validation or role verification on the backend.

## Attack:

The attacker intercepted an HTTP request using a proxy tool and modified a request parameter related to user privileges. By altering the role value from a standard user to an administrative role, the attacker successfully escalated privileges without legitimate authorization checks.

## Technical Failure:

The server trusted client-supplied data and failed to enforce role-based access control (RBAC) validation on the server side. There was no integrity verification or privilege enforcement mechanism, allowing unauthorized role escalation. As a result, the server processed the modified request as if it originated from a legitimate administrative user.

## Impact:

Unauthorized administrative access may allow attackers to manipulate database records, delete users, modify sensitive information, and compromise overall application integrity and availability.
