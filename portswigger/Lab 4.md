# Lab 4: User Role Manipulation via Server-Side Authorization Failure

## 🏷️ Category
Broken Access Control – Privilege Escalation

---

## 🛡️ Vulnerability Description
User roles can be modified through parameters within the user profile functionality. The application suffers from a server-side authentication and authorization weakness by relying on client-controlled parameters for privilege management.

## 🚀 Attack Strategy
1. **Interception**: Intercepted an HTTP request (e.g., during profile update) using a proxy tool.
2. **Parameter Tampering**: Modified a request parameter related to user privileges, altering the role value from a standard user to an administrative role.
3. **Exploitation**: Successfully escalated privileges without legitimate authorization.

## 🔍 Technical Root Cause
The server trusted client-supplied data and failed to enforce Role-Based Access Control (RBAC) validation on the backend. There was no integrity verification for privilege-related parameters.

## 💥 Impact
Unauthorized administrative access, enabling attackers to manipulate database records, delete users, and compromise the application's integrity and availability.
