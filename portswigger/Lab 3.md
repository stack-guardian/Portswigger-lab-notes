# Lab 3: User Role Controlled by Request Parameter

## 🏷️ Category
Broken Access Control – Vertical Privilege Escalation (Parameter Tampering)

---

## 🛡️ Vulnerability Description
The application relied on a client-controlled request parameter to determine administrative privileges. Authorization decisions were made using user-supplied data without server-side validation.

## 🚀 Attack Strategy
1. **Interception**: Intercepted an authenticated request using Burp Suite.
2. **Identification**: Located a parameter in the request that appeared to control privileges (e.g., `admin=false`).
3. **Tampering**: Modified the value from `false` to `true`.
4. **Elevation**: Forwarded the request and gained administrative access.

## 🔍 Technical Root Cause
Authorization logic was implemented on the client side or trusted client-side input instead of being enforced securely on the server. The server failed to validate the modified request parameters against the user's actual session-based permissions.

## 💥 Impact
Unauthorized administrative access and privilege escalation, allowing an attacker to perform sensitive operations.

## ✅ Security Recommendation
- Implement server-side authorization checks.
- Do not trust client-supplied privilege values.
- Enforce role validation using secure session data or database records.
