# Lab 7: Horizontal Privilege Escalation via IDOR with Sensitive Data Disclosure

## 🏷️ Category
Insecure Direct Object Reference (IDOR)

---

## 🛡️ Vulnerability Description
The application leaks sensitive information in an HTTP redirect response. It fails to enforce proper object-level authorization checks before processing requests for account-specific resources.

## 🚀 Attack Strategy
1. **Interception**: Logged into a legitimate account (`wiener`) and intercepted the account-related request.
2. **Manipulation**: Changed the user identifier from `wiener` to `carlos`.
3. **Leaked Data**: Observed that the server responded with a redirect, but the body of the response (or headers) contained sensitive data, such as Carlos' API key.

## 🔍 Technical Root Cause
The backend failed to verify resource ownership. Furthermore, the application logic improperly included sensitive data in a response that was intended to be a simple redirect.

## 💥 Impact
An attacker can steal sensitive credentials (like API keys) belonging to other users, leading to full account compromise.
