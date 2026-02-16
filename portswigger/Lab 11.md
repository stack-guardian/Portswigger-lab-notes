# Lab 11: Method-Based Access Control Circumvention

## 🏷️ Category
Broken Access Control – HTTP Method Bypass

---

## 🛡️ Vulnerability Description
Access controls are implemented based on the HTTP method (e.g., GET, POST). However, the application fails to apply these controls consistently when the method is changed or when parameters are passed differently.

## 🚀 Attack Strategy
1. **Interception**: Intercepted a privileged request (e.g., changing a user's role).
2. **Method Switching**: Changed the HTTP method (e.g., from `POST` to `GET` or using `POST` on a `GET` endpoint).
3. **Credential Manipulation**: Modified the target username and associated cookies to perform the action as a low-privileged user.
4. **Execution**: The server accepted the unauthorized request, resulting in the downgrade or modification of another user.

## 🔍 Technical Root Cause
The server only enforced authorization on specific HTTP methods or failed to validate the user's role consistently across all possible methods for a given endpoint.

## 💥 Impact
Unauthorized privilege manipulation and bypass of intended access control policies.
