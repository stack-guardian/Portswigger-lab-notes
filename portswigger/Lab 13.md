# Lab 13: Referer-Based Authorization Bypass

## 🏷️ Category
Broken Access Control – Insecure Authorization Mechanism

---

## 🛡️ Vulnerability Description
The application relies on the `Referer` HTTP header to make authorization decisions for administrative actions. It checks if the request originated from an `/admin` page rather than verifying the user's actual session privileges.

## 🚀 Attack Strategy
1. **Interception**: Logged in as a low-privileged user and intercepted a request to an administrative function.
2. **Header Manipulation**: Manually set or modified the `Referer` header to point to the expected administrative URL (e.g., `https://.../admin`).
3. **Bypass**: The server accepted the request based on the trusted header, granting unauthorized access.

## 🔍 Technical Root Cause
The backend relied on a client-controlled HTTP header for security decisions. Headers like `Referer` are easily spoofed and should never be used for authorization.

## 💥 Impact
Privilege escalation; low-privileged users can perform administrative actions by simply manipulating headers.
