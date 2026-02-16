# Lab 6: User ID Controlled by Request Parameters (Unpredictable IDs)

## 🏷️ Category
Broken Access Control – Horizontal Privilege Escalation

---

## 🛡️ Vulnerability Description
The application exposes user account data through direct object references. Even though user IDs might be "unpredictable" (e.g., GUIDs), the application still fails to validate ownership of the requested resource.

## 🚀 Attack Strategy
1. **Discovery**: Obtained the "unpredictable" identifier for another user (e.g., from a public profile or blog post).
2. **Interception**: Intercepted an HTTP request and replaced the user's own identifier with the victim's identifier.
3. **Access**: Gained unauthorized access to the victim's account data.

## 🔍 Technical Root Cause
The server relied on the difficulty of guessing identifiers (security by obscurity) instead of implementing proper object-level access control validation.

## 💥 Impact
Horizontal privilege escalation, allowing attackers to access other users' sensitive information and compromising account confidentiality.
