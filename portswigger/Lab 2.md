# Lab 2: Unprotected Admin Functionality with Unpredictable URL

## 🏷️ Category
Broken Access Control – Vertical Privilege Escalation

---

## 🛡️ Vulnerability Description
Administrative functionality was exposed through a client-side JavaScript file and accessible directly without proper server-side authorization checks. Although the URL was "unpredictable," it was still discoverable.

## 🚀 Attack Strategy
1. **Source Code Analysis**: Reviewed client-side JavaScript files to identify hidden administrative endpoints.
2. **Direct Access**: Accessed the discovered admin URL directly to reach privileged functionality.
3. **Exploitation**: Performed administrative actions such as deleting user accounts.

## 🔍 Technical Root Cause
The backend failed to enforce role-based access control (RBAC) on sensitive endpoints. The application relied on the unpredictability of the URL (obscurity) rather than robust authorization validation.

## 💥 Impact
Attackers can bypass the intended access restrictions, access administrative panels, and perform privileged actions like deleting users.
