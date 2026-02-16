# Lab 10: Improper Enforcement of URL-Based Authorization Controls

## 🏷️ Category
Broken Access Control – Bypass via HTTP Headers

---

## 🛡️ Vulnerability Description
The application attempts to restrict access to administrative URLs, but the enforcement is inconsistent. Access controls can be bypassed by using specific HTTP headers that confuse the routing or authorization logic.

## 🚀 Attack Strategy
1. **Access Attempt**: Attempted to access `/admin` directly and was blocked.
2. **Header Manipulation**: Added headers like `X-Original-URL: /admin` or `X-Rewrite-URL: /admin` to a request targeting a non-restricted endpoint.
3. **Bypass**: The backend processed the request based on the header, granting unauthorized access to the admin panel.

## 🔍 Technical Root Cause
The application relied on front-end or proxy-level URL filtering instead of robust server-side authorization. It trusted client-supplied header values to determine the effective request target.

## 💥 Impact
Unauthorized access to administrative functionality, potentially leading to full system compromise.
