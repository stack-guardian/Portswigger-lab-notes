# Lab 1: Unprotected Admin Functionality

## 🏷️ Category
Broken Access Control

---

## 🛡️ Vulnerability Description
Admin endpoints are accessible without any role validation. The application fails to restrict access to sensitive administrative pages, allowing any user to navigate to them directly.

## 🚀 Attack Strategy
1. **Endpoint Discovery**: Manually identified the administrative endpoint (e.g., `/admin`).
2. **Direct Navigation**: Navigated directly to the discovered URL without being logged in as an administrator.
3. **Exploitation**: Used the administrative interface to delete the user `carlos`.

## 🔍 Technical Root Cause
The server lacked proper authorization middleware or checks on sensitive endpoints. It relied on "security by obscurity" or simply failed to verify the user's role before granting access to privileged functionality.

## 💥 Impact
Complete compromise of administrative functions, allowing unauthorized users to perform sensitive actions such as account deletion.
