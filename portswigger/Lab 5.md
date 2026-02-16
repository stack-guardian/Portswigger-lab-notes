# Lab 5: User ID Controlled by Request Parameters

## 🏷️ Category
Broken Access Control – Insecure Direct Object Reference (IDOR)

---

## 🛡️ Vulnerability Description
The application retrieves account data directly based on a user identifier supplied in the request without validating whether the authenticated user owns the requested resource.

## 🚀 Attack Strategy
1. **Login**: Logged into a legitimate account (`wiener`).
2. **Interception**: Intercepted the request used to access account information.
3. **IDOR Manipulation**: Modified the user identifier parameter from `wiener` to another user (`carlos`).
4. **Access**: Successfully accessed the unauthorized account data of `carlos`.

## 🔍 Technical Root Cause
The server trusted client-controlled input and failed to enforce object-level authorization. It did not verify if the authenticated user had permission to access the specific resource identifier provided in the request.

## 💥 Impact
Attackers can access sensitive information belonging to other users, leading to unauthorized data exposure, privacy violations, and potential account compromise.
