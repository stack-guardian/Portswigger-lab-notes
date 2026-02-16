# Lab 8: User ID Controlled by Request Parameter with Password Disclosure

## 🏷️ Category
Broken Access Control – IDOR / Sensitive Data Exposure

---

## 🛡️ Vulnerability Description
The application discloses the user's password in a request or response when accessing the user profile via a manipulated ID parameter.

## 🚀 Attack Strategy
1. **Interception**: Captured the request to the user's own profile.
2. **Manipulation**: Changed the user parameter to `administrator`.
3. **Disclosure**: Observed the administrator's password being leaked in the resulting response/request cycle.
4. **Exploitation**: Used the leaked password to log in as the administrator and delete user `carlos`.

## 🔍 Technical Root Cause
The server logic included highly sensitive data (passwords) in responses and failed to validate that the requester was authorized to view that specific user's profile data.

## 💥 Impact
Full administrative account compromise and unauthorized control over the application.
