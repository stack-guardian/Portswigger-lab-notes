# Lab 03: Password reset broken logic

## Category
Authentication (Broken Logic / Password Reset)

## Vulnerability Summary
The application's password reset functionality contains a logic flaw that allows an attacker to reset the password of any user without proper authorization. By manipulating request parameters, an attacker can bypass the intended security controls and perform an account takeover.

## Attack Methodology
![Lab 03 Screenshot](screenshot.png)

1. **Request Initiation:** Started a legitimate password reset process for the controlled account 'wiener'.
2. **Interception:** Intercepted the password reset submission request using Burp Suite.
3. **Parameter Manipulation:** Identified the parameter used to specify the username (e.g., `username=wiener`) and modified it to target another user (e.g., `username=carlos`).
4. **Execution:** Submitted the modified request to the server.
5. **Success:** The server accepted the change and reset the password for 'carlos' instead of 'wiener', allowing the attacker to log in as 'carlos'.

## Technical Root Cause
The backend fails to verify that the password reset token or the current session is tied to the username provided in the request. It blindly trusts the user-supplied username parameter to determine which account's password should be updated, rather than enforcing a server-side check to validate that the requester has the authority to modify that specific account.

## Impact
This vulnerability results in a critical account takeover. An attacker can change the password of any user, including administrative accounts, leading to a complete compromise of user data and system access.
