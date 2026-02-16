# Lab 08: User ID controlled by request parameter with password disclosure

## Category
Insecure Direct Object Reference (IDOR)

## Vulnerability Summary
The user profile interface includes the user's password in the HTML source. By manipulating the user ID in the request, an attacker can view the passwords of other users, including the administrator.

## Attack Methodology
1. Accessed the user profile page and identified where the password was reflected in the source.
2. Changed the user ID parameter to 'administrator' and intercepted the response.
3. Extracted the administrator's password from the response body.
4. Logged in as the administrator and deleted the target user.

## Technical Root Cause
The application improperly included highly sensitive information (plaintext or masked passwords) in the client-side response and lacked server-side ownership validation for the profile being requested.

## Impact
Critical security breach allowing for full account takeover of any user, including administrative accounts.
