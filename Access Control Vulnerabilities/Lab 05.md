# Lab 05: User ID controlled by request parameters

## Category
Insecure Direct Object Reference (IDOR)

## Vulnerability Summary
The application retrieves and displays user account information based on a user-provided identifier in the request. It fails to check if the authenticated user has the authority to view the data associated with that identifier.

## Attack Methodology
1. Logged into a standard account and observed the request used to view the profile.
2. Modified the user identifier in the URL or request body to match a target user.
3. Successfully accessed the target user's private account information and API keys.

## Technical Root Cause
The server performed a direct lookup of the object (user profile) using the provided ID without implementing an ownership check to verify that the ID belonged to the current session user.

## Impact
Unauthorized access to sensitive user data, leading to a breach of privacy and potential account takeover if credentials or tokens are exposed.
