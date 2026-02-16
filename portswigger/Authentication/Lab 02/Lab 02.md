# Lab 02: 2FA simple bypass

## Category
Authentication (2FA Bypass)

## Vulnerability Summary
The application's two-factor authentication (2FA) mechanism can be bypassed because it fails to properly validate the user session between the initial login and the OTP verification step. This allows an attacker to gain unauthorized access to another user's account without possessing their second-factor credentials.

## Attack Methodology
1. **Initial Login:** Logged in with valid credentials for the user 'wiener'.
2. **Endpoint Identification:** Identified the URL structure for the 2FA verification page.
3. **Session Manipulation:** Instead of providing an OTP for 'wiener', manually modified the request or URL to target the user 'carlos'.
4. **Bypass Execution:** Navigated directly to the account page or manipulated the user identifier in the request to 'carlos' during the 2FA phase.
5. **Success:** The server granted access to 'carlos''s account, bypassing the requirement for a valid OTP.

## Technical Root Cause
The backend fails to enforce stateful verification of the 2FA process. It improperly relies on user-controlled input (the username) during the verification step without ensuring that the authenticated session matches the user for whom the OTP was issued. Essentially, the server changed the active user ID from 'wiener' to 'carlos' simply because it was requested, without re-authenticating the second factor.

## Impact
This flaw leads to a complete account takeover of any user (in this case, 'carlos'). An attacker can bypass security controls intended to protect accounts, resulting in unauthorized access to sensitive user data and functionality.
