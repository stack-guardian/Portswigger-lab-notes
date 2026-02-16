# Lab 01: Username enumeration via different responses

## Category
Authentication (Username Enumeration)

## Vulnerability Summary
The application is vulnerable to username enumeration because it returns different HTTP responses or error messages depending on whether a valid or invalid username is provided. This flaw allows an attacker to systematically verify the existence of user accounts on the system.

## Attack Methodology
1. **Request Capture:** Intercepted the login request using Burp Suite Proxy.
2. **Payload Setup:** Sent the request to Burp Intruder to perform a brute-force attack on the username field.
3. **Execution:** Used a wordlist of common usernames to automate the identification process.
4. **Analysis:** Monitored the server's responses to distinguish between valid and invalid usernames based on the specific error messages returned.

## Technical Root Cause
The server provides overly descriptive error messages. Specifically, it returns **"invalid user"** when a username does not exist, rather than a generic **"invalid username or password"** message. This distinct response reveals whether a username is registered in the database, regardless of the password's validity.

## Impact
An attacker can successfully identify valid usernames and IDs within the system. This information significantly reduces the complexity of subsequent attacks, such as targeted password brute-forcing or social engineering, leading to potential account takeovers.

---

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
