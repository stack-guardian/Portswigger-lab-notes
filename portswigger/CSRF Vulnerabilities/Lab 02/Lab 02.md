# Lab 02: CSRF with token validation bypass

> **Topic**: CSRF Vulnerabilities  
> **Lab Number**: 02  
> **Platform**: PortSwigger Web Security Academy  

## Category  
Cross-Site Request Forgery (CSRF)  

## Vulnerability Summary  
This lab demonstrates a CSRF vulnerability where the application validates CSRF tokens but does so insecurely, allowing attackers to bypass the validation. The root cause is weak token validation logic, such as accepting empty or predictable tokens.  

## Attack Methodology  
1. **Identify the CSRF Attack Surface**:  
   - Locate a sensitive action (e.g., email change, password reset) that lacks robust CSRF protections.  
2. **Analyze the Vulnerable Request**:  
   - Use Burp Suite to intercept the request and observe the CSRF token mechanism.  
3. **Craft the CSRF Exploit**:  
   - Create an HTML form that omits or manipulates the CSRF token to bypass validation.  
4. **Host the Exploit**:  
   - Serve the exploit on a controlled server or use a tool like `python3 -m http.server`.  
5. **Deliver to Victim**:  
   - Trick the victim into loading the exploit page (e.g., via phishing).  
6. **Lab Verification**:  
   - Confirm the attack succeeds by observing the unauthorized action (e.g., email change).  

## Technical Root Cause  
The application checks for the presence of a CSRF token but does not enforce its validity. For example:  
- The token may be optional (empty tokens are accepted).  
- The token may be predictable (e.g., derived from the user ID).  

## Impact  
- **Severity**: High  
- Attackers can perform unauthorized actions on behalf of users (e.g., change account details, transfer funds).  

## Remediation  
1. **Enforce Token Validation**:  
   - Reject requests with missing or invalid tokens.  
2. **Use Secure Tokens**:  
   - Generate tokens cryptographically (e.g., using `secrets.token_hex()` in Python).  
3. **SameSite Cookies**:  
   - Set `SameSite=Strict` or `SameSite=Lax` for session cookies.  

## Tools Used  
- Burp Suite  
- Python HTTP server (`python3 -m http.server`)  

*Writeup by vibhxr*