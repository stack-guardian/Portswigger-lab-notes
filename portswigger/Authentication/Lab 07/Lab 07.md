# Lab 07: Username enumeration via account lock

## Category
Authentication (Username Enumeration)

## Vulnerability Summary
The application is vulnerable to username enumeration through its account lockout mechanism. When multiple incorrect login attempts are made for a valid username, the application displays a different error message indicating a temporary lockout. This behavioral difference allows an attacker to identify valid usernames in the system. Additionally, the application is susceptible to cluster bomb attacks for credential enumeration.

## Attack Methodology
1. **Payload Generation:** Generated two separate payload lists containing usernames and passwords for the attack.
2. **Cluster Bomb Attack:** Configured Burp Intruder with the cluster bomb attack type, targeting both the username and password parameters in the POST request.
3. **Response Analysis:** Monitored the server responses for distinct error messages. Requests targeting valid usernames returned a specific message: *"You have made too many incorrect login attempts. Please try again in 1 minute."*
4. **Username Identification:** Identified the valid username (adm) based on the lockout message.
5. **Sniper Attack:** After the 1-minute lockout period, performed a sniper attack targeting only the password parameter with the known username.
6. **Credential Discovery:** Successfully obtained both the username (adm) and its corresponding password.

![Lab 07 Screenshot](screenshot.png)

## Technical Root Cause
The application behaves differently for valid usernames versus invalid usernames during login attempts when account lockout is triggered. Instead of returning a generic error message regardless of username validity, the server reveals whether an account exists by enforcing a rate limit only on known usernames. This differential response allows attackers to enumerate valid user accounts.

## Impact
This vulnerability leads to complete account takeover of the user 'adm'. An attacker can:
- Enumerate valid usernames in the system
- Perform targeted password brute-forcing once usernames are identified
- Gain unauthorized access to user accounts and sensitive data

*this lab took literally 4 hours straight for me to solve and find the actual flaw on my own*
