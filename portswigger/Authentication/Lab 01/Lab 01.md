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

![Lab 01 Screenshot](screenshot.png)

## Technical Root Cause
The server provides overly descriptive error messages. Specifically, it returns **"invalid user"** when a username does not exist, rather than a generic **"invalid username or password"** message. This distinct response reveals whether a username is registered in the database, regardless of the password's validity.

## Impact
An attacker can successfully identify valid usernames and IDs within the system. This information significantly reduces the complexity of subsequent attacks, such as targeted password brute-forcing or social engineering, leading to potential account takeovers.
