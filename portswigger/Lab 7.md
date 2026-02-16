# Category:Horizontal Privilege Escalation via Insecure Direct Object Reference (IDOR) with sensitive data disclosure in HTTP redirect response.

## Issue:The application exposes user account data based on a client-controlled identifier parameter and improperly includes sensitive information in the HTTP redirect response. The server fails to enforce proper object-level authorization checks before processing the request.

## Attack:The attacker logged into a legitimate account and intercepted the account-related HTTP request using Burp Suite. By modifying the user identifier parameter from wiener to carlos, the attacker triggered a server response that redirected while leaking sensitive information (Carlos’ API key) in the redirect response.

## Technical Failure:The backend application relied on client-supplied user identifiers and failed to verify ownership of the requested resource. Additionally, sensitive data was included in the redirect response without proper validation, resulting in information disclosure.

## Impact:An attacker can access another user's API key through manipulated request parameters, leading to unauthorized data exposure and potential account compromise.
