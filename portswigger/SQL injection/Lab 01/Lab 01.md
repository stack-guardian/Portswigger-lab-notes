# Lab 01: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

## Category
SQL Injection - WHERE Clause Exploitation (Hidden Data Retrieval)

## Vulnerability Summary
The website's product filtering feature contains a SQL injection vulnerability in the WHERE clause. When an unusual SQL query is entered in the category filter, the application returns all data from the database instead of filtered results. The vulnerability allows attackers to bypass intended filters and retrieve hidden data that should not be accessible through normal user interaction.

## Attack Methodology
1. **Reconnaissance:** Identified the product category filter feature on the e-commerce website.
2. **Input Testing:** Entered unusual SQL queries in the category filter parameter to test for injection points.
3. **Vulnerability Discovery:** Discovered that injecting SQL operators in the filter parameter alters the WHERE clause behavior.
4. **Payload Construction:** Crafted a SQL injection payload using `'+OR+1=1--` to manipulate the WHERE clause.
5. **Execution:** The injected payload causes the WHERE clause to always evaluate to true, returning all products.
6. **Verification:** Confirmed successful data retrieval by observing all products displayed regardless of category selection.

![Lab 01 Screenshot 1](screenshot1.png)

## Technical Root Cause
The vulnerability stems from improper handling of user input in SQL query construction:

- **Unsanitized Input:** User input from the category filter is directly concatenated into SQL queries.
- **Missing Parameterization:** The application does not use parameterized queries or prepared statements.
- **WHERE Clause Manipulation:** The injection point allows modification of the WHERE clause logic.
- **Boolean-Based Injection:** The `OR 1=1` payload creates a tautology that bypasses filter conditions.
- **Comment Injection:** The `--` comment operator terminates the original query, ignoring remaining conditions.
- **No Input Validation:** The application accepts SQL operators and special characters without validation.

### Payload Used
```
'+OR+1=1--
```

URL-encoded payload in category filter:
```
/filter?category='+OR+1=1--
```

How it works:
- The original query likely looks like: `SELECT * FROM products WHERE category = 'input'`
- The injection transforms it to: `SELECT * FROM products WHERE category = '' OR 1=1--'`
- The `OR 1=1` condition always evaluates to true, returning all rows.
- The `--` comments out the rest of the original query, preventing syntax errors.
- All products from the database are displayed, including hidden ones.

## Impact
- **Hidden Data Retrieval:** Attacker can access products or data that should remain hidden.
- **Full Database Exposure:** With advanced techniques, entire database contents may be extractable.
- **Information Disclosure:** Sensitive business data, product details, and pricing information exposed.
- **Authentication Bypass:** Similar techniques could potentially bypass login mechanisms.
- **Data Integrity Risk:** In other contexts, SQL injection could allow data modification or deletion.
- **Compliance Violation:** Data exposure may violate privacy regulations and security standards.
- **Reputation Damage:** Public disclosure of SQL injection vulnerabilities affects user trust.

## Mitigation
1. **Parameterized Queries:** Use prepared statements with parameterized queries for all database operations.
2. **Input Validation:** Implement strict input validation allowing only expected category values.
3. **Whitelist Approach:** Use a whitelist of valid category names instead of accepting raw input.
4. **ORM Usage:** Consider using Object-Relational Mapping (ORM) frameworks that handle SQL safely.
5. **Least Privilege:** Database accounts should have minimal permissions required for application function.
6. **Error Handling:** Implement generic error messages that do not reveal database structure.
7. **Web Application Firewall:** Deploy WAF rules to detect and block SQL injection attempts.
8. **Regular Security Testing:** Conduct periodic penetration testing and code reviews for SQL injection.

---
*Lab completed on: 2026-03-03*
