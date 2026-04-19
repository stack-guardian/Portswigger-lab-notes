# PortSwigger Web Security Academy — Lab Notes

This repository contains my working notes from PortSwigger Web Security Academy labs. It covers exploitation techniques, vulnerability patterns, and the underlying mechanics of each class of bug. The notes are written for my own reference and are organized to be useful during real engagements, not just as a record of completed exercises.

## Coverage

| Topic | Labs Solved | Status |
|---|---|---|
| SQL Injection | 18 | Complete |
| Cross-Site Scripting | 31 | Complete |
| CSRF | 12 | Complete |
| Access Control | 13 | Complete |
| Authentication | 14 | Complete |
| SSRF | 5 | In Progress |
| **Total** | **93+** | |

## Approach

Each lab was worked through without following walkthroughs. The goal was to understand what the application was doing wrong, why the vulnerability existed, and what a real attacker would do with it — not just to hit the green "solved" banner. Notes were written after solving, not during, which forces a cleaner explanation of the logic.

Documentation focuses on the exploitation chain: what input the application trusted, where that trust broke down, and what the impact was. Where a lab had multiple valid approaches, I noted the differences and why one technique works where another fails. This matters more in practice than memorizing payloads.

The CSRF and authentication sections in particular are documented with an eye toward how these bugs appear in real applications — where developers implement partial mitigations that still leave exploitable gaps. Understanding why `SameSite=Lax` doesn't fully protect a login flow, for example, is more useful than knowing the bypass payload in isolation.

SSRF coverage is still in progress. The notes currently cover basic server-side request forgery and blind SSRF with out-of-band detection. Advanced topics including SSRF via protocol smuggling and cloud metadata abuse will be added as I work through the remaining labs.

## Repository Structure

```
Portswigger-lab-notes/
├── portswigger/                        # All lab notes, organized by topic
│   ├── SQL injection/                  # Labs 01-18
│   ├── Cross site scripting (XSS)/     # Labs 01-31, includes personal notes
│   ├── CSRF vulnerabilities/           # Labs 01-12
│   ├── Access Control Vulnerabilities/ # Labs 01-13
│   ├── Authentication/                 # Labs 01-14
│   └── API Testing Vulnerabilities/    # Labs 01-05
├── README.md
└── LICENSE
```

## Tools

| Tool | Purpose |
|---|---|
| Burp Suite Pro | Intercepting and modifying HTTP requests, active scanning, Intruder for brute-force labs |
| FoxyProxy | Browser proxy switching between Burp and direct traffic |
| Browser DevTools | DOM inspection, JavaScript debugging, cookie and storage analysis |

## References

[PortSwigger Web Security Academy](https://portswigger.net/web-security)

[OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)

[CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

[CWE-79: Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)

[CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

[CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)

---

This is an active repository — I add notes as I work through new labs and occasionally revise older ones when I encounter the same bug class in a real context. The SSRF section will be completed over the next few weeks.
