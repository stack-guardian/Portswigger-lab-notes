# XSS — My Honest Take

I completed 31 XSS labs on PortSwigger Web Security Academy.

Did I understand all of them deeply? **No.** I'll be straight about that.

Some labs I solved by following the steps, understanding bits and pieces along the way but not the full picture. Some payloads I used without fully grasping why every character was there. Some concepts like AngularJS sandbox escapes and dangling markup attacks went over my head in the moment.

## What I Actually Walked Away With

I now understand what XSS **fundamentally** is — injecting code into a context where the browser executes it.

- I understand the difference between **reflected**, **stored**, and **DOM-based** XSS.
- I understand why **context matters** — being inside a JavaScript string is completely different from being inside an HTML attribute or a template literal.
- I understand why **filters fail** and why **blocklists always lose** eventually.
- I learned how **CSP works**, why it exists, and more importantly — **how it can be bypassed** when misconfigured.
- I learned that `<script>` is almost always blocked and real XSS is about finding the **one door nobody thought to lock**.

## Labs I Felt Genuinely Confident About

- Filter bypasses using **SVG and animate** elements
- **Cookie stealing** via fetch and Collaborator
- **Password capture** via input injection
- **CSP header injection** lab

## Labs I Need to Revisit With Fresh Eyes

- **AngularJS sandbox escapes** — understood enough to solve, not enough to replicate from scratch
- **Dangling markup attack** — same as above

## My Take

**XSS is hard.**

Harder than authentication bypass. Harder than access control — at least for me right now. Those three feel like home. XSS still feels like a city I visited but haven't lived in yet.

I'm not embarrassed by that. 31 labs in, I know significantly more than I did when I started. I know what I don't know — and that's actually progress.

**I'll come back to XSS.** With more experience, more bug hunting, and more real world context, these concepts will click differently. They always do.

---
*Written on: 2026-02-28*
