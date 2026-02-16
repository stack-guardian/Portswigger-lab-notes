# Lab 12: Broken access control in multi-step process

## Category
Broken Access Control (Workflow Bypass)

## Vulnerability Summary
A sensitive administrative function is split into multiple steps. The server validates permissions during the first step but assumes that any request reaching the final "confirmation" step has already been authorized.

## Attack Methodology
1. Observed the multi-step process for upgrading a user's role.
2. Noted the final request sent to confirm the change.
3. Logged in as a low-privileged user and sent the final confirmation request directly to the server, bypassing the initial steps.
4. The server processed the change, granting the attacker administrative rights.

## Technical Root Cause
The backend failed to implement stateful authorization or re-verify permissions at every stage of the workflow. It relied on the assumption that the steps would always be followed in order.

## Impact
Vertical privilege escalation, allowing users to execute complex administrative tasks by skipping authorization checkpoints.
