# Lab 12: Broken Access Control in Multi-Step Process

## 🏷️ Category
Broken Access Control – Workflow Bypass

---

## 🛡️ Vulnerability Description
The application uses a multi-step process for sensitive actions (e.g., upgrading a user). While initial steps might have authorization checks, the final confirmation step does not, allowing it to be called directly.

## 🚀 Attack Strategy
1. **Process Initiation**: Started the role upgrade process as a low-privileged user.
2. **Interception**: Captured the final "confirmation" request.
3. **Direct Execution**: Sent the final request (e.g., `confirmed=true`) directly to the server, bypassing the initial authorization checks in the earlier steps.
4. **Elevation**: Successfully upgraded the account to administrator.

## 🔍 Technical Root Cause
The backend failed to enforce access control consistently across all steps of a stateful workflow. It assumed that reaching the final step implied the previous steps were successfully and legitimately completed.

## 💥 Impact
Vertical privilege escalation, allowing low-privileged users to gain full administrative control.
