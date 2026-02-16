# Lab 9: Insecure direct object reference in chat transcripts

## Category
Broken Access Control (IDOR)

## Vulnerability Summary
The application provides access to historical chat transcripts using a predictable file-naming convention. It fails to verify if the requester was a participant in the chat before serving the file.

## Attack Methodology
1. Initiated a chat and downloaded the resulting transcript.
2. Observed the naming pattern of the transcript file (e.g., `2.txt`).
3. Manually requested a different file number (e.g., `1.txt`).
4. Successfully downloaded a transcript containing another user's sensitive information.

## Technical Root Cause
The transcript retrieval system lacked an access control list (ACL) or session-based verification. It served any file requested as long as the file existed on the server.

## Impact
Exposure of private conversations which may contain credentials, personal data, or sensitive business information.
