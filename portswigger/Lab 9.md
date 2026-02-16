# Lab 9: Insecure Direct Object Reference (IDOR) in Chat Transcripts

## 🏷️ Category
Broken Access Control – IDOR

---

## 🛡️ Vulnerability Description
The application allows users to download chat transcripts. These transcripts are retrieved using predictable object references (e.g., incrementing IDs), and the server fails to validate if the user is authorized to access the requested transcript.

## 🚀 Attack Strategy
1. **Interception**: Intercepted the request to download a chat transcript.
2. **ID Manipulation**: Modified the filename or ID parameter to point to a different transcript (e.g., `1.txt` to `2.txt`).
3. **Data Retrieval**: Successfully downloaded transcripts belonging to other users, which contained sensitive information like login credentials.

## 🔍 Technical Root Cause
Lack of object-level authorization checks. The server trusted the filename/ID provided by the client without verifying the user's session-based permissions.

## 💥 Impact
Confidentiality breach; unauthorized access to private conversations and potentially sensitive credentials.
