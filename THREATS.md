# TrustVault: Comprehensive Threat Model & Security Architecture (THREATS.md)

## 1. Executive Summary & Security Philosophy

TrustVault is designed under the adversarial premise that **a document platform that leaks is not a partially working document platform—it is a failed platform**. TrustVault solves the two fundamental failure modes of confidential enterprise sharing:
1. **Permissions Failure**: Over-permissioning, lingering access after employee departure, and horizontal tenant cross-contamination.
2. **Audit Failure**: The inability to definitively, tamper-evidently prove *who* opened a document, *when*, from *what IP*, and *which unauthorized attempts were refused*.

Traditional CRUD architectures treat authorization as an afterthought (client-side checks, hiding UI buttons, caching grants in long-lived JWTs, or exposing direct file system paths). TrustVault implements a **Zero-Trust Server-Authoritative Pipeline** where the server evaluates identity and permissions against live database state on every single request, recording every transaction and refused probe in an immutable, cryptographically hash-chained audit ledger.

---

## 2. Threat Modeling Framework (STRIDE)

Every attack vector is analyzed using the STRIDE classification:
- **S**poofing Identity
- **T**ampering with Data / Logs
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

---

## 3. Threat Analysis & Mitigations

### Threat 1: Insecure Direct Object References (IDOR) on Document Retrieval and Download
* **Classification**: Information Disclosure / Elevation of Privilege (OWASP A01:2021)
* **Attack Vector**: Attacker authenticates as Viewer Charlie, observes their own document URL `/api/documents/doc-audit-q3`, and modifies the ID to target Bob’s confidential intellectual property `/api/documents/doc-arch-nextgen` or Alice’s executive compensation document `/api/documents/doc-salary-2026`.
* **Vulnerability in Typical Apps**: The backend queries `SELECT * FROM documents WHERE id = :id` without checking whether `:id` is owned by or shared with the caller.
* **TrustVault Defense**:
  1. Every document request routes through `resolveUserAccess(documentId, userId)`.
  2. The server queries `documents` and `document_permissions` synchronously.
  3. If caller is neither the document owner (`owner_id === userId`) nor the recipient of an active, unrevoked grant (`revoked_at IS NULL`), access is denied immediately with HTTP 403 Forbidden.
  4. The probe is trapped and recorded in the cryptographic audit ledger as `ACCESS_DENIED` with actor identity, target resource ID, IP address, and timestamp.
* **Automated Test**: `Standard 1 (Zero-Trust): Charlie (Viewer) cannot reach Bob (Owner) confidential document` in `tests/security.test.js`.

---

### Threat 2: Stale Authorization & Lingering Access (Caches, Pre-signed URLs, Long-lived JWTs)
* **Classification**: Elevation of Privilege / Information Disclosure
* **Attack Vector**: An owner revokes a contractor's access at 12:05 PM. The contractor continues downloading confidential files until 12:30 PM because the system issued a 30-minute JWT containing permission claims, or generated an Amazon S3 pre-signed URL with a 15-minute TTL.
* **Vulnerability in Typical Apps**: Decoupled authorization where permission decisions are cached or embedded in client tokens.
* **TrustVault Defense (Standard 3 Enforced)**:
  1. TrustVault issues identity claims only in tokens (`sub`, `tokenVersion`), **never permission grants**.
  2. Every file download, metadata read, and edit request queries the database at execution time.
  3. Revoking access (`DELETE /api/documents/:id/permissions/:userId`) sets `revoked_at = NOW()` immediately.
  4. The very next millisecond request evaluates `revoked_at IS NULL`, which evaluates to false, immediately rejecting the request with HTTP 403.
  5. File streaming is handled directly by the authenticated server (`res.pipe`), not through unrevokable third-party pre-signed URLs.
* **Automated Test**: `Standard 3 (Immediate Revocation): Revoking access takes effect immediately` in `tests/security.test.js`.

---

### Threat 3: Direct File System Path Traversal & Static Asset Exposure
* **Classification**: Information Disclosure / Tampering
* **Attack Vector**:
  - Vector A: Attacker attempts to download `/storage/vault_files/Executive_Salary_Review_2026.pdf` by guessing static URL paths or exploiting web server directory listing.
  - Vector B: Attacker uploads a document with filename `../../../../etc/shadow` or `..\..\boot.ini` to overwrite system files.
* **TrustVault Defense**:
  1. Storage Isolation: Vault files reside in `./storage/vault_files/` which is outside the public web root (`public/`). The web server router explicitly forbids serving files from storage paths.
  2. Cryptographic Storage Keys: Files are never saved on disk with their user-supplied filenames. Every file is stored under a cryptographically random UUID (`vault_${crypto.randomUUID()}.${ext}`).
  3. Filename Sanitization: `sanitizeFilename()` strips path traversal symbols (`..`, `/`, `\`), null bytes (`\0`), control characters, and whitelists safe characters (`[a-zA-Z0-9._-]`).
  4. Content-Disposition Hardening: Downloads are served with `Content-Disposition: attachment; filename="..."`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`.
* **Automated Test**: `Upload Validation: Filename sanitization neutralizes path traversal attacks` in `tests/security.test.js`.

---

### Threat 4: Audit Log Tampering, Modification, and Historical Record Erasure
* **Classification**: Repudiation / Tampering
* **Attack Vector**: A malicious insider or compromised administrator downloads confidential salary documents or proprietary IP, then modifies the database to delete or alter the audit logs so that nobody can prove who reached the document.
* **Vulnerability in Typical Apps**: Standard SQL tables (`INSERT INTO logs`) can be modified via `UPDATE logs SET actor = 'bob'` or `DELETE FROM logs WHERE id = 42`.
* **TrustVault Defense (Standard 2 Enforced)**:
  1. **Cryptographic Hash Chaining**: Every audit entry represents a block linked to the previous block hash:
     $$\text{hash}_i = \text{SHA256}(\text{id} \parallel \text{prev\_hash} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{resource} \parallel \text{ip} \parallel \text{status} \parallel \text{details})$$
  2. **Genesis Block**: Block #1 is rooted in a deterministic genesis hash (`0` repeated 64 times).
  3. **Strict Sequence Continuity**: Any deleted row creates an ID discontinuity ($id_k \neq k$) and a hash mismatch ($prev\_hash_{k+1} \neq hash_{k-1}$).
  4. **Content Modification Detection**: Modifying any field (even a single character in the details JSON) alters the SHA-256 hash, causing all subsequent blocks in the chain to fail verification.
  5. **Verification Engine**: `verifyAuditChainIntegrity()` mathematically recomputes the entire chain from block 1 to Head on demand and flags any discrepancy.
* **Automated Test**: `Standard 2 (Tamper-Evident Ledger): Cryptographic hash chain detects database alteration` in `tests/security.test.js`.

---

### Threat 5: Audit Log Bypasses and Unaudited Execution Paths
* **Classification**: Repudiation
* **Attack Vector**: An attacker crafts requests that trigger exceptions before an audit log is written, or exploits unauthenticated routes to probe endpoints without leaving a record.
* **TrustVault Defense**:
  1. All access rejections (including unauthenticated requests, malformed tokens, and unauthorized IDOR probes) are audited immediately inside the request handler.
  2. Transactional Ledger Logging: Audit event insertions run inside SQLite transactions (`BEGIN IMMEDIATE`) guaranteeing persistence before HTTP response delivery.
  3. Every 401 Unauthorized, 403 Forbidden, 404 Not Found (on existing confidential resources), and 500 Security Anomaly is captured in the ledger.
* **Automated Test**: `API Integration: Full HTTP dispatch of authentication, IDOR blocking, and audit verification` in `tests/security.test.js`.

---

### Threat 6: Side-Channel Metadata Leakage via Search, Listing, and Error Codes
* **Classification**: Information Disclosure
* **Attack Vector**:
  - Attacker searches for `"Merger"`, `"Acquisition"`, or `"Salary"`: if search results return document titles or counts even without allowing download, confidential business activities are leaked.
  - Timing or status code differences: returning 404 for nonexistent documents vs 403 for existing unauthorized documents allows attackers to enumerate valid document IDs.
* **TrustVault Defense**:
  1. Push-Down Access Scoping: `searchDocuments()` enforces access control at the database query level:
     ```sql
     WHERE d.is_deleted = 0
       AND (d.owner_id = :userId OR (p.user_id = :userId AND p.revoked_at IS NULL))
     ```
  2. Users cannot discover document titles, categories, or owners for documents they do not have explicit permissions to see.
  3. A search by an unauthorized user for confidential keywords returns zero results.
* **Automated Test**: `Search Isolation: Scoped search returns strictly documents user has permission to see` in `tests/security.test.js`.

---

### Threat 7: Malicious File Uploads (Polyglots, Executable Disguises, MIME Confusion)
* **Classification**: Tampering / Remote Code Execution / Cross-Site Scripting
* **Attack Vector**: Attacker uploads a PHP script, bash script, Windows executable, or SVG with embedded JavaScript disguised with a `.pdf` or `.png` extension.
* **TrustVault Defense**:
  1. **Magic Bytes Inspection**: The server inspects the binary header bytes of the buffer:
     - PDF: Must match `%PDF-` (`0x25, 0x50, 0x44, 0x46`).
     - PNG: Must match `\x89PNG\r\n\x1a\n`.
     - JPEG: Must match `0xFF, 0xD8, 0xFF`.
     - Office Open XML: Must match ZIP magic header `PK\x03\x04`.
     - Text / CSV: Must be valid UTF-8, contain no null bytes (`\x00`), and contain no `<script>` or executable payload patterns.
  2. **Extension Whitelist & Denylist**: Dangerous extensions (`.exe`, `.sh`, `.php`, `.svg`, `.html`, `.js`, `.dll`, `.bat`) are rejected immediately.
  3. **Strict Size Limits**: 25 MB hard ceiling enforced at the streaming parser layer to prevent DoS.
* **Automated Test**:
  - `Upload Validation: Executables and scripts are strictly rejected`
  - `Upload Validation: Magic byte inspection catches extension spoofing (PHP inside .pdf)` in `tests/security.test.js`.

---

### Threat 8: Vertical and Horizontal Privilege Escalation
* **Classification**: Elevation of Privilege
* **Attack Vector**:
  - Horizontal: Viewer Charlie attempts to grant access to Viewer Dave on Alice's document.
  - Vertical: Viewer Charlie attempts to update document content or delete a document.
* **TrustVault Defense**:
  1. Only the document owner (`owner_id === userId`) can invoke `grantDocumentPermission`, `revokeDocumentPermission`, or `deleteDocument`.
  2. Users with `read` permission cannot update metadata or files; only `edit` permission holders or owners can update.
  3. Role invariants are strictly enforced in business logic and verified before database operations.
* **Automated Test**:
  - `Privilege Escalation: Viewer cannot grant permissions to other users`
  - `Edit Permissions: Viewer with Read permission cannot update or delete document` in `tests/security.test.js`.

---

### Threat 9: Admin Overreach / Superuser Eavesdropping (Zero-Trust Separation of Duties)
* **Classification**: Elevation of Privilege / Information Disclosure
* **Attack Vector**: A system administrator uses administrative status to view or download confidential salary letters, executive severance agreements, or patent drawings without authorization.
* **Design Decision & Defense**:
  1. TrustVault enforces **Strict Separation of Duties**: Administrators have governance responsibilities (user lifecycle management, viewing system audit metrics, verifying cryptographic ledger health), **but do not possess automatic read/download access to confidential document payloads**.
  2. If an administrator attempts to download a confidential document without an explicit grant from the owner, `resolveUserAccess()` returns `canRead: false`, throwing HTTP 403 Forbidden.
  3. Any attempted access by an administrator is recorded as an `ACCESS_DENIED` security incident.
* **Automated Test**: `Separation of Duties: Admin cannot download confidential document without explicit grant` in `tests/security.test.js`.

---

### Threat 10: Race Conditions (TOCTOU) During Rapid Permission Revocation
* **Classification**: Elevation of Privilege
* **Attack Vector**: An attacker initiates a large document download stream at the exact instant an owner clicks "Revoke".
* **TrustVault Defense**:
  1. SQLite runs in Write-Ahead Logging (WAL) mode with `PRAGMA synchronous = NORMAL`.
  2. Permission revocation transactions execute with `BEGIN IMMEDIATE`, ensuring that grant revocations commit before subsequent download authorizations read the permission state.
  3. File streaming checks on-disk file existence and integrity checksums before piping.

---

### Threat 11: Timing Attacks on Authentication & Tokens
* **Classification**: Information Disclosure
* **Attack Vector**: Attacker measures millisecond variations in string comparison for password hashes or session signatures to deduce valid tokens byte-by-byte.
* **TrustVault Defense**:
  1. Password verification utilizes `crypto.timingSafeEqual` over derived scrypt buffers.
  2. HMAC session token signatures are validated using `crypto.timingSafeEqual` with constant-time equality checks.
  3. Authentication error messages are standardized ("Invalid email or password") to prevent username enumeration.

---

### Threat 12: Account Suspension Lags & Dormant Ex-Employee Access
* **Classification**: Spoofing / Elevation of Privilege
* **Attack Vector**: An employee is terminated, but their active JWT token continues working until its expiry (e.g. 8 hours later).
* **TrustVault Defense**:
  1. Each user record contains a `token_version` integer.
  2. When an administrator suspends an account (`PUT /api/admin/users/:id/status`), the server sets `is_active = 0` and increments `token_version`.
  3. `validateSession()` checks both `is_active === 1` and `token_version === token.tokenVersion` against SQLite on every request.
  4. All existing sessions and tokens issued to that user become invalid instantly.
* **Automated Test**: `Instant Session Invalidation: Suspended user token is rejected on the next request` in `tests/security.test.js`.

---

## 4. Knowingly Accepted Residual Risks & Honest Engineering Trade-offs

In accordance with transparent security engineering, the following risks are explicitly acknowledged and defended:

| Residual Risk | Why It Was Left / Trade-off | Mitigations in Production |
| :--- | :--- | :--- |
| **Physical Server / OS Disk Tampering** | If an attacker obtains root access to the physical host, they could rewrite the entire SQLite file from scratch (generating a new synthetic hash chain). | In production enterprise environments, the audit ledger's Head hash should be periodically committed to an external WORM (Write-Once-Read-Many) storage, a public timestamping ledger (RFC 3161), or a centralized SIEM (e.g. Splunk/Datadog) that the host OS cannot modify. |
| **Client-Side Exfiltration (Screenshots, Photographs)** | Once an authorized viewer downloads or displays a file, TrustVault cannot prevent the user from taking a photograph of the physical screen or using external screen capture. | Document watermarking with viewer identity, session ID, and timestamp can be overlaid on rendered PDFs to discourage camera leaks. |
| **Single-Node SQLite Write Throughput Ceiling** | TrustVault uses `DatabaseSync` in WAL mode with immediate transactions to guarantee audit chain serialization. Under tens of thousands of concurrent writes per second, SQLite write serialization will queue. | Accepted for single-node prototype simplicity and zero-dependency reliability. For hyper-scale distributed clusters, an append-only distributed ledger (e.g., Kafka with idempotent producer + PostgreSQL partitioning) would replace single-file SQLite. |
| **Memory Footprint for 25MB Uploads** | Multipart uploads buffer the file in memory to compute SHA-256 and inspect magic bytes prior to writing to disk. | 25MB memory limit is safe for modern servers. Files larger than 25MB are rejected to prevent memory exhaustion DoS. |

---

## 5. Security Verification Matrix

| Threat # | Description | Mitigation Strategy | Test in `tests/security.test.js` |
| :---: | :--- | :--- | :--- |
| **1** | IDOR on Document Download | Real-time database ACL check | `Standard 1 (Zero-Trust): Charlie cannot reach Bob confidential document` |
| **2** | Stale Grants & Caching | Real-time query, no cached claims | `Standard 3: Revoking access takes effect immediately` |
| **3** | Path Traversal in Filename | Random UUID paths, filename sanitization | `Upload Validation: Filename sanitization neutralizes path traversal attacks` |
| **4** | Audit Log Modification | Cryptographic SHA-256 hash chaining | `Standard 2: Cryptographic hash chain detects database alteration` |
| **5** | Unaudited Denied Probes | Logging of 401/403/404 attempts | `API Integration: Full HTTP dispatch of authentication, IDOR blocking, and audit verification` |
| **6** | Search Metadata Leakage | Scoped SQL `WHERE` clauses | `Search Isolation: Scoped search returns strictly documents user has permission to see` |
| **7** | Polyglots & Executables | Magic byte signature verification | `Upload Validation: Rejection of executables and magic byte validation` |
| **8** | Privilege Escalation | Strict ownership checks for grants | `Privilege Escalation: Viewer cannot grant permissions to other users` |
| **9** | Admin Confidentiality Breach | Separation of duties (zero-trust) | `Separation of Duties: Admin cannot download confidential document without grant` |
| **12** | Dormant User Access | Real-time `is_active` & `token_version` | `Instant Session Invalidation: Suspended user token is rejected on the next request` |
