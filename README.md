# TrustVault | Zero-Trust Confidential Document Platform

> **"A document platform that leaks is not a partially working document platform. It is a failed platform."**

TrustVault is a zero-trust confidential document sharing and compliance system designed from the ground up to solve two fundamental problems in enterprise document governance:
1. **Permissions Failure**: Over-permissioning, dormant access after employee termination, and horizontal client data leakage.
2. **Audit Failure**: The inability to definitively, tamper-evidently prove who opened a file, when, from what IP address, and which unauthorized probes were refused.

TrustVault enforces **real-time server-authoritative authorization**, **instant revocation**, and an **immutable, cryptographically hash-chained audit ledger**.

---

## 1. Quick Start & Clean Deployment

TrustVault is built with a **Zero-Dependency Architecture** utilizing Node.js v22/v24 standard built-ins (`node:http`, `node:sqlite`, `node:crypto`, `node:fs`, `node:test`). It requires zero external npm packages, eliminating supply-chain vulnerabilities and compilation failures on any platform.

### Prerequisites
- Node.js version 22.0.0 or higher (v24 recommended).

### Running from a Clean Clone
```bash
# 1. Navigate to project root
cd trustvault

# 2. Run the automated security test suite (12/12 passing)
npm test

# 3. Start the TrustVault server
npm start
```

Open your browser to:
**`http://localhost:3000`**

---

## 2. Pre-Seeded Evaluation Accounts & Roles

The database initializes with pre-configured accounts and seed confidential documents for immediate evaluation:

| Email | Password | Role | Description & Seed Access |
| :--- | :--- | :--- | :--- |
| **`admin@trustvault.local`** | `AdminPass123!` | `admin` | Security Admin. Full audit oversight, user management, tamper verification. *Cannot read confidential documents without explicit grant (Separation of Duties).* |
| **`alice.owner@trustvault.local`** | `AlicePass123!` | `owner` | HR Director. Owns `Executive_Salary_Review_2026.pdf` and `Q3_External_Audit_Working_Papers.pdf`. Can grant/revoke access. |
| **`bob.owner@trustvault.local`** | `BobPass123!` | `owner` | Engineering IP Director. Owns `NextGen_Proprietary_Architecture.pdf`. |
| **`charlie.viewer@trustvault.local`** | `CharliePass123!` | `viewer` | Internal Auditor. Seeded with `read` permission on `Q3_External_Audit_Working_Papers.pdf`. No access to Bob's IP or Alice's salary review. |
| **`dave.viewer@trustvault.local`** | `DavePass123!` | `viewer` | External Contractor. Has zero default grants. Searches return 0 results. |
| **`eve.revoked@trustvault.local`** | `EvePass123!` | `viewer` | Former Employee (`is_active = 0`). Demonstrates immediate session and login refusal. |

*Tip: The web UI features a **Fast Role Switcher** dropdown in the top-right header allowing 1-click persona switching without retyping credentials.*

---

## 3. The Three Inviolable Standards: How TrustVault Meets Them

### Standard One: The Server Decides Every Time (Zero-Trust)
- Document access is never decided by client-side button visibility or frontend state.
- Storage files are isolated in `./storage/vault_files/` outside the web root under cryptographically generated UUIDs (`vault_${crypto.randomUUID()}.pdf`), completely unreachable via static HTTP URLs.
- Every read, download, update, and delete request invokes `resolveUserAccess(documentId, userId)` against the database in real time.
- If a user lacks a direct ownership or active grant record, the request is rejected with HTTP 403 Forbidden.

### Standard Two: Cryptographic Tamper-Evident Audit Ledger
- Every state mutation and refused access probe is appended to a **SHA-256 hash-chained ledger**:
  $$\text{hash}_i = \text{SHA256}(\text{id} \parallel \text{prev\_hash} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{resource} \parallel \text{ip} \parallel \text{status} \parallel \text{details})$$
- Block #1 is rooted in a deterministic genesis hash (`0` repeated 64 times).
- An attacker or rogue DBA who modifies or deletes any row breaks the cryptographic chain.
- The built-in verification engine (`GET /api/audit/verify`) mathematically verifies all blocks from Genesis to Head in real-time, pinpointing the exact block ID if tampered.

### Standard Three: Taking Access Away Works Immediately
- Permissions are **never cached in JWT claims** or delegated to long-lived pre-signed URLs.
- When an owner revokes access (`DELETE /api/documents/:id/permissions/:userId`), `revoked_at` is timestamped in the database.
- The very next request from that user checks `revoked_at IS NULL`, evaluates to false, and is rejected instantly with HTTP 403.
- When an admin suspends a user, their `token_version` is incremented, immediately terminating all existing sessions.

---

## 4. API Documentation & Authorization Matrix

| Method | Endpoint | Allowed Roles | Description & Required Grants |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Public | Authenticates credentials, issues signed session token with `tokenVersion`. |
| `GET` | `/api/auth/me` | Authenticated | Retrieves profile of currently authenticated user. |
| `GET` | `/api/documents` | Authenticated | Scoped search. Returns only documents caller owns or has active grants on. |
| `POST` | `/api/documents` | `owner`, `admin` | Uploads confidential file. Validates magic bytes, sanitizes filename, computes SHA-256. |
| `GET` | `/api/documents/:id` | Document Grantee / Owner | Retrieves document metadata. Requires `read`, `edit`, or `owner`. |
| `GET` | `/api/documents/:id/download` | Document Grantee / Owner | Streams file with security headers (`nosniff`, `attachment`, `no-store`). Requires `read` or `edit`. |
| `PUT` | `/api/documents/:id` | `owner` or `edit` grantee | Updates title, category, or file version. Requires `edit` or `owner`. |
| `DELETE` | `/api/documents/:id` | Document `owner` only | Deletes document. Viewers and editors are strictly denied (HTTP 403). |
| `GET` | `/api/documents/:id/permissions` | Document `owner`, `admin` | Lists named active grants on document. |
| `POST` | `/api/documents/:id/permissions` | Document `owner` only | Grants named permission (`read` or `edit`) to target email. |
| `DELETE` | `/api/documents/:id/permissions/:userId` | Document `owner` only | **Instantly revokes** permission from target user. |
| `GET` | `/api/audit` | Authenticated (Scoped) | Admin sees all; Owner sees document logs; Viewer sees own actions. |
| `GET` | `/api/audit/verify` | Authenticated | Mathematically verifies SHA-256 hash chain from block 1 to Head. |
| `GET` | `/api/admin/users` | Authenticated | Lists users for governance or sharing selector. |
| `PUT` | `/api/admin/users/:id/status` | `admin` only | Suspends or activates user account. Increments `token_version`. |

---

## 5. Automated Security Test Suite

The automated test suite (`tests/security.test.js`) executes 12 rigorous security proofs using Node.js's native test runner (`node:test`):

```bash
npm test
```

### Verified Test Cases:
1. `Standard 1 (Zero-Trust): Charlie (Viewer) cannot reach Bob (Owner) confidential document`
2. `Standard 3 (Immediate Revocation): Revoking access takes effect immediately`
3. `Standard 2 (Tamper-Evident Ledger): Cryptographic hash chain detects database alteration`
4. `Privilege Escalation: Viewer cannot grant permissions to other users`
5. `Separation of Duties: Admin cannot download confidential document without explicit grant`
6. `Edit Permissions: Viewer with Read permission cannot update or delete document`
7. `Search Isolation: Scoped search returns strictly documents user has permission to see`
8. `Upload Validation: Executables and scripts are strictly rejected`
9. `Upload Validation: Magic byte inspection catches extension spoofing (PHP inside .pdf)`
10. `Upload Validation: Filename sanitization neutralizes path traversal attacks`
11. `Instant Session Invalidation: Suspended user token is rejected on the next request`
12. `API Integration: Full HTTP dispatch of authentication, IDOR blocking, and audit verification`

---

## 6. Architecture & Engineering Write-Up

### What Was Built
- **Zero-Dependency Core**: Pure Node.js 24 + SQLite (`DatabaseSync`) with Write-Ahead Logging (WAL).
- **Cryptographic Security Layer**: Scrypt password hashing with cryptographically random salts, constant-time equality comparisons (`crypto.timingSafeEqual`), and HMAC-SHA256 session claims.
- **Content Inspection Engine**: Buffer-level magic byte detection supporting PDF, PNG, JPEG, DOCX, XLSX, and sanitized text files.
- **Chained Audit Ledger**: Deterministic block serialization linking every log entry to its predecessor via SHA-256.
- **Interactive UI**: Responsive Single-Page Application with real-time role switching, document vault, search filters, permission manager, live audit viewer, and tamper verification badges.

### What Was Deliberately Not Built & Why
- **JWT Permission Claims**: Storing permissions in tokens was deliberately omitted because it creates stale authorization windows that violate Standard 3.
- **S3 / Blob Storage Pre-Signed URLs**: Pre-signed URLs have unrevokable TTLs. TrustVault streams files directly through authenticated endpoints to guarantee instant revocation.
- **In-Memory Post-Query Filtering**: All permission checks are pushed down into SQL queries to prevent side-channel metadata leaks during search.
- **Admin Content Backdoors**: System administrators cannot decrypt or download confidential documents without explicit grants from owners (Zero-Trust Separation of Duties).

### What Is Unfinished / Enterprise Roadmap
- **External Timestamping / WORM Storage**: While the internal SQLite audit chain is mathematically tamper-evident, a physical host root compromise could rewrite the entire SQLite file. In a high-assurance deployment, the head block hash should be periodically committed to an external WORM (Write-Once-Read-Many) ledger (RFC 3161 or public timestamping authority).
- **Dynamic Watermarking**: Rendering viewer-specific watermarks (email + timestamp) onto streamed PDFs to deter physical camera capture of screens.
- **Folder Inheritance**: Currently, permissions are per-document named grants. Folder-based inheritance with explicit overrides represents a natural enterprise extension.
