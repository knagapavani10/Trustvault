# TrustVault: Engineering Prompts, AI Critique & Security Corrections (PROMPTS.md)

This log records five critical engineering interactions with AI coding tools during the development of TrustVault, detailing what was asked, what the AI proposed, the specific security vulnerabilities identified in the AI's proposal, and the hardened architectural decisions implemented instead.

---

## Entry 1: 2026-10-18 — Stale JWT Claims vs. Immediate Revocation (Standard 3)

### What Was Asked
> *"Design an authorization mechanism in Node.js for granting and revoking document access (read and edit) to named users. How should we issue access tokens so the frontend can download documents securely?"*

### What the AI Produced
The AI suggested embedding document permissions directly into a signed JSON Web Token (JWT) with a 15-minute expiration:
```javascript
// AI PROPOSED CODE (VULNERABLE)
const token = jwt.sign({
  userId: user.id,
  permissions: {
    'doc-salary-2026': 'read',
    'doc-audit-q3': 'edit'
  }
}, SECRET_KEY, { expiresIn: '15m' });

// Middleware:
function verifyDocAccess(docId, level) {
  return (req, res, next) => {
    const perm = req.user.permissions[docId];
    if (perm && (perm === level || perm === 'edit')) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}
```

### What Was Wrong With It (Specifically)
This design **catastrophically violates Standard 3: Taking access away works immediately**.
1. If Document Owner Alice grants Viewer Charlie access at 09:00, Charlie receives a 15-minute token.
2. If Alice discovers a breach or terminates the contract at 09:02 and clicks "Revoke", Charlie's existing token remains cryptographically valid until 09:15.
3. For 13 full minutes, Charlie can continue downloading confidential documents and exfiltrating trade secrets, and the server middleware will approve it because it only checks the stale claims inside the token.

### What Was Done Instead
We rejected caching permissions in tokens entirely. In TrustVault:
- The token holds **identity only** (`sub`, `tokenVersion`), with zero document grants embedded.
- Every single download, read, and edit request performs a **real-time synchronous database query** (`resolveUserAccess()` in `src/services/permissionService.js`):
```javascript
// TRUSTVAULT HARDENED IMPLEMENTATION
export function resolveUserAccess(documentId, userId) {
  const db = getDb();
  const doc = db.prepare('SELECT id, owner_id FROM documents WHERE id = ? AND is_deleted = 0').get(documentId);
  if (!doc) return null;
  if (doc.owner_id === userId) return { canRead: true, canEdit: true, canDelete: true, isOwner: true };

  // Query live, unrevoked database grant
  const grant = db.prepare(`
    SELECT permission_level FROM document_permissions
    WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL
  `).get(documentId, userId);

  return {
    canRead: Boolean(grant),
    canEdit: grant?.permission_level === 'edit',
    canDelete: false
  };
}
```
When Alice clicks "Revoke", the database marks `revoked_at = NOW()`. Charlie's next request 1 millisecond later evaluates `revoked_at IS NULL` as false and is rejected immediately.
* **Code Reference**: `src/services/permissionService.js` (lines 18–68); automated in `tests/security.test.js`.

---

## Entry 2: 2026-10-19 — Flawed Audit Logging vs. Cryptographic Hash Chaining (Standard 2)

### What Was Asked
> *"Implement an audit log for our document vault that tracks uploads, downloads, deletions, and access changes. Make sure it stores actor, action, resource, timestamp, and IP."*

### What Was Produced
The AI produced a standard CRUD logging table and insertion helper:
```javascript
// AI PROPOSED CODE (VULNERABLE)
db.exec(`
  CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    action TEXT,
    resource_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

function logAction(userId, action, resourceId) {
  db.prepare('INSERT INTO audit_logs (user_id, action, resource_id) VALUES (?, ?, ?)')
    .run(userId, action, resourceId);
}
```

### What Was Wrong With It (Specifically)
This design **fails Standard 2: An audit trail that can be quietly altered is not evidence**.
1. An attacker who gains access to the database (or a rogue DBA/insider) can execute:
   `UPDATE audit_logs SET user_id = 'innocent_user' WHERE action = 'DOCUMENT_DOWNLOAD'`
   or simply `DELETE FROM audit_logs WHERE user_id = 'compromised_account'` to erase their tracks.
2. The honest answer to the regulator or customer would be "we cannot prove this wasn't altered."
3. Furthermore, the AI only logged successful operations. When someone was denied access, no log was written, making it impossible to detect unauthorized reconnaissance or brute force probes.

### What Was Done Instead
We engineered an **Immutable Cryptographic Hash-Chained Audit Ledger** (`src/services/auditService.js`):
1. Every audit entry is treated as a block in a cryptographic hash chain.
2. Each block includes `prev_hash` (the SHA-256 hash of the immediately preceding block), rooted in a genesis hash (`0` repeated 64 times).
3. The block hash is computed as:
   $$\text{hash} = \text{SHA256}(\text{id} \parallel \text{prev\_hash} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{resource} \parallel \text{status} \parallel \text{details})$$
4. We implemented `verifyAuditChainIntegrity()`, which mathematically recomputes the chain from block #1 to Head. If any past entry is modified or deleted, the recomputed hash diverges and the system pinpoints the exact tampered block ID.
5. All refused probes (`ACCESS_DENIED`) are explicitly audited with actor IP and attempted action.
* **Code Reference**: `src/services/auditService.js` (lines 20–185); verified in `tests/security.test.js`.

---

## Entry 3: 2026-10-20 — In-Memory Search Filtering vs. Push-Down SQL Scoping

### What Was Asked
> *"Write a document search endpoint that lets users search by title, category, and date range."*

### What Was Produced
The AI wrote a query that selected all documents from the database and filtered permissions in JavaScript memory:
```javascript
// AI PROPOSED CODE (VULNERABLE)
app.get('/api/documents', (req, res) => {
  const allDocs = db.prepare('SELECT * FROM documents WHERE title LIKE ?').all(`%${req.query.q}%`);
  // Filter in memory:
  const allowed = allDocs.filter(doc => hasAccess(req.user.id, doc.id));
  res.json(allowed);
});
```

### What Was Wrong With It (Specifically)
This pattern causes **Information Disclosure & Side-Channel Leaks**:
1. Loading all confidential documents into application memory violates the Principle of Least Privilege and creates severe performance degradation as the vault scales.
2. More dangerously, if query pagination or aggregation (`COUNT(*)`) was implemented using the AI's pattern, the server would leak the total count or existence of confidential documents an unauthorized user was never granted access to see.
3. If database query logging was enabled in production, user queries for confidential terms would match documents they should not know exist.

### What Was Done Instead
We implemented **Push-Down Authorization Scoping** in `src/services/documentService.js`:
The SQL query itself restricts results strictly to documents the user owns or has an active, unrevoked grant on:
```sql
SELECT d.*, ...
FROM documents d
LEFT JOIN document_permissions p 
       ON p.document_id = d.id AND p.user_id = :userId AND p.revoked_at IS NULL
WHERE d.is_deleted = 0
  AND (d.owner_id = :userId OR p.user_id IS NOT NULL)
  AND (:search IS NULL OR d.title LIKE :search OR d.original_name LIKE :search)
```
If Viewer Dave searches for "Salary" or "Acquisition", the SQL engine returns 0 rows. Zero metadata is leaked across tenants or roles.
* **Code Reference**: `src/services/documentService.js` (`searchDocuments`, lines 95–160); verified in `tests/security.test.js`.

---

## Entry 4: 2026-10-21 — Client-Reported MIME Validation vs. Magic Bytes Inspection

### What Was Asked
> *"Add file upload validation so only PDFs and office documents can be uploaded to the vault."*

### What Was Produced
The AI relied on client-supplied headers and file extension checks:
```javascript
// AI PROPOSED CODE (VULNERABLE)
const fileFilter = (req, file, cb) => {
  const allowedMimes = ['application/pdf', 'application/msword'];
  if (allowedMimes.includes(file.mimetype) && file.originalname.endsWith('.pdf')) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'));
  }
};
```

### What Was Wrong With It (Specifically)
This is a **classic file upload bypass vulnerability (CWE-434)**:
1. `file.mimetype` is an HTTP header sent by the client (`Content-Type: application/pdf`). An attacker can send an arbitrary binary executable or PHP web shell and set the header to `application/pdf`.
2. `file.originalname` is also user-controlled. An attacker can name their payload `exploit.php.pdf` or `shell.pdf`.
3. The AI's code stored the file on disk using `file.originalname`, introducing **Path Traversal (`../../etc/shadow`)** risks.

### What Was Done Instead
We built a hardened validation pipeline in `src/middleware/fileValidator.js`:
1. **Magic Bytes Inspection**: The server reads the actual binary header bytes of the buffer:
   - PDF must start with `%PDF-` (`0x25, 0x50, 0x44, 0x46`).
   - PNG must start with `\x89PNG\r\n\x1a\n`.
   - Text files are checked for null bytes (`\x00`) and scanned for embedded script tags (`<script>`, `javascript:`).
2. **Path Traversal Neutralization**: Filenames are sanitized via `sanitizeFilename()` which strips path separators, null bytes, and control characters.
3. **Randomized Storage Keys**: Files are written to disk under a cryptographically random UUID (`vault_${crypto.randomUUID()}.${ext}`) outside the web root.
* **Code Reference**: `src/middleware/fileValidator.js` (lines 1–130); verified in `tests/security.test.js`.

---

## Entry 5: 2026-10-22 — Admin Superuser God-Mode vs. Separation of Duties

### What Was Asked
> *"Implement access control middleware. How should Administrator permissions work for viewing documents?"*

### What Was Produced
The AI provided standard RBAC middleware that gave administrators automatic bypass permissions:
```javascript
// AI PROPOSED CODE (SECURITY FLAW)
function canAccessDocument(user, document) {
  // Admin can access everything
  if (user.role === 'admin') {
    return true;
  }
  return document.owner_id === user.id || hasGrant(user.id, document.id);
}
```

### What Was Wrong With It (Specifically)
This introduces an **Admin Overreach & Confidentiality Failure**:
1. The problem statement explicitly establishes: *"Every company shares confidential documents: salary letters with employees, contracts with customers, drawings with external partners, audit papers with regulators."*
2. If an IT administrator can view executive salary sheets, medical records, or proprietary trade secrets simply because their role is `admin`, the platform fails Zero-Trust confidentiality.
3. System administrators must have governance authority (user lifecycle, audit oversight, cryptographic verification), but **never automatic content decryption/download access** without an explicit grant from the document owner.

### What Was Done Instead
We enforced **Strict Separation of Duties**:
- In `src/services/permissionService.js` and `src/services/documentService.js`, `admin` status does NOT grant read or download access to confidential documents.
- If an admin attempts to download Alice's salary document without an explicit grant, the server rejects the request with HTTP 403 Forbidden and logs an `ACCESS_DENIED` security incident in the audit ledger.
- Admins can manage accounts and verify audit integrity, but confidential document payloads remain private to authorized parties.
* **Code Reference**: `src/services/permissionService.js` (`resolveUserAccess`, lines 35–65); verified in `tests/security.test.js`.

---

## 6. Reusable Prompts & System Instructions Used Across the Project

To maintain security discipline, the following prompt prefix was reused for all architectural code generation prompts:

```text
[SYSTEM DIRECTIVE: ZERO-TRUST SECURITY ENFORCEMENT]
You are a principal security engineer designing TrustVault. You must follow these inviolable rules:
1. SERVER-AUTHORITATIVE: Never trust client headers, client claims, or UI state. All authorization is evaluated in real-time against current database state.
2. INSTANT REVOCATION: Revoking a grant must take effect on the very next millisecond request. Never cache grants in JWT tokens or long-lived presigned URLs.
3. AUDIT IMMUTABILITY: All state changes and refused access attempts must be recorded in a SHA-256 hash-chained ledger. Provide mathematical verification that catches any row modification or deletion.
4. ZERO DEPENDENCY FOOTPRINT: Use native Node.js built-in modules (node:http, node:sqlite, node:crypto, node:fs, node:test) to prevent supply chain vulnerabilities.
```
