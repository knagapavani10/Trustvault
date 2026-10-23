import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { initializeDatabase, getDb } from '../src/db/database.js';
import {
  resolveUserAccess,
  grantDocumentPermission,
  revokeDocumentPermission,
  listDocumentPermissions
} from '../src/services/permissionService.js';
import {
  createDocument,
  searchDocuments,
  getDocumentMetadata,
  prepareDocumentDownload,
  updateDocument,
  deleteDocument
} from '../src/services/documentService.js';
import {
  loginUser,
  validateSession,
  setUserActiveStatus,
  registerUser
} from '../src/services/authService.js';
import {
  recordAuditEvent,
  verifyAuditChainIntegrity,
  queryAuditLogs
} from '../src/services/auditService.js';
import { validateFileContent, sanitizeFilename } from '../src/middleware/fileValidator.js';
import { handleApiRequest } from '../src/routes/api.js';

// Clean database before test suite
test.beforeEach(() => {
  initializeDatabase(true);
});

// Helper to simulate HTTP requests to handleApiRequest
function createMockHttp(method, pathStr, { token = null, body = null, headers = {} } = {}) {
  const req = new EventEmitter();
  req.method = method;
  req.url = pathStr;
  req.headers = {
    host: 'trustvault.local',
    ...headers
  };
  if (token) {
    req.headers['authorization'] = `Bearer ${token}`;
  }
  req.socket = { remoteAddress: '127.0.0.1' };

  let responseData = '';
  let responseStatus = 200;
  let responseHeaders = {};

  const res = new EventEmitter();
  res.writeHead = (status, h = {}) => {
    responseStatus = status;
    for (const [k, v] of Object.entries(h)) {
      responseHeaders[k.toLowerCase()] = v;
    }
  };
  res.setHeader = (k, v) => {
    responseHeaders[k.toLowerCase()] = v;
  };
  res.getHeader = (k) => responseHeaders[k.toLowerCase()];
  res.write = (chunk) => {
    responseData += chunk;
    return true;
  };
  res.end = (chunk) => {
    if (chunk) responseData += chunk;
    res.emit('finish');
  };

  const url = new URL(pathStr, 'http://trustvault.local');

  const execute = async () => {
    const apiPromise = handleApiRequest(req, res, url);
    // Push body data if present
    if (body) {
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      req.emit('data', Buffer.from(payload));
    }
    req.emit('end');
    await apiPromise;

    let parsedData = responseData;
    try {
      parsedData = JSON.parse(responseData);
    } catch {}

    return {
      status: responseStatus,
      headers: responseHeaders,
      data: parsedData
    };
  };

  return { execute };
}

// =========================================================================
// TEST SUITE: THE 3 INVIOLABLE STANDARDS
// =========================================================================

test('Standard 1 (Zero-Trust): Charlie (Viewer) cannot reach Bob (Owner) confidential document', async () => {
  const charlie = { id: 'u-viewer-0001', email: 'charlie.viewer@trustvault.local', role: 'viewer' };
  const bobsDocId = 'doc-arch-nextgen';

  // 1. Core permission engine evaluation
  const access = resolveUserAccess(bobsDocId, charlie.id);
  assert.equal(access.canRead, false, 'Charlie must have NO read access to Bob proprietary IP');
  assert.equal(access.canEdit, false, 'Charlie must have NO edit access');
  assert.equal(access.canDelete, false, 'Charlie must have NO delete access');
  assert.equal(access.permissionLevel, 'none');

  // 2. Download enforcement test
  assert.throws(
    () => prepareDocumentDownload(bobsDocId, charlie, '192.168.1.50', 'TestAgent/1.0'),
    (err) => {
      assert.equal(err.statusCode, 403);
      assert.match(err.message, /Access Denied/i);
      return true;
    },
    'Server must throw 403 Forbidden on unauthorized download attempt'
  );

  // 3. Verify refusal is permanently recorded in the cryptographic audit ledger
  const db = getDb();
  const deniedRecord = db.prepare(`
    SELECT * FROM audit_ledger 
    WHERE resource_id = ? AND actor_email = ? AND status = 'DENIED'
    ORDER BY id DESC LIMIT 1
  `).get(bobsDocId, charlie.email);

  assert.ok(deniedRecord, 'Attempted unauthorized access MUST be permanently recorded in audit ledger');
  assert.equal(deniedRecord.action, 'ACCESS_DENIED');
  assert.equal(deniedRecord.status, 'DENIED');
});

test('Standard 3 (Immediate Revocation): Revoking access takes effect immediately', () => {
  const alice = { id: 'u-owner-0001', email: 'alice.owner@trustvault.local', role: 'owner' };
  const charlie = { id: 'u-viewer-0001', email: 'charlie.viewer@trustvault.local', role: 'viewer' };
  const salaryDocId = 'doc-salary-2026';

  // Step 1: Charlie has no access initially
  const accessInitial = resolveUserAccess(salaryDocId, charlie.id);
  assert.equal(accessInitial.canRead, false);

  // Step 2: Alice grants Charlie "read" permission
  const grantResult = grantDocumentPermission({
    documentId: salaryDocId,
    actor: alice,
    targetEmail: charlie.email,
    permissionLevel: 'read',
    ipAddress: '10.0.0.1',
    userAgent: 'AliceBrowser'
  });
  assert.equal(grantResult.success, true);

  // Step 3: Charlie now has valid read access
  const accessGranted = resolveUserAccess(salaryDocId, charlie.id);
  assert.equal(accessGranted.canRead, true, 'Charlie should now have read access');
  assert.equal(accessGranted.permissionLevel, 'read');

  // Step 4: Alice REVOKES Charlie's permission
  const revokeResult = revokeDocumentPermission({
    documentId: salaryDocId,
    actor: alice,
    targetUserId: charlie.id,
    ipAddress: '10.0.0.1',
    userAgent: 'AliceBrowser'
  });
  assert.equal(revokeResult.success, true);

  // Step 5: Immediate verification - the very next microsecond query MUST fail!
  const accessRevoked = resolveUserAccess(salaryDocId, charlie.id);
  assert.equal(accessRevoked.canRead, false, 'Charlie must be immediately blocked from reading');
  assert.equal(accessRevoked.permissionLevel, 'none');

  // Download attempt immediately after revocation must throw 403
  assert.throws(
    () => prepareDocumentDownload(salaryDocId, charlie, '10.0.0.2', 'CharlieBrowser'),
    (err) => err.statusCode === 403
  );
});

test('Standard 2 (Tamper-Evident Ledger): Cryptographic hash chain detects database alteration', () => {
  // 1. Check ledger integrity on pristine chain
  const pristineCheck = verifyAuditChainIntegrity();
  assert.equal(pristineCheck.valid, true, 'Pristine ledger must pass 100% integrity check');
  assert.ok(pristineCheck.totalBlocks >= 1);

  // 2. Simulate malicious insider database modification
  const db = getDb();
  const rowToTamper = db.prepare('SELECT id, details, hash FROM audit_ledger ORDER BY id DESC LIMIT 1').get();

  // Attack: Change audit details in SQL
  db.prepare("UPDATE audit_ledger SET details = '{\"tampered\": true, \"crime\": \"covered\"}' WHERE id = ?")
    .run(rowToTamper.id);

  // 3. Cryptographic integrity check MUST fail and pinpoint the tampered block ID
  const tamperedCheck = verifyAuditChainIntegrity();
  assert.equal(tamperedCheck.valid, false, 'Tampered ledger MUST fail integrity verification');
  assert.equal(tamperedCheck.brokenBlockId, rowToTamper.id, 'Must pinpoint exact block ID tampered');
  assert.match(tamperedCheck.error, /Tampering detected|Hash chain broken/i);

  // 4. Restore original details and verify chain recovers
  db.prepare('UPDATE audit_ledger SET details = ? WHERE id = ?').run(rowToTamper.details, rowToTamper.id);
  const recoveredCheck = verifyAuditChainIntegrity();
  assert.equal(recoveredCheck.valid, true, 'Chain returns to valid state once restored');
});

// =========================================================================
// TEST SUITE: PRIVILEGE ESCALATION & AUTHORIZATION BOUNDARIES
// =========================================================================

test('Privilege Escalation: Viewer cannot grant permissions to other users', () => {
  const charlie = { id: 'u-viewer-0001', email: 'charlie.viewer@trustvault.local', role: 'viewer' };
  const docId = 'doc-audit-q3';

  assert.throws(
    () => grantDocumentPermission({
      documentId: docId,
      actor: charlie,
      targetEmail: 'dave.viewer@trustvault.local',
      permissionLevel: 'read',
      ipAddress: '127.0.0.1',
      userAgent: 'Test'
    }),
    (err) => {
      assert.equal(err.statusCode, 403);
      assert.match(err.message, /Only the document owner can grant permissions/i);
      return true;
    }
  );
});

test('Separation of Duties: Admin cannot download confidential document without explicit grant', () => {
  const admin = { id: 'u-admin-0001', email: 'admin@trustvault.local', role: 'admin' };
  const salaryDocId = 'doc-salary-2026';

  const access = resolveUserAccess(salaryDocId, admin.id);
  assert.equal(access.canRead, false, 'Admin has no implicit read access to confidential employee salary doc');

  assert.throws(
    () => prepareDocumentDownload(salaryDocId, admin, '127.0.0.1', 'AdminConsole'),
    (err) => err.statusCode === 403
  );
});

test('Edit Permissions: Viewer with Read permission cannot update or delete document', () => {
  const charlie = { id: 'u-viewer-0001', email: 'charlie.viewer@trustvault.local', role: 'viewer' };
  const docId = 'doc-audit-q3'; // Charlie has read permission

  // Cannot update
  assert.throws(
    () => updateDocument({
      documentId: docId,
      actor: charlie,
      title: 'Hacked Title',
      ipAddress: '127.0.0.1',
      userAgent: 'Test'
    }),
    (err) => {
      assert.equal(err.statusCode, 403);
      assert.match(err.message, /need Edit permission/i);
      return true;
    }
  );

  // Cannot delete
  assert.throws(
    () => deleteDocument(docId, charlie, '127.0.0.1', 'Test'),
    (err) => {
      assert.equal(err.statusCode, 403);
      assert.match(err.message, /Only the document owner can delete/i);
      return true;
    }
  );
});

test('Search Isolation: Scoped search returns strictly documents user has permission to see', () => {
  const dave = { id: 'u-viewer-0002', email: 'dave.viewer@trustvault.local', role: 'viewer' };
  const alice = { id: 'u-owner-0001', email: 'alice.owner@trustvault.local', role: 'owner' };

  // Dave has no grants seeded
  const daveResults = searchDocuments(dave, {});
  assert.equal(daveResults.length, 0, 'Dave must see 0 documents');

  // Alice owns 2 documents (Salary Review and Q3 Audit)
  const aliceResults = searchDocuments(alice, {});
  assert.equal(aliceResults.length, 2, 'Alice must see both of her owned documents');

  // Dave searches specifically by keyword "Salary"
  const searchLeakageTest = searchDocuments(dave, { search: 'Salary' });
  assert.equal(searchLeakageTest.length, 0, 'Keyword search must not leak existence of unauthorized files');
});

// =========================================================================
// TEST SUITE: UPLOAD VALIDATION & MALICIOUS INPUTS
// =========================================================================

test('Upload Validation: Executables and scripts are strictly rejected', () => {
  const maliciousSh = Buffer.from('#!/bin/bash\nrm -rf /');
  const resSh = validateFileContent(maliciousSh, 'malicious.sh');
  assert.equal(resSh.valid, false);
  assert.match(resSh.error, /strictly forbidden/i);

  const maliciousExe = Buffer.from('MZ\x90\x00\x03\x00\x00\x00');
  const resExe = validateFileContent(maliciousExe, 'trojan.exe');
  assert.equal(resExe.valid, false);
});

test('Upload Validation: Magic byte inspection catches extension spoofing (PHP inside .pdf)', () => {
  const fakePdfContent = Buffer.from('<?php echo "evil"; ?>');
  const result = validateFileContent(fakePdfContent, 'invoice.pdf');
  assert.equal(result.valid, false, 'File with PDF extension but PHP magic bytes must be rejected');
});

test('Upload Validation: Filename sanitization neutralizes path traversal attacks', () => {
  const dangerousName = '../../../../etc/shadow';
  const clean = sanitizeFilename(dangerousName);
  assert.ok(!clean.includes('/'), 'Must not contain forward slashes');
  assert.ok(!clean.includes('\\'), 'Must not contain backslashes');
  assert.ok(!clean.includes('..'), 'Must not contain double dots');
  assert.equal(clean, 'shadow');
});

// =========================================================================
// TEST SUITE: INSTANT SESSION & ACCOUNT REVOCATION
// =========================================================================

test('Instant Session Invalidation: Suspended user token is rejected on the next request', () => {
  const admin = { id: 'u-admin-0001', email: 'admin@trustvault.local', role: 'admin' };
  
  // 1. Charlie logs in and receives a token
  const auth = loginUser({
    email: 'charlie.viewer@trustvault.local',
    password: 'CharliePass123!',
    ipAddress: '127.0.0.1',
    userAgent: 'Test'
  });
  assert.ok(auth.token);

  // 2. Token is initially valid
  const sessionActive = validateSession(auth.token);
  assert.ok(sessionActive);
  assert.equal(sessionActive.email, 'charlie.viewer@trustvault.local');

  // 3. Admin SUSPENDS Charlie's account
  setUserActiveStatus('u-viewer-0001', false, admin, '127.0.0.1', 'AdminConsole');

  // 4. Existing token MUST BE REJECTED IMMEDIATELY without waiting for JWT TTL!
  const sessionRevoked = validateSession(auth.token);
  assert.equal(sessionRevoked, null, 'Revoked user session token must fail validation immediately');
});

// =========================================================================
// TEST SUITE: COMPLETE HTTP API DISPATCH INTEGRATION
// =========================================================================

test('API Integration: Full HTTP dispatch of authentication, IDOR blocking, and audit verification', async () => {
  // 1. Login via HTTP API
  const loginMock = createMockHttp('POST', '/api/auth/login', {
    body: { email: 'charlie.viewer@trustvault.local', password: 'CharliePass123!' }
  });
  const loginRes = await loginMock.execute();
  assert.equal(loginRes.status, 200);
  const token = loginRes.data.token;

  // 2. Unauthorized download attempt via HTTP API (IDOR Test)
  const idorMock = createMockHttp('GET', '/api/documents/doc-arch-nextgen/download', { token });
  const idorRes = await idorMock.execute();
  assert.equal(idorRes.status, 403);
  assert.match(idorRes.data.error, /Access Denied/i);

  // 3. Audit chain verification via HTTP API
  const verifyMock = createMockHttp('GET', '/api/audit/verify', { token });
  const verifyRes = await verifyMock.execute();
  assert.equal(verifyRes.status, 200);
  assert.equal(verifyRes.data.verification.valid, true);
});

test('User Registration: Enforces email format, password strength, and issues valid session', async () => {
  // Test invalid email
  const badEmailMock = createMockHttp('POST', '/api/auth/register', {
    body: { name: 'Test', email: 'not-an-email', password: 'ValidPassword123!', role: 'viewer' }
  });
  const badEmailRes = await badEmailMock.execute();
  assert.equal(badEmailRes.status, 400);
  assert.match(badEmailRes.data.error, /valid email/i);

  // Test weak password (<8 chars)
  const weakPassMock = createMockHttp('POST', '/api/auth/register', {
    body: { name: 'Test', email: 'valid@test.com', password: '123', role: 'viewer' }
  });
  const weakPassRes = await weakPassMock.execute();
  assert.equal(weakPassRes.status, 400);
  assert.match(weakPassRes.data.error, /at least 8 characters/i);

  // Test successful registration
  const goodMock = createMockHttp('POST', '/api/auth/register', {
    body: { name: 'Sarah Connor', email: 'sarah.connor@test.com', password: 'TerminatorPass123!', role: 'owner' }
  });
  const goodRes = await goodMock.execute();
  assert.equal(goodRes.status, 201);
  assert.ok(goodRes.data.token);
  assert.equal(goodRes.data.user.email, 'sarah.connor@test.com');
  assert.equal(goodRes.data.user.role, 'owner');
});

test('Document Viewing: GET /api/documents/:id/view enforces identical zero-trust checks', async () => {
  const charlieToken = (await loginUser({
    email: 'charlie.viewer@trustvault.local',
    password: 'CharliePass123!',
    ipAddress: '127.0.0.1',
    userAgent: 'Test'
  })).token;

  // View Bob's unauthorized doc -> 403 Forbidden
  const viewDeniedMock = createMockHttp('GET', '/api/documents/doc-arch-nextgen/view', { token: charlieToken });
  const viewDeniedRes = await viewDeniedMock.execute();
  assert.equal(viewDeniedRes.status, 403);
  assert.match(viewDeniedRes.data.error, /Access Denied/i);

  // View Alice's audit doc (Charlie is granted) -> 200 OK
  const viewAllowedMock = createMockHttp('GET', '/api/documents/doc-audit-q3/view', { token: charlieToken });
  const viewAllowedRes = await viewAllowedMock.execute();
  assert.equal(viewAllowedRes.status, 200);
  assert.equal(viewAllowedRes.headers['content-disposition'], 'inline; filename="Q3_External_Audit_Working_Papers.pdf"');
});
