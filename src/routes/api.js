import path from 'node:path';
import fs from 'node:fs';
import { loginUser, validateSession, setUserActiveStatus, registerUser } from '../services/authService.js';
import {
  createDocument,
  searchDocuments,
  getDocumentMetadata,
  prepareDocumentDownload,
  updateDocument,
  deleteDocument
} from '../services/documentService.js';
import {
  grantDocumentPermission,
  revokeDocumentPermission,
  listDocumentPermissions
} from '../services/permissionService.js';
import {
  queryAuditLogs,
  verifyAuditChainIntegrity,
  recordAuditEvent
} from '../services/auditService.js';
import { parseMultipartFormData } from '../middleware/multipart.js';
import { getDb } from '../db/database.js';

/**
 * Helper to extract client IP and User Agent
 */
export function getClientContext(req) {
  const ipAddress = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';
  return { ipAddress, userAgent };
}

/**
 * Extracts and verifies bearer token, returning authenticated user
 */
export function authenticateRequest(req) {
  const authHeader = req.headers['authorization'] || '';
  if (!authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.slice(7).trim();
  return validateSession(token);
}

/**
 * Main API Route Handler
 */
export async function handleApiRequest(req, res, url) {
  const method = req.method;
  const pathname = url.pathname;
  const { ipAddress, userAgent } = getClientContext(req);

  // Helper to send JSON responses
  const sendJson = (statusCode, data) => {
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store, no-cache, must-revalidate'
    });
    res.end(JSON.stringify(data));
  };

  // Helper to read JSON request body
  const readJsonBody = async () => {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
        if (body.length > 1024 * 1024) { // 1MB limit for JSON bodies
          req.destroy();
          reject(new Error('Request body too large'));
        }
      });
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch {
          reject(new Error('Invalid JSON format'));
        }
      });
      req.on('error', reject);
    });
  };

  try {
    // -------------------------------------------------------------
    // AUTHENTICATION ENDPOINTS
    // -------------------------------------------------------------

    // POST /api/auth/register - Beginner-friendly self-registration
    if (method === 'POST' && pathname === '/api/auth/register') {
      const body = await readJsonBody();
      const { name, email, password, role } = body;

      // Input Validation
      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return sendJson(400, { error: 'Full name is required.' });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!email || !emailRegex.test(email.trim())) {
        return sendJson(400, { error: 'A valid email address is required.' });
      }

      if (!password || typeof password !== 'string' || password.length < 8) {
        return sendJson(400, { error: 'Password must be at least 8 characters long.' });
      }

      const selectedRole = role === 'owner' ? 'owner' : 'viewer';

      // Register the new user
      const newUser = registerUser({
        email: email.trim().toLowerCase(),
        password,
        name: name.trim(),
        role: selectedRole,
        creator: null,
        ipAddress,
        userAgent
      });

      // Automatically issue session token so the new user is logged in immediately
      const loginResult = loginUser({
        email: email.trim().toLowerCase(),
        password,
        ipAddress,
        userAgent
      });

      return sendJson(201, {
        message: 'Account registered successfully.',
        token: loginResult.token,
        user: loginResult.user
      });
    }

    // POST /api/auth/login
    if (method === 'POST' && pathname === '/api/auth/login') {
      const body = await readJsonBody();
      if (!body.email || !body.password) {
        return sendJson(400, { error: 'Email and password are required.' });
      }
      const result = loginUser({
        email: body.email.trim().toLowerCase(),
        password: body.password,
        ipAddress,
        userAgent
      });
      return sendJson(200, result);
    }

    // Require authentication for all subsequent endpoints
    const currentUser = authenticateRequest(req);
    if (!currentUser) {
      // Record unauthenticated attempt
      recordAuditEvent({
        actor: null,
        action: 'ACCESS_DENIED',
        resourceType: 'auth',
        resourceId: null,
        ipAddress,
        userAgent,
        status: 'DENIED',
        details: { path: pathname, method, reason: 'Missing, invalid, or revoked session token' }
      });
      return sendJson(401, { error: 'Authentication required. Invalid or expired token.' });
    }

    // GET /api/auth/me
    if (method === 'GET' && pathname === '/api/auth/me') {
      return sendJson(200, { user: currentUser });
    }

    // -------------------------------------------------------------
    // DOCUMENT ENDPOINTS
    // -------------------------------------------------------------

    // GET /api/documents - Search and List
    if (method === 'GET' && pathname === '/api/documents') {
      const search = url.searchParams.get('search') || '';
      const category = url.searchParams.get('category') || '';
      const ownerId = url.searchParams.get('ownerId') || '';
      const startDate = url.searchParams.get('startDate') || '';
      const endDate = url.searchParams.get('endDate') || '';

      const docs = searchDocuments(currentUser, { search, category, ownerId, startDate, endDate });
      return sendJson(200, { documents: docs });
    }

    // POST /api/documents - Upload Document (Owners and Admins)
    if (method === 'POST' && pathname === '/api/documents') {
      if (currentUser.role === 'viewer') {
        recordAuditEvent({
          actor: currentUser,
          action: 'ACCESS_DENIED',
          resourceType: 'document',
          ipAddress,
          userAgent,
          status: 'DENIED',
          details: { reason: 'Viewers cannot create or upload new documents' }
        });
        return sendJson(403, { error: 'Access Denied: Viewers do not have permission to upload new documents.' });
      }

      const parsed = await parseMultipartFormData(req);
      const title = parsed.fields.title;
      const category = parsed.fields.category;
      const description = parsed.fields.description;
      const file = parsed.files.file;

      if (!file) {
        return sendJson(400, { error: 'No file provided in upload.' });
      }

      const newDoc = await createDocument({
        owner: currentUser,
        title,
        category,
        description,
        fileBuffer: file.buffer,
        originalName: file.originalName,
        ipAddress,
        userAgent
      });

      return sendJson(201, { document: newDoc });
    }

    // Check for document ID in path: /api/documents/:id
    const docMatch = pathname.match(/^\/api\/documents\/([^/]+)$/);
    if (docMatch) {
      const docId = docMatch[1];

      // GET /api/documents/:id - Get Document Metadata
      if (method === 'GET') {
        const metadata = getDocumentMetadata(docId, currentUser, ipAddress, userAgent);
        return sendJson(200, { document: metadata });
      }

      // PUT /api/documents/:id - Update Document
      if (method === 'PUT') {
        const body = await readJsonBody();
        const updated = updateDocument({
          documentId: docId,
          actor: currentUser,
          title: body.title,
          category: body.category,
          description: body.description,
          ipAddress,
          userAgent
        });
        return sendJson(200, updated);
      }

      // DELETE /api/documents/:id - Delete Document
      if (method === 'DELETE') {
        const deleted = deleteDocument(docId, currentUser, ipAddress, userAgent);
        return sendJson(200, deleted);
      }
    }

    // GET /api/documents/:id/download - Secure Authorized Download Stream
    const downloadMatch = pathname.match(/^\/api\/documents\/([^/]+)\/download$/);
    if (method === 'GET' && downloadMatch) {
      const docId = downloadMatch[1];
      const downloadInfo = prepareDocumentDownload(docId, currentUser, ipAddress, userAgent);

      const stream = fs.createReadStream(downloadInfo.filePath);
      res.writeHead(200, {
        'Content-Type': downloadInfo.mimeType,
        'Content-Length': downloadInfo.fileSize,
        'Content-Disposition': `attachment; filename="${downloadInfo.originalName}"`,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
        'Pragma': 'no-cache'
      });
      stream.pipe(res);
      return;
    }

    // GET /api/documents/:id/view - Secure Authorized In-Browser Viewing Stream
    const viewMatch = pathname.match(/^\/api\/documents\/([^/]+)\/view$/);
    if (method === 'GET' && viewMatch) {
      const docId = viewMatch[1];
      const viewInfo = prepareDocumentDownload(docId, currentUser, ipAddress, userAgent);

      const stream = fs.createReadStream(viewInfo.filePath);
      res.writeHead(200, {
        'Content-Type': viewInfo.mimeType,
        'Content-Length': viewInfo.fileSize,
        'Content-Disposition': `inline; filename="${viewInfo.originalName}"`,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
        'Pragma': 'no-cache'
      });
      stream.pipe(res);
      return;
    }

    // -------------------------------------------------------------
    // PERMISSIONS ENDPOINTS
    // -------------------------------------------------------------

    // GET /api/documents/:id/permissions - List Permissions
    const permListMatch = pathname.match(/^\/api\/documents\/([^/]+)\/permissions$/);
    if (method === 'GET' && permListMatch) {
      const docId = permListMatch[1];
      const perms = listDocumentPermissions(docId, currentUser);
      return sendJson(200, { permissions: perms });
    }

    // POST /api/documents/:id/permissions - Grant Permission
    if (method === 'POST' && permListMatch) {
      const docId = permListMatch[1];
      const body = await readJsonBody();
      if (!body.targetEmail || !body.permissionLevel) {
        return sendJson(400, { error: 'targetEmail and permissionLevel ("read"|"edit") are required.' });
      }

      const result = grantDocumentPermission({
        documentId: docId,
        actor: currentUser,
        targetEmail: body.targetEmail,
        permissionLevel: body.permissionLevel,
        ipAddress,
        userAgent
      });
      return sendJson(200, result);
    }

    // DELETE /api/documents/:id/permissions/:userId - Revoke Permission Immediately
    const permRevokeMatch = pathname.match(/^\/api\/documents\/([^/]+)\/permissions\/([^/]+)$/);
    if (method === 'DELETE' && permRevokeMatch) {
      const docId = permRevokeMatch[1];
      const targetUserId = permRevokeMatch[2];

      const result = revokeDocumentPermission({
        documentId: docId,
        actor: currentUser,
        targetUserId,
        ipAddress,
        userAgent
      });
      return sendJson(200, result);
    }

    // -------------------------------------------------------------
    // AUDIT LEDGER ENDPOINTS
    // -------------------------------------------------------------

    // GET /api/audit - Query Audit Trail
    if (method === 'GET' && pathname === '/api/audit') {
      const action = url.searchParams.get('action') || '';
      const status = url.searchParams.get('status') || '';
      const resourceId = url.searchParams.get('resourceId') || '';

      const logs = queryAuditLogs(currentUser, { action, status, resourceId });
      return sendJson(200, { logs });
    }

    // GET /api/audit/verify - Cryptographic Hash Chain Verification
    if (method === 'GET' && pathname === '/api/audit/verify') {
      // Available to all authenticated users for verifiable auditability
      const verification = verifyAuditChainIntegrity();
      return sendJson(200, { verification });
    }

    // -------------------------------------------------------------
    // ADMINISTRATIVE ENDPOINTS
    // -------------------------------------------------------------

    // GET /api/admin/users - List Users (For Admin or Owners seeking to share)
    if (method === 'GET' && pathname === '/api/admin/users') {
      const db = getDb();
      // Safe projection excluding password hashes and salts
      const users = db.prepare(`
        SELECT id, email, name, role, is_active, created_at
        FROM users
        ORDER BY name ASC
      `).all();
      return sendJson(200, { users });
    }

    // PUT /api/admin/users/:id/status - Admin Suspend/Activate User
    const userStatusMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/status$/);
    if (method === 'PUT' && userStatusMatch) {
      if (currentUser.role !== 'admin') {
        recordAuditEvent({
          actor: currentUser,
          action: 'ACCESS_DENIED',
          resourceType: 'user',
          resourceId: userStatusMatch[1],
          ipAddress,
          userAgent,
          status: 'DENIED',
          details: { reason: 'Only an administrator can modify user account status' }
        });
        return sendJson(403, { error: 'Access Denied: Only administrators can modify user account status.' });
      }

      const targetId = userStatusMatch[1];
      const body = await readJsonBody();
      const isActive = Boolean(body.isActive);

      const result = setUserActiveStatus(targetId, isActive, currentUser, ipAddress, userAgent);
      return sendJson(200, result);
    }

    // Not Found
    return sendJson(404, { error: `Endpoint not found: ${method} ${pathname}` });

  } catch (err) {
    const statusCode = err.statusCode || 500;
    console.error(`API Error [${method} ${pathname}]:`, err.message);
    return sendJson(statusCode, { error: err.message || 'Internal Server Error' });
  }
}
