import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getDb, STORAGE_DIR } from '../db/database.js';
import { resolveUserAccess } from './permissionService.js';
import { recordAuditEvent } from './auditService.js';
import { validateFileContent, sanitizeFilename } from '../middleware/fileValidator.js';
import { computeFileHash } from './cryptoService.js';

/**
 * Creates and stores a new confidential document with content validation.
 */
export async function createDocument({
  owner,
  title,
  category,
  description = '',
  isConfidential = true,
  fileBuffer,
  originalName,
  ipAddress,
  userAgent
}) {
  const db = getDb();

  // 1. Content validation via magic bytes
  const validation = validateFileContent(fileBuffer, originalName);
  if (!validation.valid) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  // 2. Sanitize filename
  const cleanOriginalName = sanitizeFilename(originalName);
  const ext = path.extname(cleanOriginalName);

  // 3. Isolated disk storage under cryptographically secure UUID
  const docId = `doc-${crypto.randomUUID()}`;
  const storageFilename = `vault_${crypto.randomUUID()}${ext}`;
  const absoluteStoragePath = path.join(STORAGE_DIR, storageFilename);

  fs.writeFileSync(absoluteStoragePath, fileBuffer);

  // 4. Compute file hash
  const sha256 = computeFileHash(fileBuffer);
  const now = new Date().toISOString();

  // 5. Insert metadata into SQLite
  const insert = db.prepare(`
    INSERT INTO documents (
      id, owner_id, title, original_name, storage_path, mime_type,
      file_size, sha256_checksum, category, description, is_confidential,
      is_deleted, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `);

  insert.run(
    docId,
    owner.id,
    title || cleanOriginalName,
    cleanOriginalName,
    storageFilename,
    validation.mimeType,
    fileBuffer.length,
    sha256,
    category || 'General',
    description,
    isConfidential ? 1 : 0,
    now,
    now
  );

  // 6. Record upload in cryptographic audit ledger
  recordAuditEvent({
    actor: owner,
    action: 'DOCUMENT_UPLOAD',
    resourceType: 'document',
    resourceId: docId,
    resourceName: title || cleanOriginalName,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: {
      originalName: cleanOriginalName,
      fileSize: fileBuffer.length,
      mimeType: validation.mimeType,
      sha256Checksum: sha256,
      category
    }
  });

  return {
    id: docId,
    title: title || cleanOriginalName,
    originalName: cleanOriginalName,
    fileSize: fileBuffer.length,
    mimeType: validation.mimeType,
    sha256Checksum: sha256,
    category,
    createdAt: now
  };
}

/**
 * Searches documents scoped strictly to what the user has permission to view.
 * Guarantees zero metadata leakage.
 */
export function searchDocuments(user, filters = {}) {
  const db = getDb();

  let sql = `
    SELECT d.id, d.owner_id, d.title, d.original_name, d.mime_type,
           d.file_size, d.sha256_checksum, d.category, d.description,
           d.is_confidential, d.created_at, d.updated_at,
           u.name as owner_name, u.email as owner_email,
           CASE 
             WHEN d.owner_id = ? THEN 'owner'
             ELSE p.permission_level
           END as user_permission
    FROM documents d
    JOIN users u ON d.owner_id = u.id
    LEFT JOIN document_permissions p ON p.document_id = d.id AND p.user_id = ? AND p.revoked_at IS NULL
    WHERE d.is_deleted = 0
  `;

  const params = [user.id, user.id];

  // Access control restriction:
  // Non-admins see ONLY what they own or have active permissions on.
  // Admins see documents metadata for governance, but see user_permission as 'none' if not granted.
  if (user.role !== 'admin') {
    sql += ` AND (d.owner_id = ? OR (p.user_id = ? AND p.revoked_at IS NULL))`;
    params.push(user.id, user.id);
  }

  // Filter: Search keyword
  if (filters.search && filters.search.trim() !== '') {
    const term = `%${filters.search.trim()}%`;
    sql += ` AND (d.title LIKE ? OR d.original_name LIKE ? OR d.description LIKE ?)`;
    params.push(term, term, term);
  }

  // Filter: Category
  if (filters.category && filters.category.trim() !== '') {
    sql += ` AND d.category = ?`;
    params.push(filters.category.trim());
  }

  // Filter: Owner
  if (filters.ownerId) {
    sql += ` AND d.owner_id = ?`;
    params.push(filters.ownerId);
  }

  // Filter: Date Range
  if (filters.startDate) {
    sql += ` AND d.created_at >= ?`;
    params.push(filters.startDate);
  }
  if (filters.endDate) {
    sql += ` AND d.created_at <= ?`;
    params.push(filters.endDate);
  }

  sql += ` ORDER BY d.created_at DESC`;

  return db.prepare(sql).all(...params);
}

/**
 * Gets document metadata after verifying read permissions.
 */
export function getDocumentMetadata(documentId, user, ipAddress, userAgent) {
  const access = resolveUserAccess(documentId, user.id);

  if (!access) {
    const err = new Error('Document not found or has been deleted.');
    err.statusCode = 404;
    throw err;
  }

  if (!access.canRead) {
    // Record unauthorized probe
    recordAuditEvent({
      actor: user,
      action: 'ACCESS_DENIED',
      resourceType: 'document',
      resourceId: documentId,
      resourceName: access.document.title,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { attemptedAction: 'GET_METADATA', reason: 'Missing read permission' }
    });
    const err = new Error('Access Denied: You do not have permission to view this document.');
    err.statusCode = 403;
    throw err;
  }

  const db = getDb();
  const doc = db.prepare(`
    SELECT d.id, d.owner_id, d.title, d.original_name, d.mime_type,
           d.file_size, d.sha256_checksum, d.category, d.description,
           d.is_confidential, d.created_at, d.updated_at,
           u.name as owner_name, u.email as owner_email
    FROM documents d
    JOIN users u ON d.owner_id = u.id
    WHERE d.id = ?
  `).get(documentId);

  // Record audit read
  recordAuditEvent({
    actor: user,
    action: 'DOCUMENT_READ',
    resourceType: 'document',
    resourceId: documentId,
    resourceName: doc.title,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: { accessLevel: access.permissionLevel }
  });

  return {
    ...doc,
    accessLevel: access.permissionLevel,
    canEdit: access.canEdit,
    canDelete: access.canDelete,
    canManagePermissions: access.canManagePermissions
  };
}

/**
 * Authorizes and prepares a file download stream.
 * Validates on-disk cryptographic integrity against database checksum.
 */
export function prepareDocumentDownload(documentId, user, ipAddress, userAgent) {
  const access = resolveUserAccess(documentId, user.id);

  if (!access) {
    const err = new Error('Document not found.');
    err.statusCode = 404;
    throw err;
  }

  if (!access.canRead) {
    recordAuditEvent({
      actor: user,
      action: 'ACCESS_DENIED',
      resourceType: 'document',
      resourceId: documentId,
      resourceName: access.document.title,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { attemptedAction: 'DOCUMENT_DOWNLOAD', reason: 'Insufficient privileges' }
    });
    const err = new Error('Access Denied: You are not authorized to download this document.');
    err.statusCode = 403;
    throw err;
  }

  const db = getDb();
  const doc = db.prepare(`
    SELECT id, title, original_name, storage_path, mime_type, file_size, sha256_checksum
    FROM documents
    WHERE id = ?
  `).get(documentId);

  const fullPath = path.join(STORAGE_DIR, doc.storage_path);

  if (!fs.existsSync(fullPath)) {
    const err = new Error('Storage file integrity error: physical file missing.');
    err.statusCode = 500;
    throw err;
  }

  // Optional: Read small chunk or verify file on disk
  const diskBuffer = fs.readFileSync(fullPath);
  const diskHash = computeFileHash(diskBuffer);
  if (diskHash !== doc.sha256_checksum) {
    recordAuditEvent({
      actor: user,
      action: 'SECURITY_ANOMALY',
      resourceType: 'document',
      resourceId: documentId,
      resourceName: doc.title,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { error: 'Cryptographic checksum mismatch between disk file and registered ledger checksum!' }
    });
    const err = new Error('Security Alert: Stored file hash mismatch. Download blocked for integrity verification.');
    err.statusCode = 500;
    throw err;
  }

  // Record successful download audit event
  recordAuditEvent({
    actor: user,
    action: 'DOCUMENT_DOWNLOAD',
    resourceType: 'document',
    resourceId: documentId,
    resourceName: doc.title,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: {
      originalName: doc.original_name,
      fileSize: doc.file_size,
      sha256: doc.sha256_checksum
    }
  });

  return {
    filePath: fullPath,
    originalName: doc.original_name,
    mimeType: doc.mime_type,
    fileSize: doc.file_size
  };
}

/**
 * Updates document metadata or contents. Requires 'edit' or 'owner' permission.
 */
export function updateDocument({
  documentId,
  actor,
  title,
  category,
  description,
  newFileBuffer = null,
  newOriginalName = null,
  ipAddress,
  userAgent
}) {
  const access = resolveUserAccess(documentId, actor.id);

  if (!access) {
    const err = new Error('Document not found.');
    err.statusCode = 404;
    throw err;
  }

  if (!access.canEdit) {
    recordAuditEvent({
      actor,
      action: 'ACCESS_DENIED',
      resourceType: 'document',
      resourceId: documentId,
      resourceName: access.document.title,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { attemptedAction: 'DOCUMENT_UPDATE', reason: 'Requires edit permission' }
    });
    const err = new Error('Access Denied: You need Edit permission to update this document.');
    err.statusCode = 403;
    throw err;
  }

  const db = getDb();
  const now = new Date().toISOString();

  let storagePath = null;
  let mimeType = null;
  let fileSize = null;
  let sha256 = null;

  if (newFileBuffer && newOriginalName) {
    const validation = validateFileContent(newFileBuffer, newOriginalName);
    if (!validation.valid) {
      const err = new Error(validation.error);
      err.statusCode = 400;
      throw err;
    }
    const cleanName = sanitizeFilename(newOriginalName);
    const ext = path.extname(cleanName);
    const storageFilename = `vault_${crypto.randomUUID()}${ext}`;
    const fullPath = path.join(STORAGE_DIR, storageFilename);
    fs.writeFileSync(fullPath, newFileBuffer);

    storagePath = storageFilename;
    mimeType = validation.mimeType;
    fileSize = newFileBuffer.length;
    sha256 = computeFileHash(newFileBuffer);

    db.prepare(`
      UPDATE documents
      SET title = COALESCE(?, title),
          category = COALESCE(?, category),
          description = COALESCE(?, description),
          storage_path = ?,
          original_name = ?,
          mime_type = ?,
          file_size = ?,
          sha256_checksum = ?,
          updated_at = ?
      WHERE id = ?
    `).run(title, category, description, storagePath, cleanName, mimeType, fileSize, sha256, now, documentId);
  } else {
    db.prepare(`
      UPDATE documents
      SET title = COALESCE(?, title),
          category = COALESCE(?, category),
          description = COALESCE(?, description),
          updated_at = ?
      WHERE id = ?
    `).run(title, category, description, now, documentId);
  }

  recordAuditEvent({
    actor,
    action: 'DOCUMENT_UPDATE',
    resourceType: 'document',
    resourceId: documentId,
    resourceName: title || access.document.title,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: {
      hasNewFile: Boolean(newFileBuffer),
      category,
      updatedAt: now
    }
  });

  return { success: true, updatedAt: now };
}

/**
 * Deletes document. ONLY the owner can delete.
 */
export function deleteDocument(documentId, actor, ipAddress, userAgent) {
  const access = resolveUserAccess(documentId, actor.id);

  if (!access) {
    const err = new Error('Document not found.');
    err.statusCode = 404;
    throw err;
  }

  if (!access.isOwner) {
    recordAuditEvent({
      actor,
      action: 'ACCESS_DENIED',
      resourceType: 'document',
      resourceId: documentId,
      resourceName: access.document.title,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { attemptedAction: 'DOCUMENT_DELETE', reason: 'Only the document owner can delete' }
    });
    const err = new Error('Access Denied: Only the document owner can delete this document.');
    err.statusCode = 403;
    throw err;
  }

  const db = getDb();
  // Soft delete to preserve historical audit context
  db.prepare('UPDATE documents SET is_deleted = 1, updated_at = ? WHERE id = ?')
    .run(new Date().toISOString(), documentId);

  recordAuditEvent({
    actor,
    action: 'DOCUMENT_DELETE',
    resourceType: 'document',
    resourceId: documentId,
    resourceName: access.document.title,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: { deletedAt: new Date().toISOString() }
  });

  return { success: true };
}
