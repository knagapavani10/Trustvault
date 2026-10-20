import crypto from 'node:crypto';
import { getDb } from '../db/database.js';
import { recordAuditEvent } from './auditService.js';

/**
 * Evaluates real-time permissions for a given user against a specific document.
 * Crucial Standard: The server queries current database state synchronously on every request.
 * 
 * @param {string} documentId 
 * @param {string} userId 
 * @returns {object|null} Permission evaluation result or null if document doesn't exist
 */
export function resolveUserAccess(documentId, userId) {
  const db = getDb();

  const doc = db.prepare(`
    SELECT id, owner_id, title, is_confidential, is_deleted
    FROM documents
    WHERE id = ? AND is_deleted = 0
  `).get(documentId);

  if (!doc) {
    return null;
  }

  // 1. Owner has absolute control over their document
  if (doc.owner_id === userId) {
    return {
      document: doc,
      isOwner: true,
      canRead: true,
      canEdit: true,
      canDelete: true,
      canManagePermissions: true,
      permissionLevel: 'owner'
    };
  }

  // 2. Query named per-document permission grant (must be active and not revoked)
  const grant = db.prepare(`
    SELECT permission_level, revoked_at
    FROM document_permissions
    WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL
  `).get(documentId, userId);

  if (grant) {
    const isEdit = grant.permission_level === 'edit';
    return {
      document: doc,
      isOwner: false,
      canRead: true,
      canEdit: isEdit,
      canDelete: false, // Only owner can delete
      canManagePermissions: false, // Only owner can manage permissions
      permissionLevel: grant.permission_level
    };
  }

  // 3. User has no grant (including Admins without an explicit grant, for Zero-Trust confidentiality)
  return {
    document: doc,
    isOwner: false,
    canRead: false,
    canEdit: false,
    canDelete: false,
    canManagePermissions: false,
    permissionLevel: 'none'
  };
}

/**
 * Grants a named permission (read or edit) to a target user.
 * Only the document owner can grant permissions.
 */
export function grantDocumentPermission({
  documentId,
  actor,
  targetEmail,
  permissionLevel,
  ipAddress,
  userAgent
}) {
  const db = getDb();

  // Validate permission level
  if (!['read', 'edit'].includes(permissionLevel)) {
    throw new Error('Invalid permission level. Must be "read" or "edit".');
  }

  // Resolve actor access
  const access = resolveUserAccess(documentId, actor.id);
  if (!access) {
    throw new Error('Document not found or has been deleted.');
  }

  if (!access.isOwner) {
    recordAuditEvent({
      actor,
      action: 'ACCESS_DENIED',
      resourceType: 'permission',
      resourceId: documentId,
      resourceName: access.document.title,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { reason: 'Only the document owner can grant permissions', targetEmail, permissionLevel }
    });
    const err = new Error('Access Denied: Only the document owner can grant permissions.');
    err.statusCode = 403;
    throw err;
  }

  // Find target user
  const targetUser = db.prepare('SELECT id, email, name, is_active FROM users WHERE email = ?').get(targetEmail);
  if (!targetUser) {
    const err = new Error(`User with email "${targetEmail}" does not exist.`);
    err.statusCode = 404;
    throw err;
  }

  if (!targetUser.is_active) {
    const err = new Error(`Cannot grant access to deactivated user "${targetEmail}".`);
    err.statusCode = 400;
    throw err;
  }

  if (targetUser.id === actor.id) {
    const err = new Error('Owner already holds full access.');
    err.statusCode = 400;
    throw err;
  }

  const now = new Date().toISOString();

  // Check existing grant
  const existing = db.prepare('SELECT id FROM document_permissions WHERE document_id = ? AND user_id = ?')
    .get(documentId, targetUser.id);

  if (existing) {
    db.prepare(`
      UPDATE document_permissions
      SET permission_level = ?, granted_by = ?, granted_at = ?, revoked_at = NULL
      WHERE id = ?
    `).run(permissionLevel, actor.id, now, existing.id);
  } else {
    const permId = `perm-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO document_permissions (id, document_id, user_id, permission_level, granted_by, granted_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(permId, documentId, targetUser.id, permissionLevel, actor.id, now);
  }

  // Record in cryptographic audit ledger
  recordAuditEvent({
    actor,
    action: 'PERMISSION_GRANTED',
    resourceType: 'permission',
    resourceId: documentId,
    resourceName: access.document.title,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: {
      targetUserId: targetUser.id,
      targetEmail: targetUser.email,
      targetName: targetUser.name,
      permissionLevel
    }
  });

  return {
    success: true,
    targetEmail: targetUser.email,
    permissionLevel
  };
}

/**
 * Revokes permission from a target user immediately.
 * Only the document owner can revoke permissions.
 */
export function revokeDocumentPermission({
  documentId,
  actor,
  targetUserId,
  ipAddress,
  userAgent
}) {
  const db = getDb();

  const access = resolveUserAccess(documentId, actor.id);
  if (!access) {
    throw new Error('Document not found or has been deleted.');
  }

  if (!access.isOwner) {
    recordAuditEvent({
      actor,
      action: 'ACCESS_DENIED',
      resourceType: 'permission',
      resourceId: documentId,
      resourceName: access.document.title,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { reason: 'Only the document owner can revoke permissions', targetUserId }
    });
    const err = new Error('Access Denied: Only the document owner can revoke permissions.');
    err.statusCode = 403;
    throw err;
  }

  const targetUser = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(targetUserId);

  const now = new Date().toISOString();
  const result = db.prepare(`
    UPDATE document_permissions
    SET revoked_at = ?
    WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL
  `).run(now, documentId, targetUserId);

  if (result.changes === 0) {
    const err = new Error('No active permission grant found for this user on this document.');
    err.statusCode = 404;
    throw err;
  }

  // Audit record of revocation
  recordAuditEvent({
    actor,
    action: 'PERMISSION_REVOKED',
    resourceType: 'permission',
    resourceId: documentId,
    resourceName: access.document.title,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: {
      targetUserId,
      targetEmail: targetUser?.email ?? 'UNKNOWN',
      targetName: targetUser?.name ?? 'UNKNOWN',
      revokedAt: now
    }
  });

  return {
    success: true,
    revokedAt: now
  };
}

/**
 * Lists all permissions granted on a document.
 */
export function listDocumentPermissions(documentId, actor) {
  const db = getDb();
  const access = resolveUserAccess(documentId, actor.id);

  if (!access) {
    const err = new Error('Document not found.');
    err.statusCode = 404;
    throw err;
  }

  // Only the owner or an administrator can view the ACL list
  if (!access.isOwner && actor.role !== 'admin') {
    const err = new Error('Access Denied: Only the document owner or administrator can view permissions.');
    err.statusCode = 403;
    throw err;
  }

  const permissions = db.prepare(`
    SELECT p.id, p.user_id, u.email, u.name, u.role, p.permission_level, p.granted_at, p.revoked_at
    FROM document_permissions p
    JOIN users u ON p.user_id = u.id
    WHERE p.document_id = ? AND p.revoked_at IS NULL
    ORDER BY p.granted_at DESC
  `).all(documentId);

  return permissions;
}
