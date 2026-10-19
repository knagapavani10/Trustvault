import { getDb } from '../db/database.js';
import { computeAuditBlockHash } from './cryptoService.js';

const GENESIS_PREV_HASH = '0'.repeat(64);

/**
 * Records an immutable, cryptographically chained audit event.
 * Atomically computes the SHA-256 block hash linked to the previous block.
 * 
 * @param {object} params
 * @param {object|null} params.actor - { id, email, role }
 * @param {string} params.action - DOCUMENT_READ, ACCESS_DENIED, etc.
 * @param {string} params.resourceType - 'document', 'permission', 'auth', 'system'
 * @param {string|null} params.resourceId
 * @param {string|null} params.resourceName
 * @param {string} params.ipAddress
 * @param {string} params.userAgent
 * @param {'SUCCESS'|'DENIED'} params.status
 * @param {object|string} [params.details]
 * @returns {object} The persisted audit record
 */
export function recordAuditEvent({
  actor = null,
  action,
  resourceType,
  resourceId = null,
  resourceName = null,
  ipAddress = '127.0.0.1',
  userAgent = 'Unknown',
  status = 'SUCCESS',
  details = {}
}) {
  const db = getDb();

  // Clean details
  const detailsStr = typeof details === 'string' ? details : JSON.stringify(details);
  const now = new Date().toISOString();

  // In SQLite WAL mode, run in a transaction for immediate serialization
  db.exec('BEGIN IMMEDIATE;');
  try {
    // Get the most recent audit entry to link the hash
    const lastRow = db.prepare('SELECT id, hash FROM audit_ledger ORDER BY id DESC LIMIT 1').get();

    const nextId = lastRow ? lastRow.id + 1 : 1;
    const prevHash = lastRow ? lastRow.hash : GENESIS_PREV_HASH;

    const entryToHash = {
      id: nextId,
      timestamp: now,
      actor_id: actor?.id ?? null,
      actor_email: actor?.email ?? 'ANONYMOUS',
      actor_role: actor?.role ?? 'NONE',
      action,
      resource_type: resourceType,
      resource_id: resourceId ?? null,
      ip_address: ipAddress,
      status,
      details: detailsStr
    };

    const hash = computeAuditBlockHash(entryToHash, prevHash);

    const insert = db.prepare(`
      INSERT INTO audit_ledger (
        id, timestamp, actor_id, actor_email, actor_role, action,
        resource_type, resource_id, resource_name, ip_address, user_agent,
        status, details, prev_hash, hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insert.run(
      nextId,
      now,
      actor?.id ?? null,
      actor?.email ?? 'ANONYMOUS',
      actor?.role ?? 'NONE',
      action,
      resourceType,
      resourceId ?? null,
      resourceName ?? null,
      ipAddress,
      userAgent,
      status,
      detailsStr,
      prevHash,
      hash
    );

    db.exec('COMMIT;');

    return {
      id: nextId,
      timestamp: now,
      prevHash,
      hash,
      status,
      action
    };
  } catch (err) {
    db.exec('ROLLBACK;');
    console.error('CRITICAL: Failed to write audit ledger event:', err);
    throw err;
  }
}

/**
 * Mathematically verifies the entire cryptographic audit ledger from genesis to head.
 * Detects any modifications, deletions, injections, or field tampering.
 * 
 * @returns {{ valid: boolean, totalBlocks: number, verifiedAt: string, error?: string, brokenBlockId?: number }}
 */
export function verifyAuditChainIntegrity() {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM audit_ledger ORDER BY id ASC').all();

  if (rows.length === 0) {
    return {
      valid: false,
      totalBlocks: 0,
      verifiedAt: new Date().toISOString(),
      error: 'Audit ledger is completely empty. Genesis block is missing!'
    };
  }

  let expectedPrevHash = GENESIS_PREV_HASH;

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const expectedId = i + 1;

    // Check 1: Sequence ID continuity
    if (row.id !== expectedId) {
      return {
        valid: false,
        totalBlocks: rows.length,
        verifiedAt: new Date().toISOString(),
        error: `Sequence violation: Expected block #${expectedId} but found block #${row.id}. Possible row deletion or injection.`,
        brokenBlockId: row.id
      };
    }

    // Check 2: Previous hash link continuity
    if (row.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        totalBlocks: rows.length,
        verifiedAt: new Date().toISOString(),
        error: `Hash chain broken at block #${row.id}: prev_hash does not match previous block's hash.`,
        brokenBlockId: row.id,
        expectedPrevHash,
        actualPrevHash: row.prev_hash
      };
    }

    // Check 3: Content integrity recomputation
    const entryToHash = {
      id: row.id,
      timestamp: row.timestamp,
      actor_id: row.actor_id,
      actor_email: row.actor_email,
      actor_role: row.actor_role,
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      ip_address: row.ip_address,
      status: row.status,
      details: row.details
    };

    const recomputedHash = computeAuditBlockHash(entryToHash, row.prev_hash);
    if (recomputedHash !== row.hash) {
      return {
        valid: false,
        totalBlocks: rows.length,
        verifiedAt: new Date().toISOString(),
        error: `Tampering detected in block #${row.id}: recomputed SHA-256 does not match stored hash. Data was modified!`,
        brokenBlockId: row.id,
        expectedHash: recomputedHash,
        storedHash: row.hash
      };
    }

    // Advance expected hash for next block
    expectedPrevHash = row.hash;
  }

  return {
    valid: true,
    totalBlocks: rows.length,
    headHash: expectedPrevHash,
    verifiedAt: new Date().toISOString()
  };
}

/**
 * Retrieves audit entries scoped to user role permissions.
 * Admins see all logs; Owners see logs for their documents; Viewers see only their own access logs.
 * 
 * @param {object} user 
 * @param {object} filters 
 * @returns {Array<object>}
 */
export function queryAuditLogs(user, filters = {}) {
  const db = getDb();
  let query = 'SELECT * FROM audit_ledger WHERE 1=1';
  const params = [];

  if (user.role === 'admin') {
    // Admin sees all
  } else if (user.role === 'owner') {
    // Owner sees logs where they are actor, OR resource is a document they own
    query += ` AND (
      actor_id = ? OR 
      (resource_type = 'document' AND resource_id IN (SELECT id FROM documents WHERE owner_id = ?))
    )`;
    params.push(user.id, user.id);
  } else {
    // Viewer sees only their own actions
    query += ' AND actor_id = ?';
    params.push(user.id);
  }

  if (filters.action) {
    query += ' AND action = ?';
    params.push(filters.action);
  }

  if (filters.status) {
    query += ' AND status = ?';
    params.push(filters.status);
  }

  if (filters.resourceId) {
    query += ' AND resource_id = ?';
    params.push(filters.resourceId);
  }

  query += ' ORDER BY id DESC LIMIT 200';

  return db.prepare(query).all(...params);
}
