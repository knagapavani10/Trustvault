import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { hashPassword, computeAuditBlockHash } from '../services/cryptoService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Root paths
export const PROJECT_ROOT = path.resolve(__dirname, '../..');
export const DB_PATH = path.join(PROJECT_ROOT, 'storage', 'trustvault.sqlite');
export const STORAGE_DIR = path.join(PROJECT_ROOT, 'storage', 'vault_files');

// Ensure storage directories exist
if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

let dbInstance = null;

/**
 * Returns the singleton DatabaseSync instance
 * @returns {DatabaseSync}
 */
export function getDb() {
  if (!dbInstance) {
    dbInstance = new DatabaseSync(DB_PATH);
    dbInstance.exec('PRAGMA foreign_keys = ON;');
    dbInstance.exec('PRAGMA journal_mode = WAL;');
    dbInstance.exec('PRAGMA synchronous = NORMAL;');
  }
  return dbInstance;
}

/**
 * Initialize Schema and Seeds
 * @param {boolean} forceReset 
 */
export function initializeDatabase(forceReset = false) {
  if (forceReset && fs.existsSync(DB_PATH)) {
    if (dbInstance) {
      dbInstance.close();
      dbInstance = null;
    }
    fs.unlinkSync(DB_PATH);
  }

  const db = getDb();

  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
      is_active INTEGER DEFAULT 1,
      token_version INTEGER DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      original_name TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      sha256_checksum TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT,
      is_confidential INTEGER DEFAULT 1,
      is_deleted INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS document_permissions (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission_level TEXT NOT NULL CHECK (permission_level IN ('read', 'edit')),
      granted_by TEXT NOT NULL REFERENCES users(id),
      granted_at TEXT NOT NULL,
      revoked_at TEXT,
      UNIQUE (document_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS audit_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      actor_id TEXT,
      actor_email TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      resource_name TEXT,
      ip_address TEXT NOT NULL,
      user_agent TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'DENIED')),
      details TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_ledger(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_ledger(resource_type, resource_id);
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_ledger(actor_id);
    CREATE INDEX IF NOT EXISTS idx_doc_owner ON documents(owner_id);
    CREATE INDEX IF NOT EXISTS idx_doc_category ON documents(category);
    CREATE INDEX IF NOT EXISTS idx_perm_doc_user ON document_permissions(document_id, user_id);
  `);

  // Initialize Genesis block in audit ledger if empty
  const countRow = db.prepare('SELECT COUNT(*) as count FROM audit_ledger').get();
  if (countRow.count === 0) {
    const genesisPrevHash = '0'.repeat(64);
    const genesisTime = new Date().toISOString();
    const genesisDetails = JSON.stringify({ system: 'TrustVault Cryptographic Audit Ledger Initialized' });
    const genesisEntry = {
      id: 1,
      timestamp: genesisTime,
      actor_id: null,
      actor_email: 'SYSTEM',
      actor_role: 'SYSTEM',
      action: 'SYSTEM_GENESIS',
      resource_type: 'system',
      resource_id: 'genesis-0001',
      resource_name: 'Root Ledger Block',
      ip_address: '127.0.0.1',
      user_agent: 'TrustVault Kernel/1.0',
      status: 'SUCCESS',
      details: genesisDetails
    };
    const genesisHash = computeAuditBlockHash(genesisEntry, genesisPrevHash);

    const insertAudit = db.prepare(`
      INSERT INTO audit_ledger (
        id, timestamp, actor_id, actor_email, actor_role, action,
        resource_type, resource_id, resource_name, ip_address, user_agent,
        status, details, prev_hash, hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertAudit.run(
      genesisEntry.id, genesisEntry.timestamp, genesisEntry.actor_id,
      genesisEntry.actor_email, genesisEntry.actor_role, genesisEntry.action,
      genesisEntry.resource_type, genesisEntry.resource_id, genesisEntry.resource_name,
      genesisEntry.ip_address, genesisEntry.user_agent, genesisEntry.status,
      genesisEntry.details, genesisPrevHash, genesisHash
    );
  }

  // Seed default users if table is empty
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count === 0) {
    seedDefaultData(db);
  }

  return db;
}

/**
 * Seed initial accounts and demo confidential documents
 * @param {DatabaseSync} db 
 */
function seedDefaultData(db) {
  const insertUser = db.prepare(`
    INSERT INTO users (id, email, password_hash, salt, name, role, is_active, token_version, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();

  // 1. Admin
  const adminPass = hashPassword('AdminPass123!');
  const adminId = 'u-admin-0001';
  insertUser.run(adminId, 'admin@trustvault.local', adminPass.hash, adminPass.salt, 'Security Administrator', 'admin', 1, 1, now);

  // 2. Document Owner Alice (HR Director)
  const alicePass = hashPassword('AlicePass123!');
  const aliceId = 'u-owner-0001';
  insertUser.run(aliceId, 'alice.owner@trustvault.local', alicePass.hash, alicePass.salt, 'Alice Harrison (HR Director)', 'owner', 1, 1, now);

  // 3. Document Owner Bob (Engineering Director)
  const bobPass = hashPassword('BobPass123!');
  const bobId = 'u-owner-0002';
  insertUser.run(bobId, 'bob.owner@trustvault.local', bobPass.hash, bobPass.salt, 'Bob Vance (Engineering IP)', 'owner', 1, 1, now);

  // 4. Viewer Charlie (Internal Auditor)
  const charliePass = hashPassword('CharliePass123!');
  const charlieId = 'u-viewer-0001';
  insertUser.run(charlieId, 'charlie.viewer@trustvault.local', charliePass.hash, charliePass.salt, 'Charlie Kelly (Internal Auditor)', 'viewer', 1, 1, now);

  // 5. Viewer Dave (External Contractor)
  const davePass = hashPassword('DavePass123!');
  const daveId = 'u-viewer-0002';
  insertUser.run(daveId, 'dave.viewer@trustvault.local', davePass.hash, davePass.salt, 'Dave Miller (External Contractor)', 'viewer', 1, 1, now);

  // 6. Suspended Ex-Employee Eve
  const evePass = hashPassword('EvePass123!');
  const eveId = 'u-viewer-0003';
  insertUser.run(eveId, 'eve.revoked@trustvault.local', evePass.hash, evePass.salt, 'Eve Adams (Former Employee)', 'viewer', 0, 1, now);

  // Seed sample confidential files on disk
  const samplePdfContent = Buffer.from('%PDF-1.4\n% TrustVault Confidential Seed Document Sample\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');
  
  // Seed Document 1: Alice's Executive Salary Review (Confidential HR)
  const doc1Id = 'doc-salary-2026';
  const doc1Storage = `vault_${crypto.randomUUID()}.pdf`;
  fs.writeFileSync(path.join(STORAGE_DIR, doc1Storage), samplePdfContent);
  const doc1Hash = crypto.createHash('sha256').update(samplePdfContent).digest('hex');

  const insertDoc = db.prepare(`
    INSERT INTO documents (
      id, owner_id, title, original_name, storage_path, mime_type,
      file_size, sha256_checksum, category, description, is_confidential,
      is_deleted, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertDoc.run(
    doc1Id, aliceId, 'Executive Salary Review 2026', 'Executive_Salary_Review_2026.pdf',
    doc1Storage, 'application/pdf', samplePdfContent.length, doc1Hash,
    'Human Resources', 'Highly confidential executive compensation breakdown.',
    1, 0, now, now
  );

  // Seed Document 2: Bob's Proprietary Architecture (Confidential IP)
  const doc2Id = 'doc-arch-nextgen';
  const doc2Storage = `vault_${crypto.randomUUID()}.pdf`;
  fs.writeFileSync(path.join(STORAGE_DIR, doc2Storage), samplePdfContent);
  const doc2Hash = crypto.createHash('sha256').update(samplePdfContent).digest('hex');

  insertDoc.run(
    doc2Id, bobId, 'NextGen Proprietary Architecture', 'NextGen_Proprietary_Architecture.pdf',
    doc2Storage, 'application/pdf', samplePdfContent.length, doc2Hash,
    'Intellectual Property', 'Core patent pending system design drawings and specs.',
    1, 0, now, now
  );

  // Seed Document 3: Alice's Audit Working Papers (Compliance) - Shared with Charlie for Read
  const doc3Id = 'doc-audit-q3';
  const doc3Storage = `vault_${crypto.randomUUID()}.pdf`;
  fs.writeFileSync(path.join(STORAGE_DIR, doc3Storage), samplePdfContent);
  const doc3Hash = crypto.createHash('sha256').update(samplePdfContent).digest('hex');

  insertDoc.run(
    doc3Id, aliceId, 'Q3 External Audit Working Papers', 'Q3_External_Audit_Working_Papers.pdf',
    doc3Storage, 'application/pdf', samplePdfContent.length, doc3Hash,
    'Compliance', 'Audit work papers prepared for regulators.',
    1, 0, now, now
  );

  // Grant read permission on doc3 to Charlie
  const insertPerm = db.prepare(`
    INSERT INTO document_permissions (id, document_id, user_id, permission_level, granted_by, granted_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  insertPerm.run(`perm-${crypto.randomUUID().slice(0, 8)}`, doc3Id, charlieId, 'read', aliceId, now);
}
