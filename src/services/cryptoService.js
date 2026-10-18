import crypto from 'node:crypto';

// Static application secret for HMAC signing (in production, loaded from environment or HSM)
const HMAC_SECRET = process.env.TRUSTVAULT_SECRET || 'trustvault-super-secure-cryptographic-signing-key-2026';
const SCRYPT_KEYLEN = 64;

/**
 * Hashes a plaintext password using scrypt with a unique cryptographically random salt.
 * @param {string} password 
 * @returns {{ salt: string, hash: string }}
 */
export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return { salt, hash };
}

/**
 * Verifies a password against the stored salt and hash using timing-safe comparison.
 * @param {string} password 
 * @param {string} salt 
 * @param {string} expectedHash 
 * @returns {boolean}
 */
export function verifyPassword(password, salt, expectedHash) {
  try {
    const derivedHash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
    const a = Buffer.from(derivedHash, 'utf8');
    const b = Buffer.from(expectedHash, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Creates a tamper-proof signed session token containing user claims.
 * @param {object} user 
 * @param {number} expiresInSeconds - Default 8 hours
 * @returns {string}
 */
export function createSessionToken(user, expiresInSeconds = 28800) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payloadData = {
    sub: user.id,
    email: user.email,
    role: user.role,
    name: user.name,
    tokenVersion: user.token_version ?? 1,
    iat: now,
    exp: now + expiresInSeconds,
    jti: crypto.randomUUID()
  };
  const payload = Buffer.from(JSON.stringify(payloadData)).toString('base64url');
  const signatureInput = `${header}.${payload}`;
  const signature = crypto.createHmac('sha256', HMAC_SECRET).update(signatureInput).digest('base64url');
  return `${signatureInput}.${signature}`;
}

/**
 * Verifies and decodes a session token.
 * @param {string} token 
 * @returns {object|null}
 */
export function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const signatureInput = `${header}.${payload}`;
  const expectedSig = crypto.createHmac('sha256', HMAC_SECRET).update(signatureInput).digest('base64url');

  const sigBuf = Buffer.from(signature, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (data.exp && data.exp < now) {
      return null; // Expired token
    }
    return data;
  } catch {
    return null;
  }
}

/**
 * Computes SHA-256 hash of a file buffer or stream.
 * @param {Buffer} buffer 
 * @returns {string}
 */
export function computeFileHash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Canonical block hashing for the Tamper-Evident Audit Ledger.
 * Ensures every field is deterministically formatted and hashed.
 * @param {object} entry 
 * @param {string} prevHash 
 * @returns {string}
 */
export function computeAuditBlockHash(entry, prevHash) {
  const canonicalString = [
    entry.id ?? '',
    prevHash,
    entry.timestamp,
    entry.actor_id ?? 'ANONYMOUS',
    entry.actor_email ?? 'ANONYMOUS',
    entry.actor_role ?? 'NONE',
    entry.action,
    entry.resource_type,
    entry.resource_id ?? 'NONE',
    entry.ip_address ?? 'UNKNOWN',
    entry.status,
    typeof entry.details === 'string' ? entry.details : JSON.stringify(entry.details || {})
  ].join('|');

  return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
}
