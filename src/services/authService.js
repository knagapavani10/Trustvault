import { getDb } from '../db/database.js';
import { verifyPassword, createSessionToken, verifySessionToken, hashPassword } from './cryptoService.js';
import { recordAuditEvent } from './auditService.js';
import crypto from 'node:crypto';

/**
 * Authenticates user credentials and issues a signed session token.
 */
export function loginUser({ email, password, ipAddress, userAgent }) {
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    recordAuditEvent({
      actor: null,
      action: 'AUTH_FAILED',
      resourceType: 'auth',
      resourceId: null,
      resourceName: email,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { email, reason: 'User not found' }
    });
    const err = new Error('Invalid email or password.');
    err.statusCode = 401;
    throw err;
  }

  if (!user.is_active) {
    recordAuditEvent({
      actor: { id: user.id, email: user.email, role: user.role },
      action: 'AUTH_FAILED',
      resourceType: 'auth',
      resourceId: user.id,
      resourceName: user.email,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { email, reason: 'Account suspended or revoked' }
    });
    const err = new Error('Account has been deactivated. Contact an administrator.');
    err.statusCode = 403;
    throw err;
  }

  const isPasswordValid = verifyPassword(password, user.salt, user.password_hash);
  if (!isPasswordValid) {
    recordAuditEvent({
      actor: { id: user.id, email: user.email, role: user.role },
      action: 'AUTH_FAILED',
      resourceType: 'auth',
      resourceId: user.id,
      resourceName: user.email,
      ipAddress,
      userAgent,
      status: 'DENIED',
      details: { email, reason: 'Incorrect password' }
    });
    const err = new Error('Invalid email or password.');
    err.statusCode = 401;
    throw err;
  }

  // Issue session token containing current token_version
  const token = createSessionToken(user);

  recordAuditEvent({
    actor: { id: user.id, email: user.email, role: user.role },
    action: 'AUTH_LOGIN',
    resourceType: 'auth',
    resourceId: user.id,
    resourceName: user.email,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: { role: user.role }
  });

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    }
  };
}

/**
 * Validates request session token with live database revocation check.
 * Standard 3: Revocation takes effect immediately!
 */
export function validateSession(token) {
  const payload = verifySessionToken(token);
  if (!payload) return null;

  const db = getDb();
  // Real-time user state query
  const user = db.prepare('SELECT id, email, name, role, is_active, token_version FROM users WHERE id = ?')
    .get(payload.sub);

  if (!user) return null;
  if (!user.is_active) return null; // Immediately rejects deactivated users
  if (user.token_version !== payload.tokenVersion) return null; // Immediately rejects revoked sessions

  return user;
}

/**
 * Registers a new user (admin only or setup).
 */
export function registerUser({ email, password, name, role, creator, ipAddress, userAgent }) {
  if (!['admin', 'owner', 'viewer'].includes(role)) {
    throw new Error('Invalid role specified.');
  }

  const db = getDb();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    const err = new Error(`User with email "${email}" already exists.`);
    err.statusCode = 409;
    throw err;
  }

  const userId = `u-${role}-${crypto.randomUUID().slice(0, 8)}`;
  const { salt, hash } = hashPassword(password);
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO users (id, email, password_hash, salt, name, role, is_active, token_version, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?)
  `).run(userId, email, hash, salt, name, role, now);

  recordAuditEvent({
    actor: creator,
    action: 'USER_REGISTERED',
    resourceType: 'user',
    resourceId: userId,
    resourceName: email,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: { name, role }
  });

  return { id: userId, email, name, role };
}

/**
 * Suspends or activates a user account, instantly terminating all existing sessions.
 */
export function setUserActiveStatus(userId, isActive, adminActor, ipAddress, userAgent) {
  const db = getDb();
  const user = db.prepare('SELECT id, email, token_version FROM users WHERE id = ?').get(userId);

  if (!user) {
    const err = new Error('User not found.');
    err.statusCode = 404;
    throw err;
  }

  // Increment token_version to invalidate any existing issued JWTs/tokens immediately!
  const nextTokenVersion = (user.token_version || 1) + 1;

  db.prepare('UPDATE users SET is_active = ?, token_version = ? WHERE id = ?')
    .run(isActive ? 1 : 0, nextTokenVersion, userId);

  recordAuditEvent({
    actor: adminActor,
    action: isActive ? 'USER_ACTIVATED' : 'USER_SUSPENDED',
    resourceType: 'user',
    resourceId: userId,
    resourceName: user.email,
    ipAddress,
    userAgent,
    status: 'SUCCESS',
    details: {
      previousState: user.is_active,
      newState: isActive ? 1 : 0,
      sessionsRevokedVersion: nextTokenVersion
    }
  });

  return { success: true, isActive, sessionsRevoked: true };
}
