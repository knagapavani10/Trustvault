import path from 'node:path';

// Magic bytes signatures for allowed document types
const MAGIC_SIGNATURES = {
  pdf: [0x25, 0x50, 0x44, 0x46], // %PDF
  png: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], // \x89PNG\r\n\x1a\n
  jpg: [0xFF, 0xD8, 0xFF], // JPEG SOI
  zip: [0x50, 0x4B, 0x03, 0x04], // PK.. (DOCX, XLSX, ZIP)
};

// Disallowed dangerous extensions
const FORBIDDEN_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.sh', '.bash', '.vbs', '.js', '.mjs', '.cjs',
  '.ts', '.jsx', '.tsx', '.html', '.htm', '.xhtml', '.svg', '.xml',
  '.php', '.phtml', '.php3', '.php4', '.php5', '.phps', '.asp', '.aspx',
  '.jsp', '.cgi', '.pl', '.py', '.rb', '.ps1', '.vbe', '.wsf', '.hta',
  '.dll', '.so', '.dylib', '.com', '.scr', '.msi', '.jar'
]);

/**
 * Validates file buffer magic bytes against declared or expected type.
 * @param {Buffer} buffer 
 * @param {string} originalName 
 * @returns {{ valid: boolean, mimeType: string, detectedFormat: string, error?: string }}
 */
export function validateFileContent(buffer, originalName) {
  if (!buffer || buffer.length === 0) {
    return { valid: false, error: 'File is empty (0 bytes).' };
  }

  // Maximum size limit: 25 MB
  const MAX_SIZE = 25 * 1024 * 1024;
  if (buffer.length > MAX_SIZE) {
    return { valid: false, error: 'File exceeds maximum permitted size of 25 MB.' };
  }

  const ext = path.extname(originalName).toLowerCase();

  // Reject dangerous extensions immediately
  if (FORBIDDEN_EXTENSIONS.has(ext)) {
    return {
      valid: false,
      error: `Security Violation: File extension "${ext}" is strictly forbidden for security reasons.`
    };
  }

  // Helper to match buffer prefix
  const matchesPrefix = (sig) => {
    if (buffer.length < sig.length) return false;
    for (let i = 0; i < sig.length; i++) {
      if (buffer[i] !== sig[i]) return false;
    }
    return true;
  };

  // Check PDF
  if (matchesPrefix(MAGIC_SIGNATURES.pdf)) {
    return { valid: true, mimeType: 'application/pdf', detectedFormat: 'PDF' };
  }

  // Check PNG
  if (matchesPrefix(MAGIC_SIGNATURES.png)) {
    return { valid: true, mimeType: 'image/png', detectedFormat: 'PNG' };
  }

  // Check JPEG
  if (matchesPrefix(MAGIC_SIGNATURES.jpg)) {
    return { valid: true, mimeType: 'image/jpeg', detectedFormat: 'JPEG' };
  }

  // Check ZIP / Office Docs
  if (matchesPrefix(MAGIC_SIGNATURES.zip)) {
    if (ext === '.docx') return { valid: true, mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', detectedFormat: 'DOCX' };
    if (ext === '.xlsx') return { valid: true, mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', detectedFormat: 'XLSX' };
    return { valid: true, mimeType: 'application/zip', detectedFormat: 'ZIP' };
  }

  // Plain Text / Markdown / CSV validation:
  // Must be strictly text (no null bytes \x00, no binary control chars, no HTML/script tags)
  if (['.txt', '.md', '.csv', '.json', '.log'].includes(ext)) {
    // Check for null bytes (hallmark of binary files)
    for (let i = 0; i < Math.min(buffer.length, 4096); i++) {
      if (buffer[i] === 0) {
        return { valid: false, error: 'File contains binary null bytes while claiming to be text.' };
      }
    }

    const textContent = buffer.toString('utf8');
    // Reject embedded active script vectors in text files
    if (/<script\b[^>]*>/i.test(textContent) || /javascript:/i.test(textContent)) {
      return { valid: false, error: 'Malicious Content Detected: Executable script patterns detected in text document.' };
    }

    const mime = ext === '.csv' ? 'text/csv' : ext === '.json' ? 'application/json' : 'text/plain';
    return { valid: true, mimeType: mime, detectedFormat: 'TEXT' };
  }

  return {
    valid: false,
    error: `Unsupported or unverified file type with extension "${ext}". Allowed types: PDF, PNG, JPG, DOCX, XLSX, TXT, CSV, MD.`
  };
}

/**
 * Sanitizes original filename to prevent directory traversal or filesystem exploitation.
 * @param {string} originalName 
 * @returns {string}
 */
export function sanitizeFilename(originalName) {
  if (!originalName || typeof originalName !== 'string') {
    return 'document.dat';
  }

  // 1. Strip any directory traversal (e.g. ../../)
  let base = path.basename(originalName);

  // 2. Replace null bytes and dangerous shell/fs characters
  base = base.replace(/[\0\r\n\t]/g, '');
  base = base.replace(/[^a-zA-Z0-9._-]/g, '_');

  // 3. Prevent hidden files or double dots
  base = base.replace(/^\.+/, 'doc_');

  // 4. Limit length
  if (base.length > 200) {
    const ext = path.extname(base);
    base = base.slice(0, 190) + ext;
  }

  return base || 'document.dat';
}
