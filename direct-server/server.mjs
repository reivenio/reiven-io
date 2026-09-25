import { createReadStream, promises as fs } from 'node:fs';
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { parseHeader, FORMAT_VERSION } from '../public/envelope.mjs';
import { PUBLIC_PAGE_PATHS, SITE_SCHEMA } from '../shared/site-pages.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.resolve(process.env.PUBLIC_DIR || path.join(REPO_ROOT, 'public'));
const PUBLIC_PAGES = new Set(PUBLIC_PAGE_PATHS);
const TOOL_PAGES = new Set(['/share', '/receive', '/download']);
const SCHEMA_HASH = createHash('sha256').update(SITE_SCHEMA).digest('base64');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8080);
const DEFAULT_TTL_HOURS = 24;
const DEFAULT_MAX_FILE_SIZE_MB = 512;
const DEFAULT_MAX_MEMORY_STORAGE_MB = 2048;
const DEFAULT_PART_SIZE_BYTES = 50 * 1024 * 1024;
const DEFAULT_UPLOAD_MAX_AGE_MS = 30 * 60 * 1000;
const UPLOAD_IDLE_MS = 5 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 10 * 1000;
const CODE_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const CODE_RATE_LIMIT_MAX = 20;

const uploads = new Map();
const fileBlobs = new Map();
const rateBuckets = new Map();
const clientHashSalt = randomBytes(32).toString('hex');
let activeParts = 0;
let activeRequests = 0;
let db = {
  version: 1,
  files: {},
  accessCodes: {},
};

const BASE_SECURITY_HEADERS = Object.freeze({
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
});

const buildContentSecurityPolicy = (scriptNonce = '', publicPage = false) => {
  const scriptSrc = ["'self'", "'wasm-unsafe-eval'"];
  if (scriptNonce) {
    scriptSrc.push(`'nonce-${scriptNonce}'`);
  }
  if (publicPage) {
    scriptSrc.push(`'sha256-${SCHEMA_HASH}'`, 'https://www.googletagmanager.com');
  }
  const analyticsConnect = publicPage
    ? ' https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com'
    : '';
  const analyticsImages = publicPage
    ? ' https://*.google-analytics.com https://*.googletagmanager.com'
    : '';
  return [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `connect-src 'self'${analyticsConnect}`,
    `img-src 'self' data:${analyticsImages}`,
    "style-src 'self'",
    `script-src ${scriptSrc.join(' ')}`,
    "worker-src 'self'",
    "upgrade-insecure-requests",
  ].join('; ');
};

const withSecurityHeaders = (headers = {}, csp = buildContentSecurityPolicy()) => ({
  ...BASE_SECURITY_HEADERS,
  'content-security-policy': csp,
  ...headers,
});

const logEvent = (event, details = {}) => {
  console.log(JSON.stringify({
    t: new Date().toISOString(),
    service: 'reiven-direct-server',
    event,
    ...details,
  }));
};

const randomHex = (bytes = 16) => randomBytes(bytes).toString('hex');
const nowIso = () => new Date().toISOString();
const addHoursIso = (hours) => new Date(Date.now() + (hours * 60 * 60 * 1000)).toISOString();
const sha256Hex = (value) => createHash('sha256').update(String(value)).digest('hex');

const safeEqualString = (left, right) => {
  const leftBuffer = Buffer.from(String(left || ''));
  const rightBuffer = Buffer.from(String(right || ''));
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
};

const parseEnvNumber = (value, fallback) => {
  const num = Number(value);
  return Number.isFinite(num) && num > 0 ? num : fallback;
};

const getMaxMemoryBytes = () => parseEnvNumber(
  process.env.MAX_MEMORY_STORAGE_MB,
  DEFAULT_MAX_MEMORY_STORAGE_MB
) * 1024 * 1024;

const getStoredBytes = () => {
  let total = 0;
  for (const blob of fileBlobs.values()) {
    total += Number(blob.size || 0);
  }
  return total;
};

const getReservedUploadBytes = () => {
  let total = 0;
  for (const session of uploads.values()) {
    total += Number(session.expectedSize || 0);
  }
  return total;
};

const hasMemoryCapacityFor = (bytes) => (getStoredBytes() + getReservedUploadBytes() + bytes) <= getMaxMemoryBytes();

const getOrigin = (req) => {
  const configured = String(process.env.PUBLIC_BASE_URL || '').trim();
  if (configured) {
    return new URL(configured).origin;
  }
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() || 'http';
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return `${proto}://${host || `${HOST}:${PORT}`}`;
};

const getClientIp = (req) => {
  const peer = req.socket?.remoteAddress || '';
  const proxy = process.env.TRUST_PROXY === '1' && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer);
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').at(-1).trim();
  let address = proxy && isIP(forwarded) ? forwarded : peer;
  if (address.startsWith('::ffff:') && isIP(address.slice(7)) === 4) address = address.slice(7);
  if (isIP(address) === 6) {
    const [left, right = ''] = address.split('::');
    const leading = left ? left.split(':') : [];
    const trailing = right ? right.split(':') : [];
    address = [...leading, ...Array(Math.max(0, 8 - leading.length - trailing.length)).fill('0'), ...trailing]
      .slice(0, 4).map(part => Number.parseInt(part, 16).toString(16)).join(':');
  }
  return sha256Hex(`${clientHashSalt}:${address}`);
};

const expireUpload = (uploadId, session) => {
  uploads.delete(uploadId);
  session.cancelled = true;
  session.request?.destroy();
  session.parts.clear();
};

const isRateLimited = (key, maxRequests, windowMs) => {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    if (!bucket && rateBuckets.size >= 4096) return true;
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  bucket.count += 1;
  return bucket.count > maxRequests;
};

const normalizeAccessCode = (value) => {
  const digits = String(value || '').replace(/\D/g, '');
  return digits.length === 8 ? digits : null;
};

const formatAccessCode = (rawCode) => {
  const normalized = normalizeAccessCode(rawCode);
  return normalized ? normalized.match(/.{1,2}/g).join('-') : null;
};

const generateAccessCodeRaw = () => {
  let out = '';
  for (let i = 0; i < 8; i += 1) {
    out += String(randomInt(0, 10));
  }
  return out;
};

const escapeHtml = (value) => String(value || '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

const escapeHeaderValue = (value) => String(value || '')
  .replace(/[^\x20-\x21\x23-\x5b\x5d-\x7e]/g, '_')
  .slice(0, 255);

const json = (res, status, payload, headers = {}) => {
  if (res.destroyed || res.writableEnded) return;
  if (res.headersSent) return res.destroy();
  const body = JSON.stringify(payload);
  res.writeHead(status, withSecurityHeaders({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
    ...headers,
  }));
  res.end(body);
};

const text = (res, status, body, headers = {}) => {
  const value = String(body || '');
  res.writeHead(status, withSecurityHeaders({
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(value),
    ...headers,
  }));
  res.end(value);
};

const html = (res, status, body, headers = {}, nonce = '') => {
  res.writeHead(status, withSecurityHeaders({
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
    ...headers,
  }, buildContentSecurityPolicy(nonce)));
  res.end(body);
};

const noContent = (res) => {
  res.writeHead(204, withSecurityHeaders({ 'cache-control': 'no-store' }));
  res.end();
};

const redirect = (res, location) => {
  res.writeHead(308, withSecurityHeaders({
    location,
    'cache-control': 'no-store',
    'content-length': '0',
  }));
  res.end();
};

const readJson = async (req, limitBytes = 65536) => {
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
    throw Object.assign(new Error('JSON content type required'), { statusCode: 415 });
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.byteLength;
    if (total > limitBytes) {
      throw Object.assign(new Error('JSON body is too large'), { statusCode: 413 });
    }
    chunks.push(chunk);
  }
  if (!chunks.length) {
    return null;
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return null;
  }
};

const consumeToBuffer = async (req, limitBytes) => {
  const chunks = [];
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buf.length;
    if (Number.isFinite(limitBytes) && size > limitBytes) {
      const err = new Error('Upload part exceeds expected size');
      err.statusCode = 413;
      throw err;
    }
    chunks.push(buf);
    hash.update(buf);
  }
  return {
    size,
    etag: hash.digest('hex'),
    buffer: Buffer.concat(chunks, size),
  };
};

const deleteFileRecord = async (id) => {
  const row = db.files[id];
  if (!row) {
    return;
  }
  fileBlobs.delete(id);
  if (row.accessCodeHash) {
    delete db.accessCodes[row.accessCodeHash];
  }
  delete db.files[id];
};

const loadFileRow = async (id) => {
  const row = db.files[id];
  if (!row) {
    return null;
  }
  if (Date.parse(row.expiresAt) <= Date.now()) {
    await deleteFileRecord(id);
    return null;
  }
  if (!fileBlobs.has(id)) {
    await deleteFileRecord(id);
    return null;
  }
  return row;
};

const assignAccessCode = (fileId, maxAttempts = 50) => {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const code = generateAccessCodeRaw();
    const codeHash = sha256Hex(code);
    if (!db.accessCodes[codeHash]) {
      db.accessCodes[codeHash] = fileId;
      return { code, codeHash };
    }
  }
  throw new Error('Could not allocate unique access code');
};

const parseRange = (headerValue, totalSize) => {
  if (!headerValue) return null;
  const m = String(headerValue).match(/^bytes=(\d+)-(\d+)?$/i);
  if (!m) return { error: true };
  const start = Number(m[1]);
  let end = m[2] ? Number(m[2]) : totalSize - 1;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || start >= totalSize) {
    return { error: true };
  }
  end = Math.min(end, totalSize - 1);
  return { start, end, length: (end - start) + 1 };
};

const mimeFor = (filePath) => {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') return 'text/html; charset=utf-8';
  if (ext === '.css') return 'text/css; charset=utf-8';
  if (ext === '.js' || ext === '.mjs') return 'text/javascript; charset=utf-8';
  if (ext === '.json') return 'application/json; charset=utf-8';
  if (ext === '.xml') return 'application/xml; charset=utf-8';
  if (ext === '.txt') return 'text/plain; charset=utf-8';
  if (ext === '.wasm') return 'application/wasm';
  if (ext === '.svg') return 'image/svg+xml';
  if (ext === '.png') return 'image/png';
  if (ext === '.ico') return 'image/x-icon';
  return 'application/octet-stream';
};

const resolvePublicPath = (pathname) => {
  let routePath = decodeURIComponent(pathname);
  if (routePath === '/') {
    routePath = '/index.html';
  } else if (routePath === '/share' || routePath === '/receive') {
    routePath = '/share.html';
  } else if (routePath === '/download') {
    routePath = '/download.html';
  } else if (PUBLIC_PAGES.has(routePath)) {
    routePath = `${routePath}.html`;
  }
  const normalized = path.normalize(routePath).replace(/^(\.\.[/\\])+/, '');
  const fullPath = path.join(PUBLIC_DIR, normalized);
  if (!fullPath.startsWith(`${path.resolve(PUBLIC_DIR)}${path.sep}`)) {
    return null;
  }
  return fullPath;
};

const serveStatic = async (req, res, url) => {
  const alias = url.pathname === '/index.html' ? '/' : url.pathname.replace(/\.html$|\/$/g, '');
  if (alias !== url.pathname && (PUBLIC_PAGES.has(alias) || TOOL_PAGES.has(alias))) {
    return redirect(res, `${alias}${url.search}`);
  }

  const filePath = resolvePublicPath(url.pathname);
  if (!filePath) {
    return text(res, 403, 'Forbidden');
  }

  let stat;
  try {
    stat = await fs.stat(filePath);
  } catch {
    return text(res, 404, 'Not found');
  }
  if (!stat.isFile()) {
    return text(res, 404, 'Not found');
  }

  const headers = {
    'content-type': mimeFor(filePath),
    'cache-control': 'public, max-age=0, must-revalidate',
    'content-length': String(stat.size),
  };
  if (TOOL_PAGES.has(url.pathname)) {
    headers['x-robots-tag'] = 'noindex, nofollow, noarchive';
    headers['cache-control'] = 'no-store';
  }

  res.writeHead(200, withSecurityHeaders(headers, buildContentSecurityPolicy('', PUBLIC_PAGES.has(url.pathname))));
  if (req.method === 'HEAD') {
    return res.end();
  }
  createReadStream(filePath).pipe(res);
};

const handleUploadInit = async (req, res) => {
  await cleanup();
  const ownerKey = getClientIp(req);
  if (isRateLimited('upload-global', 120, 60000) || isRateLimited(`upload:${ownerKey}`, 10, 60000)) {
    return json(res, 429, { error: 'Too many upload requests. Try again later.' }, { 'retry-after': '60' });
  }
  const body = await readJson(req);
  if (!body || typeof body !== 'object') {
    return json(res, 400, { error: 'Invalid JSON body' });
  }

  if (body.formatVersion !== FORMAT_VERSION) return json(res, 400, { error: 'Refresh or update your client: encryption format 6 is required.' });

  const expectedSize = Number(body.size || 0);
  const maxMb = parseEnvNumber(process.env.MAX_FILE_SIZE_MB, DEFAULT_MAX_FILE_SIZE_MB);
  const maxBytes = maxMb * 1024 * 1024;
  if (!Number.isSafeInteger(expectedSize) || expectedSize <= 0) {
    return json(res, 400, { error: 'Invalid file size' });
  }
  if (expectedSize > maxBytes) {
    return json(res, 413, { error: `File exceeds ${maxMb}MB limit` });
  }
  const ownedUploads = [...uploads.values()].filter(session => session.ownerKey === ownerKey);
  const ownedFiles = Object.values(db.files).filter(row => row.ownerKey === ownerKey);
  const ownerBytes = ownedFiles.reduce((total, row) => total + row.size, 0) + ownedUploads.reduce((total, session) => total + session.expectedSize, 0);
  const ownerLimit = Math.min(maxBytes, getMaxMemoryBytes() / 4);
  if (ownedUploads.length >= 1 || ownedFiles.length >= 64 || ownerBytes + expectedSize > ownerLimit) {
    return json(res, 429, { error: 'Client storage or active-upload quota reached. Finish, delete, or wait for existing shares to expire.' });
  }
  if (uploads.size >= 32 || Object.keys(db.files).length + uploads.size >= 1024 || getReservedUploadBytes() + expectedSize > getMaxMemoryBytes() / 2) {
    return json(res, 503, { error: 'Upload capacity temporarily busy.' }, { 'retry-after': '60' });
  }
  if (!hasMemoryCapacityFor(expectedSize)) {
    const maxMemoryMb = parseEnvNumber(process.env.MAX_MEMORY_STORAGE_MB, DEFAULT_MAX_MEMORY_STORAGE_MB);
    return json(res, 507, { error: `Server memory storage limit reached (${maxMemoryMb}MB)` });
  }

  const fileId = randomHex(9);
  const uploadId = randomHex(16);
  const deleteToken = randomHex(24);
  const ttlHours = parseEnvNumber(process.env.FILE_TTL_HOURS, DEFAULT_TTL_HOURS);
  const createdAt = nowIso();
  const expiresAt = addHoursIso(ttlHours);

  uploads.set(uploadId, {
    uploadId,
    fileId,
    originalName: String(body.originalName || 'encrypted.bin').trim().slice(0, 255) || 'encrypted.bin',
    expectedSize,
    ownerKey,
    busy: false,
    cancelled: false,
    lastActivityMs: Date.now(),
    createdAt,
    expiresAt,
    deleteToken,
    allowReceiverDelete: body.allowReceiverDelete === true || body.allowReceiverDelete === 1 || body.allowReceiverDelete === '1',
    isNote: body.isNote === true || body.isNote === 1 || body.isNote === '1',
    createdAtMs: Date.now(),
    receivedSize: 0,
    parts: new Map(),
  });

  return json(res, 201, {
    uploadId,
    partSizeBytes: Math.min(parseEnvNumber(process.env.PART_SIZE_BYTES, DEFAULT_PART_SIZE_BYTES), DEFAULT_PART_SIZE_BYTES),
  });
};

const handleUploadPart = async (req, res, url) => {
  const uploadId = url.searchParams.get('uploadId');
  const partNumber = Number(url.searchParams.get('partNumber') || 0);
  if (!uploadId || !Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
    return json(res, 400, { error: 'Invalid uploadId or partNumber' });
  }

  const session = uploads.get(uploadId);
  if (!session) {
    return json(res, 404, { error: 'Upload session not found' });
  }
  if (session.ownerKey !== getClientIp(req)) return json(res, 403, { error: 'Upload belongs to another client.' });
  if (session.busy) return json(res, 409, { error: 'Another part is already in progress.' });
  if (activeParts >= 8) return json(res, 503, { error: 'Upload readers are busy. Retry later.' });
  if (session.parts.has(partNumber)) {
    return json(res, 409, { error: `Part ${partNumber} already uploaded` });
  }

  let uploaded;
  session.busy = true;
  session.request = req;
  session.lastActivityMs = Date.now();
  activeParts += 1;
  const deadline = setTimeout(() => req.destroy(), 120000);
  try {
    uploaded = await consumeToBuffer(req, Math.min(session.expectedSize - session.receivedSize, DEFAULT_PART_SIZE_BYTES));
    if (session.cancelled || uploads.get(uploadId) !== session) return json(res, 410, { error: 'Upload expired or aborted.' });
    if (uploaded.size <= 0) return json(res, 400, { error: 'Upload part is empty' });
    session.parts.set(partNumber, uploaded);
    session.receivedSize += uploaded.size;
    session.lastActivityMs = Date.now();
    return json(res, 200, { partNumber, etag: uploaded.etag });
  } catch (err) {
    expireUpload(uploadId, session);
    return json(res, err.statusCode || 400, { error: 'Upload part failed; start a new upload.' });
  } finally {
    clearTimeout(deadline);
    activeParts -= 1;
    session.busy = false;
    session.request = null;
  }
};

const handleUploadComplete = async (req, res) => {
  const body = await readJson(req);
  if (!body || typeof body !== 'object') {
    return json(res, 400, { error: 'Invalid JSON body' });
  }
  const uploadId = String(body.uploadId || '');
  const size = Number(body.size || 0);
  const partsRaw = Array.isArray(body.parts) ? body.parts : [];
  const session = uploads.get(uploadId);
  if (!session) {
    return json(res, 404, { error: 'Upload session not found' });
  }

  const parts = partsRaw
    .map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag || '') }))
    .filter((p) => Number.isInteger(p.partNumber) && p.partNumber > 0 && p.etag)
    .sort((a, b) => a.partNumber - b.partNumber);

  if (session.ownerKey !== getClientIp(req)) return json(res, 403, { error: 'Upload belongs to another client.' });
  if (session.busy || session.cancelled) return json(res, 409, { error: 'Upload is not ready to complete.' });
  if (!Number.isSafeInteger(size) || size <= 0 || parts.length === 0 || parts.length !== partsRaw.length || parts.length !== session.parts.size || parts.some((part, index) => part.partNumber !== index + 1)) {
    return json(res, 400, { error: 'Invalid upload completion payload' });
  }

  let total = 0;
  for (const part of parts) {
    const stored = session.parts.get(part.partNumber);
    if (!stored) {
      return json(res, 400, { error: `Missing uploaded part ${part.partNumber}` });
    }
    if (stored.etag !== part.etag) {
      return json(res, 400, { error: `ETag mismatch for part ${part.partNumber}` });
    }
    total += stored.size;
  }

  if (total !== size || total !== session.expectedSize || total !== session.receivedSize) {
    return json(res, 400, { error: 'Uploaded size does not match expected size' });
  }

  const probeParts = [];
  let probeRemaining = 4096;
  for (const part of parts) {
    const bytes = session.parts.get(part.partNumber).buffer.subarray(0, probeRemaining);
    probeParts.push(bytes);
    probeRemaining -= bytes.length;
    if (!probeRemaining) break;
  }
  try {
    if (parseHeader(Buffer.concat(probeParts)).encryptedSize !== total) throw new Error('Size mismatch');
  } catch {
    expireUpload(uploadId, session);
    return json(res, 400, { error: 'Invalid version 6 encrypted envelope.' });
  }
  const { code, codeHash } = assignAccessCode(session.fileId);

  fileBlobs.set(session.fileId, {
    size: total,
    parts: parts.map((part) => session.parts.get(part.partNumber).buffer),
  });

  db.files[session.fileId] = {
    id: session.fileId,
    originalName: session.originalName,
    size: total,
    ownerKey: session.ownerKey,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    deleteToken: session.deleteToken,
    downloadCount: 0,
    allowReceiverDelete: session.allowReceiverDelete,
    isNote: session.isNote,
    accessCodeHash: codeHash,
  };

  uploads.delete(uploadId);

  const base = getOrigin(req);
  return json(res, 201, {
    id: session.fileId,
    size: total,
    expiresAt: session.expiresAt,
    downloadUrl: `${base}/download?id=${session.fileId}`,
    deleteUrl: `${base}/delete/${session.fileId}/${session.deleteToken}`,
    allowReceiverDelete: session.allowReceiverDelete,
    isNote: session.isNote,
    accessCode: formatAccessCode(code),
  });
};

const handleUploadAbort = async (req, res) => {
  const body = await readJson(req);
  const uploadId = body && typeof body.uploadId === 'string' ? body.uploadId : '';
  if (!uploadId) {
    return json(res, 400, { error: 'Missing uploadId' });
  }
  const session = uploads.get(uploadId);
  if (session) {
    if (session.ownerKey !== getClientIp(req)) return json(res, 403, { error: 'Upload belongs to another client.' });
    expireUpload(uploadId, session);
  }
  return noContent(res);
};

const fileInfoPayload = (req, row) => ({
  id: row.id,
  size: row.size,
  createdAt: row.createdAt,
  expiresAt: row.expiresAt,
  downloadCount: row.downloadCount || 0,
  allowReceiverDelete: row.allowReceiverDelete === true,
  deleteUrl: row.allowReceiverDelete === true ? `${getOrigin(req)}/delete/${row.id}/${row.deleteToken}` : null,
  isNote: row.isNote === true,
  accessCode: null,
});

const handleFileInfo = async (req, res, id) => {
  const row = await loadFileRow(id);
  if (!row) {
    return json(res, 404, { error: 'File not found or expired' });
  }
  return json(res, 200, fileInfoPayload(req, row));
};

const handleFileInfoByCode = async (req, res, codeInput) => {
  const codeRaw = normalizeAccessCode(codeInput);
  if (!codeRaw) {
    return json(res, 400, { error: 'Invalid code format' });
  }
  const fileId = db.accessCodes[sha256Hex(codeRaw)];
  const row = fileId ? await loadFileRow(fileId) : null;
  if (!row) {
    return json(res, 404, { error: 'File not found or expired' });
  }
  return json(res, 200, {
    ...fileInfoPayload(req, row),
    downloadUrl: `${getOrigin(req)}/download?id=${row.id}`,
    accessCode: formatAccessCode(codeRaw),
  });
};

const writeStoredBlob = async (res, blob, range = null) => {
  const start = range ? range.start : 0;
  const end = range ? range.end : blob.size - 1;
  let offset = 0;

  for (const part of blob.parts) {
    const partStart = offset;
    const partEnd = offset + part.length - 1;
    offset += part.length;

    if (partEnd < start || partStart > end) {
      continue;
    }

    const sliceStart = Math.max(0, start - partStart);
    const sliceEnd = Math.min(part.length, (end - partStart) + 1);
    const chunk = part.subarray(sliceStart, sliceEnd);
    if (chunk.length && !res.write(chunk)) {
      await new Promise((resolve, reject) => {
        const clear = () => { res.off('drain', drained); res.off('close', closed); res.off('error', closed); };
        const drained = () => { clear(); resolve(); };
        const closed = () => { clear(); reject(new Error('Download closed')); };
        res.once('drain', drained);
        res.once('close', closed);
        res.once('error', closed);
        if (res.destroyed) closed();
      });
    }
  }

  res.end();
};

const handleDownload = async (req, res, id) => {
  const row = await loadFileRow(id);
  if (!row) {
    return json(res, 404, { error: 'File not found or expired' });
  }

  const blob = fileBlobs.get(id);
  if (!blob) {
    await deleteFileRecord(id);
    return json(res, 404, { error: 'File not found or expired' });
  }

  const total = Number(blob.size || 0);
  const range = parseRange(req.headers.range, total);
  if (range && range.error) {
    res.writeHead(416, withSecurityHeaders({
      'content-range': `bytes */${total}`,
      'cache-control': 'no-store',
    }));
    res.end();
    return;
  }

  if (!range) {
    row.downloadCount = Number(row.downloadCount || 0) + 1;
  }

  const headers = {
    'content-type': 'application/octet-stream',
    'content-disposition': `attachment; filename="${escapeHeaderValue(row.originalName || 'encrypted.bin')}"`,
    'cache-control': 'no-store',
    'accept-ranges': 'bytes',
  };

  if (!range) {
    res.writeHead(200, withSecurityHeaders({
      ...headers,
      'content-length': String(total),
    }));
    return writeStoredBlob(res, blob);
  }

  res.writeHead(206, withSecurityHeaders({
    ...headers,
    'content-range': `bytes ${range.start}-${range.end}/${total}`,
    'content-length': String(range.length),
  }));
  return writeStoredBlob(res, blob, range);
};

const handleDeleteApi = async (req, res, id) => {
  const token = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`).searchParams.get('token');
  if (!token) {
    return json(res, 400, { error: 'Missing delete token' });
  }
  const row = await loadFileRow(id);
  if (!row) {
    return json(res, 404, { error: 'File not found or expired' });
  }
  if (!safeEqualString(token, row.deleteToken)) {
    return json(res, 403, { error: 'Invalid token' });
  }
  await deleteFileRecord(id);
  return noContent(res);
};

const renderDeletePage = ({ title, message, id = '', token = '', showConfirm = false, statusCode = 200 }, res) => {
  const nonce = randomHex(18);
  const page = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="noindex, nofollow, noarchive" />
    <meta name="theme-color" content="#080c0e" />
    <title>Reiven.io Delete</title>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body>
    <main class="app-shell">
      <header class="site-header">
        <a class="brand-mark" href="/">reiven.io</a>
        <nav class="site-nav" aria-label="Primary">
          <a class="nav-link" href="/share">share</a>
          <a class="nav-link" href="/receive">download</a>
          <a class="nav-link" href="/cli">cli</a>
        </nav>
      </header>

      <section class="page-panel delete-shell">
        <section id="delete-card" class="utility-card delete-card" data-file-id="${escapeHtml(id)}" data-token="${escapeHtml(token)}">
          <div class="download-form">
            <p id="delete-title" class="share-title">${escapeHtml(title)}</p>
            <p id="delete-message" class="delete-message">${escapeHtml(message)}</p>
            ${showConfirm ? `
            <div id="delete-actions" class="delete-actions">
              <button id="delete-yes-btn" type="button" class="cta-btn">Yes</button>
              <button id="delete-no-btn" type="button" class="cta-btn delete-no-btn">No</button>
            </div>
            ` : ''}
          </div>
        </section>

        <a id="delete-back-link" href="/" class="cta-btn delete-back-btn">Back to reiven.io</a>
      </section>

      <footer class="footer-note">
        Encrypted in your browser · Temporary server-memory storage · No accounts
      </footer>
    </main>

    <script nonce="${nonce}">
      (function () {
        var card = document.getElementById('delete-card');
        if (!card) return;
        var titleEl = document.getElementById('delete-title');
        var yesBtn = document.getElementById('delete-yes-btn');
        var noBtn = document.getElementById('delete-no-btn');
        var msgEl = document.getElementById('delete-message');
        var actionsEl = document.getElementById('delete-actions');
        var backLinkEl = document.getElementById('delete-back-link');
        if (!msgEl || !yesBtn || !noBtn) return;

        var fileId = card.getAttribute('data-file-id') || '';
        var token = card.getAttribute('data-token') || '';
        var done = false;
        var setMessage = function (text, isError, nextTitle) {
          if (titleEl && nextTitle) titleEl.textContent = nextTitle;
          msgEl.textContent = text;
          card.classList.toggle('error', !!isError);
        };

        noBtn.addEventListener('click', function () { window.location.href = '/'; });
        yesBtn.addEventListener('click', async function () {
          if (done) return;
          done = true;
          yesBtn.disabled = true;
          noBtn.disabled = true;
          setMessage('Deleting file...', false);
          try {
            var res = await fetch('/api/file/' + encodeURIComponent(fileId) + '?token=' + encodeURIComponent(token), { method: 'DELETE' });
            if (!res.ok) {
              var text = 'Deletion failed.';
              try {
                var payload = await res.json();
                text = payload && payload.error ? payload.error : text;
              } catch (_) {}
              setMessage(text, true, 'Delete file');
              done = false;
              yesBtn.disabled = false;
              noBtn.disabled = false;
              return;
            }
            if (actionsEl) actionsEl.remove();
            setMessage('File deleted successfully.', false, 'Delete file');
            if (backLinkEl) backLinkEl.focus();
          } catch (_) {
            setMessage('Network error while deleting file.', true, 'Delete file');
            done = false;
            yesBtn.disabled = false;
            noBtn.disabled = false;
          }
        });
      })();
    </script>
  </body>
</html>`;
  html(res, statusCode, page, {}, nonce);
};

const handleDeletePage = async (req, res, id, token) => {
  const row = await loadFileRow(id);
  if (!row) {
    return renderDeletePage({
      title: 'Delete File',
      message: 'File not found or expired.',
      statusCode: 404,
    }, res);
  }
  if (!safeEqualString(token, row.deleteToken)) {
    return renderDeletePage({
      title: 'Delete File',
      message: 'Invalid delete token.',
      statusCode: 403,
    }, res);
  }
  return renderDeletePage({
    title: 'Delete File',
    message: `Are you sure you want to delete file ${row.id}?`,
    id: row.id,
    token,
    showConfirm: true,
  }, res);
};

const cleanup = async () => {
  const now = Date.now();
  for (const [uploadId, session] of uploads.entries()) {
    if (now - session.lastActivityMs > UPLOAD_IDLE_MS || (now - session.createdAtMs) > parseEnvNumber(process.env.UPLOAD_MAX_AGE_MS, DEFAULT_UPLOAD_MAX_AGE_MS)) {
      expireUpload(uploadId, session);
    }
  }
  for (const [key, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(key);
  }
  for (const [id, row] of Object.entries(db.files)) {
    if (Date.parse(row.expiresAt) <= now) {
      if (row.accessCodeHash) {
        delete db.accessCodes[row.accessCodeHash];
      }
      fileBlobs.delete(id);
      delete db.files[id];
    }
  }
};

const routeRequest = async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const { pathname } = url;
  if (req.headers.origin && req.headers.origin !== getOrigin(req)) return json(res, 403, { error: 'Cross-origin requests are not permitted.' });
  if (pathname.startsWith('/api/') || pathname.startsWith('/delete/') || pathname === '/health' || TOOL_PAGES.has(pathname.replace(/\.html$|\/$/g, ''))) {
    res.setHeader('x-robots-tag', 'noindex, nofollow, noarchive');
  }

  if (req.method === 'GET' && pathname === '/health') {
    return json(res, 200, { ok: true, files: Object.keys(db.files).length, uploads: uploads.size });
  }
  if (req.method === 'POST' && pathname === '/api/upload/init') {
    return handleUploadInit(req, res);
  }
  if (req.method === 'POST' && pathname === '/api/upload/part') {
    return handleUploadPart(req, res, url);
  }
  if (req.method === 'POST' && pathname === '/api/upload/complete') {
    return handleUploadComplete(req, res);
  }
  if (req.method === 'POST' && pathname === '/api/upload/abort') {
    return handleUploadAbort(req, res);
  }
  if (req.method === 'GET' && pathname === '/api/encryption-config') {
    const mod = await import('../shared/encryption-config.mjs');
    return json(res, 200, mod.ENCRYPTION_CONFIG);
  }
  if (req.method === 'GET' && pathname.startsWith('/api/file/') && pathname.endsWith('/info')) {
    if (pathname.startsWith('/api/file/code/')) {
      if (isRateLimited(`code:${getClientIp(req)}`, CODE_RATE_LIMIT_MAX, CODE_RATE_LIMIT_WINDOW_MS)) {
        return json(res, 429, { error: 'Too many code attempts. Try again shortly.' });
      }
      const code = pathname.slice('/api/file/code/'.length, -'/info'.length);
      return handleFileInfoByCode(req, res, code);
    }
    const id = pathname.slice('/api/file/'.length, -'/info'.length);
    return handleFileInfo(req, res, id);
  }
  if (req.method === 'GET' && pathname.startsWith('/api/file/') && pathname.endsWith('/download')) {
    const id = pathname.slice('/api/file/'.length, -'/download'.length);
    return handleDownload(req, res, id);
  }
  if (req.method === 'DELETE' && pathname.startsWith('/api/file/')) {
    const id = pathname.slice('/api/file/'.length);
    return handleDeleteApi(req, res, id);
  }
  if (req.method === 'GET' && pathname.startsWith('/delete/')) {
    const parts = pathname.split('/');
    if (parts.length === 4) {
      return handleDeletePage(req, res, decodeURIComponent(parts[2]), decodeURIComponent(parts[3]));
    }
  }
  if (pathname.startsWith('/api/')) {
    return json(res, 404, { error: 'API route not found' });
  }
  if (req.method === 'GET' || req.method === 'HEAD') {
    return serveStatic(req, res, url);
  }
  return text(res, 405, 'Method not allowed', { allow: 'GET, HEAD, POST, DELETE' });
};

const main = async () => {
  await cleanup();
  setInterval(() => cleanup().catch((err) => {
    console.error('[cleanup]', err && err.message ? err.message : err);
  }), CLEANUP_INTERVAL_MS).unref();

  const server = createServer((req, res) => {
    if (activeRequests >= 128) return json(res, 503, { error: 'Server busy.' });
    activeRequests += 1;
    let released = false;
    const release = () => { if (!released) { released = true; activeRequests -= 1; } };
    res.once('close', release);
    res.once('finish', release);
    routeRequest(req, res).catch((err) => {
      logEvent('request-error', { method: req.method, status: err.statusCode || 500 });
      json(res, err.statusCode || 500, { error: 'Request could not be completed.' });
    });
  });
  server.maxConnections = 128;
  server.maxRequestsPerSocket = 100;
  server.headersTimeout = 15000;
  server.requestTimeout = 120000;
  server.setTimeout(120000, socket => socket.destroy());

  server.listen(PORT, HOST, () => {
    logEvent('server-start', {
      host: HOST,
      port: PORT,
      storage: 'memory',
      maxFileMb: parseEnvNumber(process.env.MAX_FILE_SIZE_MB, DEFAULT_MAX_FILE_SIZE_MB),
      maxMemoryStorageMb: parseEnvNumber(process.env.MAX_MEMORY_STORAGE_MB, DEFAULT_MAX_MEMORY_STORAGE_MB),
      publicDir: PUBLIC_DIR,
    });
  });
};

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
