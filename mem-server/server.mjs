import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, promises as fs } from 'node:fs';
import path from 'node:path';

const PORT = Number(process.env.PORT || 8788);
const MEM_ROOT = process.env.MEM_ROOT || '/srv/reiven-mem';
const FILES_DIR = path.join(MEM_ROOT, 'files');
const UPLOADS_DIR = path.join(MEM_ROOT, 'uploads');
const PART_SIZE_BYTES = Number(process.env.MEM_PART_SIZE_BYTES || 5 * 1024 * 1024);
const MAX_UPLOAD_AGE_MS = Number(process.env.MEM_UPLOAD_MAX_AGE_MS || 2 * 60 * 60 * 1000);
const CLEANUP_INTERVAL_MS = Number(process.env.MEM_CLEANUP_INTERVAL_MS || 60 * 1000);
const BEARER = String(process.env.MEM_BEARER_TOKEN || '').trim();

const uploads = new Map();
const files = new Map();

const logEvent = (event, details = {}) => {
  console.log(JSON.stringify({
    t: new Date().toISOString(),
    service: 'reiven-mem-server',
    event,
    ...details,
  }));
};

const tokenFingerprint = (value) => {
  const token = String(value || '').trim();
  if (!token) {
    return null;
  }
  return createHash('sha256').update(token).digest('hex').slice(0, 12);
};

const authSummary = (authorizationHeader) => {
  const raw = String(authorizationHeader || '');
  const trimmed = raw.trim();
  const spaceIndex = trimmed.indexOf(' ');
  const scheme = spaceIndex > 0 ? trimmed.slice(0, spaceIndex) : (trimmed ? '(no-scheme)' : '');
  const token = spaceIndex > 0 ? trimmed.slice(spaceIndex + 1).trim() : '';
  return {
    hasHeader: Boolean(trimmed),
    scheme: scheme || null,
    tokenLength: token.length || 0,
    tokenFingerprint: tokenFingerprint(token),
  };
};

const json = (res, status, payload) => {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
};

const noContent = (res) => {
  res.writeHead(204, { 'cache-control': 'no-store' });
  res.end();
};

const readJson = async (req) => {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return null;
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
};

const ensureDirs = async () => {
  await fs.mkdir(FILES_DIR, { recursive: true });
  await fs.mkdir(UPLOADS_DIR, { recursive: true });
};

const requireAuth = (req, res, context = {}) => {
  if (!BEARER) {
    logEvent('auth-bypass-no-bearer-configured', {
      reqId: context.reqId || null,
      method: req.method,
      path: context.path || null,
    });
    return true;
  }
  const value = String(req.headers.authorization || '');
  const expected = `Bearer ${BEARER}`;
  const providedAuth = authSummary(value);
  const expectedAuth = {
    scheme: 'Bearer',
    tokenLength: BEARER.length,
    tokenFingerprint: tokenFingerprint(BEARER),
  };

  if (value !== expected) {
    logEvent('auth-failed', {
      reqId: context.reqId || null,
      method: req.method,
      path: context.path || null,
      remoteAddress: req.socket?.remoteAddress || null,
      userAgent: String(req.headers['user-agent'] || ''),
      ...providedAuth,
      expectedScheme: expectedAuth.scheme,
      expectedTokenLength: expectedAuth.tokenLength,
      expectedTokenFingerprint: expectedAuth.tokenFingerprint,
    });
    json(res, 401, { error: 'Unauthorized' });
    return false;
  }
  logEvent('auth-ok', {
    reqId: context.reqId || null,
    method: req.method,
    path: context.path || null,
    remoteAddress: req.socket?.remoteAddress || null,
    ...providedAuth,
  });
  return true;
};

const nowIso = () => new Date().toISOString();

const uploadDirFor = (uploadId) => path.join(UPLOADS_DIR, uploadId);
const filePathFor = (fileId) => path.join(FILES_DIR, `${fileId}.bin`);

const normalizeFileIdFromObjectKey = (objectKey, fileIdFallback = '') => {
  const key = String(objectKey || '');
  if (key.startsWith('mem:')) {
    return key.slice(4);
  }
  return String(fileIdFallback || key || '').replace(/[^a-zA-Z0-9_-]/g, '');
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

const consumeToFile = async (req, filePath) => {
  const handle = await fs.open(filePath, 'w');
  let size = 0;
  const hash = createHash('sha256');
  try {
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      await handle.write(buf);
      hash.update(buf);
      size += buf.length;
    }
  } finally {
    await handle.close();
  }
  return {
    size,
    etag: hash.digest('hex'),
  };
};

const handleUploadInit = async (req, res) => {
  logEvent('upload-init-start');
  const body = await readJson(req);
  if (!body || typeof body !== 'object') {
    logEvent('upload-init-invalid-json');
    return json(res, 400, { error: 'Invalid JSON body' });
  }

  const fileId = String(body.fileId || '').trim();
  const objectKey = String(body.objectKey || '').trim();
  const originalName = String(body.originalName || 'encrypted.bin').slice(0, 255);
  const expectedSize = Number(body.size || 0);
  const createdAt = String(body.createdAt || nowIso());
  const expiresAt = String(body.expiresAt || nowIso());

  if (!fileId || !objectKey || !Number.isFinite(expectedSize) || expectedSize <= 0) {
    logEvent('upload-init-invalid-payload', {
      hasFileId: Boolean(fileId),
      hasObjectKey: Boolean(objectKey),
      expectedSize,
    });
    return json(res, 400, { error: 'Invalid upload init payload' });
  }

  const uploadId = randomBytes(16).toString('hex');
  const dir = uploadDirFor(uploadId);
  await fs.mkdir(dir, { recursive: true });

  uploads.set(uploadId, {
    uploadId,
    fileId,
    objectKey,
    originalName,
    expectedSize,
    createdAt,
    expiresAt,
    createdAtMs: Date.now(),
    dir,
    parts: new Map(),
  });

  logEvent('upload-init-complete', {
    uploadId,
    fileId,
    objectKey,
    expectedSize,
  });
  return json(res, 201, {
    uploadId,
    partSizeBytes: PART_SIZE_BYTES,
  });
};

const handleUploadPart = async (req, res, url) => {
  const uploadId = url.searchParams.get('uploadId');
  const partNumber = Number(url.searchParams.get('partNumber') || 0);
  logEvent('upload-part-start', { uploadId, partNumber });
  if (!uploadId || !Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
    logEvent('upload-part-invalid-query', { uploadId, partNumber });
    return json(res, 400, { error: 'Invalid uploadId or partNumber' });
  }

  const session = uploads.get(uploadId);
  if (!session) {
    logEvent('upload-part-missing-session', { uploadId, partNumber });
    return json(res, 404, { error: 'Upload session not found' });
  }

  const partPath = path.join(session.dir, `${partNumber}.part`);
  const { size, etag } = await consumeToFile(req, partPath);
  session.parts.set(partNumber, { etag, size, path: partPath });

  logEvent('upload-part-complete', { uploadId, partNumber, size, etag });
  return json(res, 200, {
    partNumber,
    etag,
  });
};

const handleUploadComplete = async (req, res) => {
  logEvent('upload-complete-start');
  const body = await readJson(req);
  if (!body || typeof body !== 'object') {
    logEvent('upload-complete-invalid-json');
    return json(res, 400, { error: 'Invalid JSON body' });
  }

  const uploadId = String(body.uploadId || '');
  const fileId = String(body.fileId || '');
  const objectKey = String(body.objectKey || '');
  const size = Number(body.size || 0);
  const parts = Array.isArray(body.parts) ? body.parts : [];

  if (!uploadId || !fileId || !objectKey || !Number.isFinite(size) || size <= 0 || parts.length === 0) {
    logEvent('upload-complete-invalid-payload', {
      uploadId,
      fileId,
      objectKey,
      size,
      partsLength: parts.length,
    });
    return json(res, 400, { error: 'Invalid upload completion payload' });
  }

  const session = uploads.get(uploadId);
  if (!session) {
    logEvent('upload-complete-missing-session', { uploadId, fileId });
    return json(res, 404, { error: 'Upload session not found' });
  }

  const normalizedParts = parts
    .map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag || '') }))
    .filter((p) => Number.isInteger(p.partNumber) && p.partNumber > 0 && p.etag)
    .sort((a, b) => a.partNumber - b.partNumber);

  if (normalizedParts.length === 0) {
    logEvent('upload-complete-no-valid-parts', { uploadId, fileId });
    return json(res, 400, { error: 'No valid parts provided' });
  }

  let total = 0;
  for (const part of normalizedParts) {
    const stored = session.parts.get(part.partNumber);
    if (!stored) {
      logEvent('upload-complete-missing-part', { uploadId, fileId, partNumber: part.partNumber });
      return json(res, 400, { error: `Missing uploaded part ${part.partNumber}` });
    }
    if (stored.etag !== part.etag) {
      logEvent('upload-complete-etag-mismatch', { uploadId, fileId, partNumber: part.partNumber });
      return json(res, 400, { error: `ETag mismatch for part ${part.partNumber}` });
    }
    total += stored.size;
  }

  const finalId = normalizeFileIdFromObjectKey(objectKey, fileId);
  if (!finalId) {
    logEvent('upload-complete-invalid-file-id', { uploadId, fileId, objectKey });
    return json(res, 400, { error: 'Invalid file id' });
  }
  const finalPath = filePathFor(finalId);
  const out = await fs.open(finalPath, 'w');
  try {
    for (const part of normalizedParts) {
      const stored = session.parts.get(part.partNumber);
      const data = await fs.readFile(stored.path);
      await out.write(data);
    }
  } finally {
    await out.close();
  }

  files.set(finalId, {
    id: finalId,
    objectKey,
    filePath: finalPath,
    size: total,
    originalName: session.originalName,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
  });

  await fs.rm(session.dir, { recursive: true, force: true });
  uploads.delete(uploadId);

  logEvent('upload-complete-finished', {
    uploadId,
    fileId,
    finalId,
    objectKey,
    size: total,
  });
  return json(res, 200, {
    id: finalId,
    size: total,
  });
};

const handleUploadAbort = async (req, res) => {
  const body = await readJson(req);
  const uploadId = body && typeof body.uploadId === 'string' ? body.uploadId : '';
  logEvent('upload-abort-start', { uploadId });
  if (!uploadId) {
    logEvent('upload-abort-missing-upload-id');
    return json(res, 400, { error: 'Missing uploadId' });
  }

  const session = uploads.get(uploadId);
  if (session) {
    await fs.rm(session.dir, { recursive: true, force: true });
    uploads.delete(uploadId);
  }
  logEvent('upload-abort-complete', { uploadId, sessionFound: Boolean(session) });
  return noContent(res);
};

const handleDownload = async (req, res, id) => {
  const file = files.get(id);
  if (!file) {
    return json(res, 404, { error: 'File not found' });
  }

  const expiresAtMs = Date.parse(file.expiresAt || '');
  if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) {
    await fs.rm(file.filePath, { force: true });
    files.delete(id);
    return json(res, 404, { error: 'File expired' });
  }

  let stat;
  try {
    stat = await fs.stat(file.filePath);
  } catch {
    files.delete(id);
    return json(res, 404, { error: 'File not found' });
  }

  const total = Number(stat.size || 0);
  const range = parseRange(req.headers.range, total);
  if (range && range.error) {
    res.writeHead(416, {
      'content-range': `bytes */${total}`,
      'cache-control': 'no-store',
    });
    res.end();
    return;
  }

  const headers = {
    'content-type': 'application/octet-stream',
    'content-disposition': `attachment; filename="${String(file.originalName || 'encrypted.bin').replace(/"/g, '')}"`,
    'cache-control': 'no-store',
    'accept-ranges': 'bytes',
  };

  if (!range) {
    headers['content-length'] = String(total);
    res.writeHead(200, headers);
    const stream = createReadStream(file.filePath);
    stream.pipe(res);
    return;
  }

  headers['content-range'] = `bytes ${range.start}-${range.end}/${total}`;
  headers['content-length'] = String(range.length);
  res.writeHead(206, headers);
  const stream = createReadStream(file.filePath, {
    start: range.start,
    end: range.end,
  });
  stream.pipe(res);
};

const handleDelete = async (res, id) => {
  const file = files.get(id);
  if (file) {
    await fs.rm(file.filePath, { force: true });
    files.delete(id);
  }
  return noContent(res);
};

const cleanup = async () => {
  const now = Date.now();

  for (const [uploadId, session] of uploads.entries()) {
    if ((now - session.createdAtMs) > MAX_UPLOAD_AGE_MS) {
      await fs.rm(session.dir, { recursive: true, force: true });
      uploads.delete(uploadId);
    }
  }

  for (const [id, file] of files.entries()) {
    const expiresAtMs = Date.parse(file.expiresAt || '');
    if (Number.isFinite(expiresAtMs) && expiresAtMs <= now) {
      await fs.rm(file.filePath, { force: true });
      files.delete(id);
    }
  }
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const reqId = randomBytes(6).toString('hex');
    logEvent('request-start', {
      reqId,
      method: req.method,
      path: url.pathname,
      query: url.searchParams.toString() || null,
      remoteAddress: req.socket?.remoteAddress || null,
      host: String(req.headers.host || ''),
      forwardedFor: String(req.headers['x-forwarded-for'] || ''),
      forwardedProto: String(req.headers['x-forwarded-proto'] || ''),
      userAgent: String(req.headers['user-agent'] || ''),
      contentLength: String(req.headers['content-length'] || ''),
    });

    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, {
        ok: true,
        filesInMemory: files.size,
        uploadsInMemory: uploads.size,
      });
    }

    if (!requireAuth(req, res, { reqId, path: url.pathname })) {
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/upload/init') {
      return await handleUploadInit(req, res);
    }

    if (req.method === 'POST' && url.pathname === '/api/upload/part') {
      return await handleUploadPart(req, res, url);
    }

    if (req.method === 'POST' && url.pathname === '/api/upload/complete') {
      return await handleUploadComplete(req, res);
    }

    if (req.method === 'POST' && url.pathname === '/api/upload/abort') {
      return await handleUploadAbort(req, res);
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/file/') && url.pathname.endsWith('/download')) {
      const id = decodeURIComponent(url.pathname.slice('/api/file/'.length, -'/download'.length));
      return await handleDownload(req, res, id);
    }

    if (req.method === 'DELETE' && url.pathname.startsWith('/api/file/')) {
      const id = decodeURIComponent(url.pathname.slice('/api/file/'.length));
      return await handleDelete(res, id);
    }

    return json(res, 404, { error: 'Not found' });
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return json(res, 500, { error: message });
  }
});

await ensureDirs();
setInterval(() => {
  cleanup().catch((err) => {
    console.error('[cleanup]', err && err.message ? err.message : err);
  });
}, CLEANUP_INTERVAL_MS).unref();

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[reiven-mem-server] listening on 127.0.0.1:${PORT}`);
  console.log(`[reiven-mem-server] root=${MEM_ROOT}`);
  console.log(`[reiven-mem-server] auth=${BEARER ? 'enabled' : 'disabled'}`);
});
