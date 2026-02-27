import { ENCRYPTION_CONFIG } from '../shared/encryption-config.mjs';

const DEFAULT_TTL_HOURS = 24;
const DEFAULT_MAX_FILE_SIZE_MB = 2048;
const DEFAULT_PART_SIZE_BYTES = 50 * 1024 * 1024;
const STORAGE_RAMDISK = "ramdisk";
const STORAGE_R2 = "r2";
const STORAGE_MEM_LEGACY = "mem";

const json = (body, init = {}) => new Response(JSON.stringify(body), {
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  },
  ...init,
});

const text = (body, init = {}) => new Response(body, {
  headers: {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
  },
  ...init,
});

const html = (body, init = {}) => new Response(body, {
  headers: {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  },
  ...init,
});

const nowIso = () => new Date().toISOString();
const addHoursIso = (hours) => new Date(Date.now() + (hours * 60 * 60 * 1000)).toISOString();

const randomId = (bytes = 9) => {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, '0')).join('');
};

const parseEnvNumber = (value, fallback) => {
  const num = Number(value);
  return Number.isFinite(num) && num > 0 ? num : fallback;
};

const parseStorageMode = (value) => {
  const mode = String(value || "").trim().toLowerCase();
  if (mode === STORAGE_RAMDISK || mode === STORAGE_MEM_LEGACY) {
    return STORAGE_RAMDISK;
  }
  if (mode === STORAGE_R2) {
    return STORAGE_R2;
  }
  return STORAGE_RAMDISK;
};

const parseDeploymentStorageBackend = (env) => {
  const value = String(env.STORAGE_BACKEND || "").trim().toLowerCase();
  if (value === STORAGE_R2) {
    return STORAGE_R2;
  }
  return STORAGE_RAMDISK;
};

const isRamdiskObjectKey = (value) => {
  const objectKey = String(value || "");
  return objectKey.startsWith("ramdisk:") || objectKey.startsWith("mem:");
};

const getMemBaseUrl = (env) => {
  const raw = String(env.MEM_STORAGE_BASE_URL || "").trim();
  if (!raw) {
    return null;
  }
  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
};

const memFetch = async (env, path, init = {}) => {
  const base = getMemBaseUrl(env);
  if (!base) {
    throw new Error('Memory storage backend is not configured');
  }

  const headers = new Headers(init.headers || {});
  const token = String(env.MEM_STORAGE_BEARER_TOKEN || '').trim();
  if (token) {
    headers.set('authorization', `Bearer ${token}`);
  }

  return fetch(`${base}${path}`, {
    ...init,
    headers,
  });
};

const parseJsonSafe = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const generateAccessCodeRaw = () => {
  const arr = new Uint8Array(8);
  crypto.getRandomValues(arr);
  return [...arr].map((v) => String(v % 10)).join('');
};

const normalizeAccessCode = (value) => {
  const digits = String(value || '').replace(/\D/g, '');
  return digits.length === 8 ? digits : null;
};

const formatAccessCode = (rawCode) => {
  const normalized = normalizeAccessCode(rawCode);
  if (!normalized) {
    return null;
  }
  return normalized.match(/.{1,2}/g).join('-');
};

const logApi = (request, message, extra = {}) => {
  const url = new URL(request.url);
  console.log(JSON.stringify({
    t: new Date().toISOString(),
    method: request.method,
    path: url.pathname,
    message,
    ...extra,
  }));
};

const deleteFileRecord = async (env, row) => {
  const deleteBlobPromise = isRamdiskObjectKey(row.object_key)
    ? memFetch(env, `/api/file/${encodeURIComponent(row.id)}`, { method: 'DELETE' })
    : env.FILES.delete(row.object_key);

  await Promise.allSettled([
    deleteBlobPromise,
    env.DB.prepare('DELETE FROM file_codes WHERE file_id = ?1').bind(row.id).run(),
    env.DB.prepare('DELETE FROM files WHERE id = ?1').bind(row.id).run(),
  ]);
};

const loadFileRow = async (env, id) => {
  const row = await env.DB
    .prepare('SELECT f.id, f.object_key, f.original_name, f.size, f.created_at, f.expires_at, f.delete_token, f.download_count, f.allow_receiver_delete, fc.access_code FROM files f LEFT JOIN file_codes fc ON fc.file_id = f.id WHERE f.id = ?1')
    .bind(id)
    .first();

  if (!row) {
    return null;
  }

  if (Date.parse(row.expires_at) <= Date.now()) {
    await deleteFileRecord(env, row);
    return null;
  }

  return row;
};

const loadFileRowByCode = async (env, rawCode) => {
  const row = await env.DB
    .prepare('SELECT f.id, f.object_key, f.original_name, f.size, f.created_at, f.expires_at, f.delete_token, f.download_count, f.allow_receiver_delete, fc.access_code FROM file_codes fc JOIN files f ON f.id = fc.file_id WHERE fc.access_code = ?1')
    .bind(rawCode)
    .first();

  if (!row) {
    return null;
  }

  if (Date.parse(row.expires_at) <= Date.now()) {
    await deleteFileRecord(env, row);
    return null;
  }

  return row;
};

const loadUploadRow = async (env, uploadId) => {
  return env.DB
    .prepare('SELECT upload_id, file_id, object_key, original_name, created_at, expires_at, delete_token, expected_size, allow_receiver_delete FROM uploads WHERE upload_id = ?1')
    .bind(uploadId)
    .first();
};

const assignUniqueAccessCode = async (env, fileId, maxAttempts = 30) => {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const code = generateAccessCodeRaw();
    try {
      await env.DB.prepare('INSERT INTO file_codes (file_id, access_code) VALUES (?1, ?2)')
        .bind(fileId, code)
        .run();
      return code;
    } catch (err) {
      const msg = String(err && err.message ? err.message : err);
      if (msg.includes('UNIQUE')) {
        continue;
      }
      throw err;
    }
  }
  throw new Error('Could not allocate unique access code');
};

const getOrigin = (request) => new URL(request.url).origin;

const readJsonBody = async (request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const parseAllowReceiverDelete = (value) => {
  return value === true || value === 1 || value === '1' || String(value || '').toLowerCase() === 'true';
};

const handleUploadInit = async (request, env) => {
  logApi(request, 'upload-init-start');

  const body = await readJsonBody(request);
  if (!body || typeof body !== 'object') {
    return json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const expectedSize = Number(body.size || 0);
  const requestedStorageMode = parseStorageMode(body.storage);
  const deploymentStorageBackend = parseDeploymentStorageBackend(env);
  const storageMode = deploymentStorageBackend === STORAGE_RAMDISK
    ? STORAGE_RAMDISK
    : requestedStorageMode;
  const originalNameHeader = String(body.originalName || '').trim();
  const originalName = (originalNameHeader || 'encrypted.bin').slice(0, 255);
  const allowReceiverDelete = parseAllowReceiverDelete(body.allowReceiverDelete);

  if (!Number.isFinite(expectedSize) || expectedSize <= 0) {
    return json({ error: 'Invalid file size' }, { status: 400 });
  }

  const maxMb = parseEnvNumber(env.MAX_FILE_SIZE_MB, DEFAULT_MAX_FILE_SIZE_MB);
  const maxBytes = maxMb * 1024 * 1024;
  if (expectedSize > maxBytes) {
    return json({ error: `File exceeds ${maxMb}MB limit` }, { status: 413 });
  }

  const fileId = randomId(9);
  const deleteToken = randomId(24);
  const objectKey = storageMode === STORAGE_RAMDISK ? `ramdisk:${fileId}` : `${fileId}.bin`;
  const ttlHours = parseEnvNumber(env.FILE_TTL_HOURS, DEFAULT_TTL_HOURS);
  const createdAt = nowIso();
  const expiresAt = addHoursIso(ttlHours);

  let uploadId = '';
  let partSizeBytes = DEFAULT_PART_SIZE_BYTES;

  if (storageMode === STORAGE_RAMDISK) {
    const memInitResponse = await memFetch(env, '/api/upload/init', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        fileId,
        objectKey,
        originalName,
        size: expectedSize,
        createdAt,
        expiresAt,
      }),
    });
    const memInitPayload = await parseJsonSafe(memInitResponse);
    if (!memInitResponse.ok) {
      return json({ error: memInitPayload?.error || 'Memory upload initialization failed' }, { status: 502 });
    }
    uploadId = String(memInitPayload?.uploadId || '');
    partSizeBytes = Number(memInitPayload?.partSizeBytes || DEFAULT_PART_SIZE_BYTES);
    if (!uploadId || !Number.isFinite(partSizeBytes) || partSizeBytes <= 0) {
      return json({ error: 'Memory upload initialization returned invalid session data' }, { status: 502 });
    }
  } else {
    const upload = await env.FILES.createMultipartUpload(objectKey, {
      httpMetadata: {
        contentType: 'application/octet-stream',
        contentDisposition: `attachment; filename="${originalName}"`,
      },
      customMetadata: {
        id: fileId,
        createdAt,
        expiresAt,
      },
    });
    uploadId = upload.uploadId;
  }

  await env.DB.prepare(
    'INSERT INTO uploads (upload_id, file_id, object_key, original_name, created_at, expires_at, delete_token, expected_size, allow_receiver_delete) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)'
  )
    .bind(uploadId, fileId, objectKey, originalName, createdAt, expiresAt, deleteToken, expectedSize, allowReceiverDelete ? 1 : 0)
    .run();

  logApi(request, 'upload-init-complete', { fileId, uploadId, expectedSize, storageMode, allowReceiverDelete });
  return json({
    uploadId,
    partSizeBytes,
  }, { status: 201 });
};

const handleUploadPart = async (request, env) => {
  const url = new URL(request.url);
  const uploadId = url.searchParams.get('uploadId');
  const partNumber = Number(url.searchParams.get('partNumber') || 0);

  if (!uploadId || !Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
    return json({ error: 'Invalid uploadId or partNumber' }, { status: 400 });
  }

  if (!request.body) {
    return json({ error: 'Missing part body' }, { status: 400 });
  }

  const uploadRow = await loadUploadRow(env, uploadId);
  if (!uploadRow) {
    return json({ error: 'Upload session not found' }, { status: 404 });
  }

  if (isRamdiskObjectKey(uploadRow.object_key)) {
    const memPartResponse = await memFetch(env, `/api/upload/part?uploadId=${encodeURIComponent(uploadId)}&partNumber=${partNumber}`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: request.body,
      duplex: 'half',
    });
    const memPartPayload = await parseJsonSafe(memPartResponse);
    if (!memPartResponse.ok) {
      return json({ error: memPartPayload?.error || 'Memory upload part failed' }, { status: 502 });
    }

    return json({
      partNumber: Number(memPartPayload?.partNumber || partNumber),
      etag: String(memPartPayload?.etag || ''),
    });
  }

  const multipart = env.FILES.resumeMultipartUpload(uploadRow.object_key, uploadId);
  const uploaded = await multipart.uploadPart(partNumber, request.body);

  return json({
    partNumber: uploaded.partNumber,
    etag: uploaded.etag,
  });
};

const handleUploadComplete = async (request, env) => {
  const body = await readJsonBody(request);
  if (!body || typeof body !== 'object') {
    return json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const uploadId = String(body.uploadId || '');
  const size = Number(body.size || 0);
  const partsRaw = Array.isArray(body.parts) ? body.parts : [];

  if (!uploadId || !Number.isFinite(size) || size <= 0 || partsRaw.length === 0) {
    return json({ error: 'Invalid upload completion payload' }, { status: 400 });
  }

  const uploadRow = await loadUploadRow(env, uploadId);
  if (!uploadRow) {
    return json({ error: 'Upload session not found' }, { status: 404 });
  }

  const parts = partsRaw
    .map((p) => ({
      partNumber: Number(p.partNumber),
      etag: String(p.etag || ''),
    }))
    .filter((p) => Number.isInteger(p.partNumber) && p.partNumber > 0 && p.etag)
    .sort((a, b) => a.partNumber - b.partNumber);

  if (parts.length === 0) {
    return json({ error: 'No valid parts provided' }, { status: 400 });
  }

  if (isRamdiskObjectKey(uploadRow.object_key)) {
    const memCompleteResponse = await memFetch(env, '/api/upload/complete', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        uploadId,
        fileId: uploadRow.file_id,
        objectKey: uploadRow.object_key,
        size,
        parts,
      }),
    });
    const memCompletePayload = await parseJsonSafe(memCompleteResponse);
    if (!memCompleteResponse.ok) {
      return json({ error: memCompletePayload?.error || 'Memory upload completion failed' }, { status: 502 });
    }
  } else {
    const multipart = env.FILES.resumeMultipartUpload(uploadRow.object_key, uploadId);
    await multipart.complete(parts);
  }

  await env.DB.prepare(
    'INSERT INTO files (id, object_key, original_name, size, created_at, expires_at, delete_token, download_count, allow_receiver_delete) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)'
  )
    .bind(uploadRow.file_id, uploadRow.object_key, uploadRow.original_name, size, uploadRow.created_at, uploadRow.expires_at, uploadRow.delete_token, Number(uploadRow.allow_receiver_delete) ? 1 : 0)
    .run();

  const accessCodeRaw = await assignUniqueAccessCode(env, uploadRow.file_id);

  await env.DB.prepare('DELETE FROM uploads WHERE upload_id = ?1').bind(uploadId).run();

  const base = getOrigin(request);
  logApi(request, 'upload-complete', { id: uploadRow.file_id, size, accessCode: formatAccessCode(accessCodeRaw) });
  return json({
    id: uploadRow.file_id,
    size,
    expiresAt: uploadRow.expires_at,
    downloadUrl: `${base}/download.html?id=${uploadRow.file_id}`,
    deleteUrl: `${base}/delete/${uploadRow.file_id}/${uploadRow.delete_token}`,
    allowReceiverDelete: Number(uploadRow.allow_receiver_delete) === 1,
    accessCode: formatAccessCode(accessCodeRaw),
  }, { status: 201 });
};

const handleUploadAbort = async (request, env) => {
  const body = await readJsonBody(request);
  const uploadId = body && typeof body.uploadId === 'string' ? body.uploadId : '';
  if (!uploadId) {
    return json({ error: 'Missing uploadId' }, { status: 400 });
  }

  const uploadRow = await loadUploadRow(env, uploadId);
  if (!uploadRow) {
    return new Response(null, { status: 204 });
  }

  try {
    if (isRamdiskObjectKey(uploadRow.object_key)) {
      await memFetch(env, '/api/upload/abort', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ uploadId }),
      });
    } else {
      const multipart = env.FILES.resumeMultipartUpload(uploadRow.object_key, uploadId);
      await multipart.abort();
    }
  } catch {
    // Ignore abort failures in PoC cleanup path.
  }

  await env.DB.prepare('DELETE FROM uploads WHERE upload_id = ?1').bind(uploadId).run();
  return new Response(null, { status: 204 });
};

const handleFileInfo = async (request, env, id) => {

  logApi(request, 'file-info', { id });
  const row = await loadFileRow(env, id);
  if (!row) {
    return json({ error: 'File not found or expired' }, { status: 404 });
  }

  return json({
    id: row.id,
    size: row.size,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    downloadCount: row.download_count,
    allowReceiverDelete: Number(row.allow_receiver_delete) === 1,
    deleteUrl: Number(row.allow_receiver_delete) === 1 ? `${getOrigin(request)}/delete/${row.id}/${row.delete_token}` : null,
    accessCode: formatAccessCode(row.access_code),
  });
};

const handleFileInfoByCode = async (request, env, codeInput) => {
  const codeRaw = normalizeAccessCode(codeInput);
  if (!codeRaw) {
    return json({ error: 'Invalid code format' }, { status: 400 });
  }

  logApi(request, 'file-info-by-code', { code: formatAccessCode(codeRaw) });
  const row = await loadFileRowByCode(env, codeRaw);
  if (!row) {
    return json({ error: 'File not found or expired' }, { status: 404 });
  }

  const base = getOrigin(request);
  return json({
    id: row.id,
    size: row.size,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    downloadCount: row.download_count,
    allowReceiverDelete: Number(row.allow_receiver_delete) === 1,
    deleteUrl: Number(row.allow_receiver_delete) === 1 ? `${base}/delete/${row.id}/${row.delete_token}` : null,
    accessCode: formatAccessCode(row.access_code),
    downloadUrl: `${base}/download.html?id=${row.id}`,
  });
};

const handleDownload = async (request, env, id) => {
  logApi(request, 'file-download', { id });
  const row = await loadFileRow(env, id);
  if (!row) {
    return json({ error: 'File not found or expired' }, { status: 404 });
  }

  const totalSize = Number(row.size || 0);
  const rangeHeader = request.headers.get('range');
  let range = null;
  let isRangeRequest = false;

  if (rangeHeader) {
    const m = rangeHeader.match(/^bytes=(\d+)-(\d+)?$/i);
    if (!m) {
      return new Response(null, {
        status: 416,
        headers: {
          'content-range': `bytes */${totalSize}`,
          'cache-control': 'no-store',
        },
      });
    }

    const start = Number(m[1]);
    let end = m[2] ? Number(m[2]) : totalSize - 1;
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || start >= totalSize) {
      return new Response(null, {
        status: 416,
        headers: {
          'content-range': `bytes */${totalSize}`,
          'cache-control': 'no-store',
        },
      });
    }

    end = Math.min(end, totalSize - 1);
    range = {
      offset: start,
      length: (end - start) + 1,
    };
    isRangeRequest = true;
  }

  if (isRamdiskObjectKey(row.object_key)) {
    const headers = new Headers();
    if (rangeHeader) {
      headers.set('range', rangeHeader);
    }

    const memResponse = await memFetch(env, `/api/file/${encodeURIComponent(id)}/download`, {
      method: 'GET',
      headers,
    });

    if (memResponse.status === 404) {
      await env.DB.prepare('DELETE FROM files WHERE id = ?1').bind(id).run();
      return json({ error: 'File not found or expired' }, { status: 404 });
    }

    if (!memResponse.ok || !memResponse.body) {
      return json({ error: 'Memory download failed' }, { status: 502 });
    }

    if (!isRangeRequest) {
      await env.DB.prepare('UPDATE files SET download_count = download_count + 1 WHERE id = ?1').bind(id).run();
    }

    const outHeaders = new Headers(memResponse.headers);
    outHeaders.set('cache-control', 'no-store');
    outHeaders.set('accept-ranges', outHeaders.get('accept-ranges') || 'bytes');
    if (!outHeaders.get('content-disposition')) {
      outHeaders.set('content-disposition', `attachment; filename="${row.original_name}"`);
    }
    if (!outHeaders.get('content-type')) {
      outHeaders.set('content-type', 'application/octet-stream');
    }

    return new Response(memResponse.body, {
      status: memResponse.status,
      headers: outHeaders,
    });
  }

  const object = range
    ? await env.FILES.get(row.object_key, { range })
    : await env.FILES.get(row.object_key);
  if (!object || !object.body) {
    await env.DB.prepare('DELETE FROM files WHERE id = ?1').bind(id).run();
    return json({ error: 'File not found or expired' }, { status: 404 });
  }

  if (!isRangeRequest) {
    await env.DB.prepare('UPDATE files SET download_count = download_count + 1 WHERE id = ?1').bind(id).run();
  }

  const headers = {
    'content-type': 'application/octet-stream',
    'content-disposition': `attachment; filename="${row.original_name}"`,
    'cache-control': 'no-store',
    'accept-ranges': 'bytes',
  };

  if (totalSize > 0) {
    headers['content-length'] = String(totalSize);
  }

  if (isRangeRequest && object.range) {
    const start = object.range.offset;
    const end = object.range.offset + object.range.length - 1;
    headers['content-range'] = `bytes ${start}-${end}/${totalSize}`;
    headers['content-length'] = String(object.range.length);
    return new Response(object.body, {
      status: 206,
      headers,
    });
  }

  return new Response(object.body, {
    headers,
  });
};

const handleDeleteApi = async (request, env, id) => {

  logApi(request, 'delete-api-start', { id });
  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return json({ error: 'Missing delete token' }, { status: 400 });
  }

  const row = await loadFileRow(env, id);
  if (!row) {
    return json({ error: 'File not found or expired' }, { status: 404 });
  }

  if (token !== row.delete_token) {
    return json({ error: 'Invalid token' }, { status: 403 });
  }

  await deleteFileRecord(env, row);
  logApi(request, 'delete-api-complete', { id });
  return new Response(null, { status: 204 });
};

const renderDeletePage = ({ title, message, id = '', token = '', showConfirm = false, statusCode = 200 }) => {
  const escapedTitle = String(title || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escapedMessage = String(message || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escapedId = String(id || '').replace(/"/g, '&quot;');
  const escapedToken = String(token || '').replace(/"/g, '&quot;');

  const page = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Reiven.io Delete</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body>
    <main class="container">
      <h1>Reiven.io</h1>
      <p class="muted">Quantum resistant encrypted file sharing for the masses</p>

      <section id="delete-card" class="card" data-file-id="${escapedId}" data-token="${escapedToken}">
        <h2>${escapedTitle}</h2>
        <p id="delete-message">${escapedMessage}</p>
        ${showConfirm ? `
        <div style="display:flex; gap:10px; margin-top:14px;">
          <button id="delete-yes-btn" type="button">Yes</button>
          <button id="delete-no-btn" type="button">No</button>
        </div>
        ` : `
        <div style="margin-top:14px;">
          <a href="/">Back to Reiven.io</a>
        </div>
        `}
      </section>
    </main>

    <script>
      (function () {
        var card = document.getElementById('delete-card');
        if (!card) return;
        var yesBtn = document.getElementById('delete-yes-btn');
        var noBtn = document.getElementById('delete-no-btn');
        var msgEl = document.getElementById('delete-message');
        if (!yesBtn || !noBtn || !msgEl) return;

        var fileId = card.getAttribute('data-file-id') || '';
        var token = card.getAttribute('data-token') || '';
        var done = false;

        var setMessage = function (text, isError) {
          msgEl.textContent = text;
          msgEl.classList.toggle('error', !!isError);
        };

        noBtn.addEventListener('click', function () {
          if (done) return;
          done = true;
          yesBtn.remove();
          noBtn.remove();
          setMessage('Deletion canceled. The file was not deleted.', false);
          var back = document.createElement('a');
          back.href = '/';
          back.textContent = 'Back to Reiven.io';
          var wrap = document.createElement('div');
          wrap.style.marginTop = '14px';
          wrap.appendChild(back);
          card.appendChild(wrap);
        });

        yesBtn.addEventListener('click', async function () {
          if (done) return;
          done = true;
          yesBtn.disabled = true;
          noBtn.disabled = true;
          setMessage('Deleting file...', false);
          try {
            var res = await fetch('/api/file/' + encodeURIComponent(fileId) + '?token=' + encodeURIComponent(token), {
              method: 'DELETE'
            });
            if (!res.ok) {
              var text = 'Deletion failed.';
              try {
                var payload = await res.json();
                text = payload && payload.error ? payload.error : text;
              } catch (_) {}
              setMessage(text, true);
              done = false;
              yesBtn.disabled = false;
              noBtn.disabled = false;
              return;
            }
            yesBtn.remove();
            noBtn.remove();
            setMessage('File deleted successfully.', false);
            var back = document.createElement('a');
            back.href = '/';
            back.textContent = 'Back to Reiven.io';
            var wrap = document.createElement('div');
            wrap.style.marginTop = '14px';
            wrap.appendChild(back);
            card.appendChild(wrap);
          } catch (_) {
            setMessage('Network error while deleting file.', true);
            done = false;
            yesBtn.disabled = false;
            noBtn.disabled = false;
          }
        });
      })();
    </script>
  </body>
</html>`;

  return html(page, { status: statusCode });
};

const handleDeletePage = async (request, env, id, token) => {
  logApi(request, 'delete-page-open', { id });
  const row = await loadFileRow(env, id);
  if (!row) {
    return renderDeletePage({
      title: 'Delete File',
      message: 'File not found or expired.',
      statusCode: 404,
    });
  }

  if (token !== row.delete_token) {
    return renderDeletePage({
      title: 'Delete File',
      message: 'Invalid delete token.',
      statusCode: 403,
    });
  }

  return renderDeletePage({
    title: 'Delete File',
    message: `Are you sure you want to delete file ${row.id}?`,
    id: row.id,
    token,
    showConfirm: true,
  });
};

const handleEncryptionConfig = () => json(ENCRYPTION_CONFIG);

const serveAsset = (request, env) => env.ASSETS.fetch(request);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'GET' && pathname === '/health') {
      return json({ ok: true });
    }

    if (request.method === 'POST' && pathname === '/api/upload/init') {
      return handleUploadInit(request, env);
    }

    if (request.method === 'POST' && pathname === '/api/upload/part') {
      return handleUploadPart(request, env);
    }

    if (request.method === 'POST' && pathname === '/api/upload/complete') {
      return handleUploadComplete(request, env);
    }

    if (request.method === 'POST' && pathname === '/api/upload/abort') {
      return handleUploadAbort(request, env);
    }

    if (request.method === 'GET' && pathname === '/api/encryption-config') {
      return handleEncryptionConfig();
    }

    if (request.method === 'GET' && pathname.startsWith('/api/file/') && pathname.endsWith('/info')) {
      if (pathname.startsWith('/api/file/code/')) {
        const code = pathname.slice('/api/file/code/'.length, -'/info'.length);
        return handleFileInfoByCode(request, env, code);
      }
      const id = pathname.slice('/api/file/'.length, -'/info'.length);
      return handleFileInfo(request, env, id);
    }

    if (request.method === 'GET' && pathname.startsWith('/api/file/') && pathname.endsWith('/download')) {
      const id = pathname.slice('/api/file/'.length, -'/download'.length);
      return handleDownload(request, env, id);
    }

    if (request.method === 'DELETE' && pathname.startsWith('/api/file/')) {
      const id = pathname.slice('/api/file/'.length);
      return handleDeleteApi(request, env, id);
    }

    if (request.method === 'GET' && pathname.startsWith('/delete/')) {
      const parts = pathname.split('/');
      if (parts.length === 4) {
        return handleDeletePage(request, env, parts[2], parts[3]);
      }
    }

    if (pathname.startsWith('/api/')) {
      return json({ error: 'API route not found' }, { status: 404 });
    }

    return serveAsset(request, env);
  },
};
