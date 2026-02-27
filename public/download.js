const VERIFY_TIMEOUT_MS = 180000;
const DECRYPT_TIMEOUT_MS = 300000;
let encryptionConfig = null;

const statusEl = document.getElementById('status');
const fileMetaEl = document.getElementById('file-meta');
const downloadForm = document.getElementById('download-form');
const downloadBtn = document.getElementById('download-btn');
const slowWarningEl = document.getElementById('slow-warning');
let statusDotsTimer = null;
let slowWarningTimer = null;

const worker = new Worker('/crypto-worker.js');
let nextRequestId = 1;
const pending = new Map();
let workerReadyResolve;
let workerReadyReject;
const workerReady = new Promise((resolve, reject) => {
  workerReadyResolve = resolve;
  workerReadyReject = reject;
});
workerReady.catch(() => {});

const clearPendingWithError = (message) => {
  for (const p of pending.values()) {
    if (p.timeoutId) {
      clearTimeout(p.timeoutId);
    }
    p.reject(new Error(message));
  }
  pending.clear();
};

worker.onmessage = (event) => {
  const msg = event.data || {};

  if (msg.type === 'ready') {
    if (msg.ok) {
      workerReadyResolve();
    } else {
      workerReadyReject(new Error(msg.error || 'Crypto worker failed to initialize'));
    }
    return;
  }

  if (msg.type === 'progress') {
    const p = pending.get(msg.id);
    if (p && typeof p.onProgress === 'function') {
      p.onProgress(msg);
    }
    console.debug('[crypto-worker progress]', msg.stage, msg.message, msg.data || {});
    return;
  }

  const { id, ok, result, error } = msg;
  const p = pending.get(id);
  if (!p) {
    return;
  }

  pending.delete(id);
  if (p.timeoutId) {
    clearTimeout(p.timeoutId);
  }

  if (ok) {
    p.resolve(result);
  } else {
    p.reject(new Error(error || 'Worker error'));
  }
};

worker.onerror = (event) => {
  const message = event?.message || 'Crypto worker crashed.';
  workerReadyReject(new Error(message));
  clearPendingWithError(message);
  console.error('[crypto-worker error]', event);
};

worker.onmessageerror = (event) => {
  const message = 'Crypto worker message parsing failed.';
  clearPendingWithError(message);
  console.error('[crypto-worker messageerror]', event);
};

const callWorker = (type, payload, transfer = [], options = {}) => new Promise((resolve, reject) => {
  const id = nextRequestId;
  nextRequestId += 1;

  const timeoutMs = options.timeoutMs || 120000;
  const timeoutId = setTimeout(() => {
    pending.delete(id);
    reject(new Error(`Worker timeout during ${type} after ${Math.round(timeoutMs / 1000)}s`));
  }, timeoutMs);

  pending.set(id, {
    resolve,
    reject,
    timeoutId,
    onProgress: options.onProgress,
  });

  try {
    worker.postMessage({ id, type, payload }, transfer);
  } catch (err) {
    clearTimeout(timeoutId);
    pending.delete(id);
    reject(err);
  }
});

const stopStatusDots = () => {
  if (statusDotsTimer) {
    clearInterval(statusDotsTimer);
    statusDotsTimer = null;
  }
};

const setStatusText = (message, isError = false) => {
  statusEl.textContent = message;
  statusEl.classList.remove('hidden');
  statusEl.classList.toggle('error', isError);
};

const showStatus = (message, isError = false) => {
  stopStatusDots();
  setStatusText(message, isError);
};

const hideSlowWarning = () => {
  if (slowWarningEl) {
    slowWarningEl.classList.add('hidden');
  }
};

const showSlowWarning = () => {
  if (slowWarningEl) {
    slowWarningEl.classList.remove('hidden');
  }
};

const clearSlowWarningTimer = () => {
  if (slowWarningTimer) {
    clearTimeout(slowWarningTimer);
    slowWarningTimer = null;
  }
};

const startSlowWarningTimer = () => {
  hideSlowWarning();
  clearSlowWarningTimer();
  slowWarningTimer = setTimeout(() => {
    showSlowWarning();
  }, 10000);
};

const showStepStatus = (message) => {
  const base = String(message || '').replace(/\.*\s*$/, '');
  startStatusDots(base);
};

const startStatusDots = (baseMessage) => {
  stopStatusDots();
  const frames = ['.', '..', '...', ''];
  let frameIndex = 0;
  setStatusText(`${baseMessage}${frames[frameIndex]}`);
  statusDotsTimer = setInterval(() => {
    frameIndex = (frameIndex + 1) % frames.length;
    setStatusText(`${baseMessage}${frames[frameIndex]}`);
  }, 320);
};

const formatMb = (bytes) => `${Math.round(bytes / (1024 * 1024))}`;

const parseApiResponse = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  const text = await response.text();
  return { error: text || `HTTP ${response.status}` };
};

const loadEncryptionConfig = async () => {
  const response = await fetch('/api/encryption-config');
  const payload = await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload.error || 'Failed to load encryption config');
  }
  return payload;
};

const getEncryptionConfig = () => {
  if (!encryptionConfig) {
    throw new Error('Encryption config is not loaded yet');
  }
  return encryptionConfig;
};

const parseEnvelopeHeader = (arrayBuffer) => {
  const cfg = getEncryptionConfig();
  const bytes = new Uint8Array(arrayBuffer);
  if (bytes.length < cfg.headerFixedLen) {
    throw new Error('Invalid encrypted payload.');
  }

  const magic = new TextDecoder().decode(bytes.slice(0, 7));
  if (magic !== cfg.magic) {
    throw new Error('Unsupported file format.');
  }

  const version = bytes[7];
  if (version !== cfg.formatVersion) {
    throw new Error('Unsupported file format version.');
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const mem = view.getUint32(12, false);
  const saltLen = bytes[8];
  const ivLen = bytes[9];
  const checkIvLen = bytes[16];
  const checkCipherLen = view.getUint16(17, false);
  const wrapIvLen = bytes[19];
  const wrappedDekLen = view.getUint16(20, false);
  const pqCipherLen = view.getUint16(22, false);
  if (saltLen !== cfg.saltLen || ivLen !== cfg.ivLen) {
    throw new Error('Unsupported encrypted payload layout.');
  }
  if (checkIvLen !== cfg.checkIvLen || checkCipherLen <= 0) {
    throw new Error('Unsupported encrypted check layout.');
  }
  if (wrapIvLen !== cfg.wrapIvLen || wrappedDekLen <= 0) {
    throw new Error('Unsupported wrapped-key layout.');
  }
  if (pqCipherLen <= 0) {
    throw new Error('Unsupported ML-KEM ciphertext layout.');
  }
  const headerSize = cfg.headerFixedLen + saltLen + checkIvLen + checkCipherLen + pqCipherLen + wrapIvLen + wrappedDekLen + ivLen;
  if (bytes.length < headerSize) {
    throw new Error('Incomplete encrypted header.');
  }
  return {
    time: bytes[10],
    mem,
    parallelism: bytes[11],
    headerSize,
  };
};

const getFileIdFromPath = () => {
  const fromQuery = new URLSearchParams(window.location.search).get('id');
  if (fromQuery) {
    return decodeURIComponent(fromQuery);
  }

  return null;
};

const loadInfo = async (id) => {
  try {
    const response = await fetch(`/api/file/${encodeURIComponent(id)}/info`);
    const payload = await parseApiResponse(response);

    if (!response.ok) {
      throw new Error(payload.error || 'File unavailable');
    }

    fileMetaEl.textContent = `File ID: ${payload.id} | Size: ${payload.size} bytes | Expires: ${new Date(payload.expiresAt).toLocaleString()}`;
  } catch (error) {
    fileMetaEl.textContent = error.message;
    downloadBtn.disabled = true;
  }
};

const downloadDecryptedFile = async (id, password, pim) => {
  await workerReady;
  const cfg = getEncryptionConfig();

  showStepStatus('Checking password against encrypted header');
  const headerResponse = await fetch(`/api/file/${encodeURIComponent(id)}/download`, {
    headers: {
      range: `bytes=0-${cfg.headerProbeBytes - 1}`,
    },
  });
  const headerPayload = headerResponse.ok ? null : await parseApiResponse(headerResponse);
  if (!headerResponse.ok) {
    throw new Error(headerPayload?.error || 'Download failed');
  }
  const headerBuffer = await headerResponse.arrayBuffer();
  const headerInfo = parseEnvelopeHeader(headerBuffer);

  const verified = await callWorker(
    'verify-header',
    {
      headerBuffer: headerBuffer.slice(0, headerInfo.headerSize),
      password,
      pim,
    },
    [headerBuffer],
    {
      timeoutMs: VERIFY_TIMEOUT_MS,
      onProgress: () => {
        startStatusDots(`Validating password with Argon2id (time=${headerInfo.time}, mem=${Math.round(headerInfo.mem / 1024)}MB)`);
      },
    }
  );

  showStepStatus('Password accepted. Preparing full download');
  const response = await fetch(`/api/file/${encodeURIComponent(id)}/download`);
  const payload = response.ok ? null : await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload?.error || 'Download failed');
  }

  let encryptedBuffer;
  const totalBytes = Number(response.headers.get('content-length') || 0);
  if (!response.body) {
    encryptedBuffer = await response.arrayBuffer();
    if (totalBytes > 0) {
      showStatus(`Downloading encrypted file ${formatMb(totalBytes)}/${formatMb(totalBytes)} MB`);
    } else {
      showStepStatus('Downloading encrypted file. This may take a while for large files');
    }
  } else {
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      chunks.push(value);
      received += value.byteLength;
      if (totalBytes > 0) {
        showStatus(`Downloading encrypted file ${formatMb(received)}/${formatMb(totalBytes)} MB`);
      } else {
        showStatus(`Downloading encrypted file ${formatMb(received)} MB...`);
      }
    }

    const merged = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    encryptedBuffer = merged.buffer;
  }

  showStepStatus(`Decrypting in worker with Argon2id (time=${headerInfo.time}, mem=${Math.round(headerInfo.mem / 1024)}MB)`);

  const decrypted = await callWorker(
    'decrypt',
    {
      encryptedBuffer,
      password,
      pim,
    },
    [encryptedBuffer],
    {
      timeoutMs: DECRYPT_TIMEOUT_MS,
      onProgress: (progress) => {
        const message = progress.message || 'Decrypting in worker...';
        if (message.startsWith('Deriving key with Argon2id')) {
          startStatusDots('Deriving key with Argon2id');
          return;
        }
        showStatus(message);
      },
    }
  );

  const decryptedBlob = new Blob([decrypted.plaintextBuffer], { type: 'application/octet-stream' });

  const filename = (verified && verified.originalName) ? verified.originalName : `decrypted-${id}`;

  const url = URL.createObjectURL(decryptedBlob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  showStatus('File ready. Starting browser download...');
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
};

const fileId = getFileIdFromPath();
const initializeDownload = async () => {
  try {
    encryptionConfig = await loadEncryptionConfig();
  } catch (error) {
    fileMetaEl.textContent = error.message || 'Could not load encryption config.';
    downloadBtn.disabled = true;
    return;
  }

  if (!fileId) {
    fileMetaEl.textContent = 'Invalid URL.';
    downloadBtn.disabled = true;
    return;
  }

  loadInfo(fileId);
};

downloadForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const password = document.getElementById('password-input').value;
  if (!password) {
    showStatus('Please provide a password.', true);
    return;
  }
  if (!fileId) {
    showStatus('Invalid file id.', true);
    return;
  }

  try {
    const cfg = getEncryptionConfig();
    const pim = cfg.defaultPim;
    downloadBtn.disabled = true;
    startSlowWarningTimer();
    showStepStatus(`Downloading encrypted file (fixed profile PIM=${cfg.defaultPim})`);
    await downloadDecryptedFile(fileId, password, pim);
    showStatus('Decrypted download started.');
  } catch (error) {
    showStatus(error.message || 'Download failed', true);
    console.error('[download flow]', error);
  } finally {
    clearSlowWarningTimer();
    hideSlowWarning();
    downloadBtn.disabled = false;
  }
});

initializeDownload();
