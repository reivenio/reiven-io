const VERIFY_TIMEOUT_MS = 180000;
const DECRYPT_TIMEOUT_MS = 300000;
const LEGACY_FORMAT_VERSION = 4;
let encryptionConfig = null;

const statusEl = document.getElementById('status');
const statusMessageEl = document.getElementById('status-message');
const fileMetaEl = document.getElementById('file-meta');
const downloadForm = document.getElementById('download-form');
const downloadBtn = document.getElementById('download-btn');
const receiverDeleteBtn = document.getElementById('receiver-delete-btn');
const slowWarningEl = document.getElementById('slow-warning');
const noteCardEl = document.getElementById('note-card');
const noteOutputEl = document.getElementById('note-output');
const noteDownloadBtn = document.getElementById('note-download-btn');
const passwordInputEl = document.getElementById('password-input');
const passwordToggleBtn = document.getElementById('password-toggle-btn');
const textDecoder = new TextDecoder();
let statusDotsTimer = null;
let slowWarningTimer = null;
let fileMeta = null;
let autoDownloadStarted = false;

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
  if (statusMessageEl) {
    statusMessageEl.textContent = message;
    statusMessageEl.classList.toggle('error', isError);
    statusEl.classList.remove('error');
  } else {
    statusEl.textContent = message;
    statusEl.classList.toggle('error', isError);
  }
  statusEl.classList.remove('hidden');
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

const runWithSlowCryptoWarning = async (task) => {
  startSlowWarningTimer();
  try {
    return await task();
  } finally {
    clearSlowWarningTimer();
    hideSlowWarning();
  }
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

const concatUint8Arrays = (left, right) => {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
};

const parseEnvelopeHeader = (arrayBuffer) => {
  const cfg = getEncryptionConfig();
  const bytes = new Uint8Array(arrayBuffer);
  const legacyHeaderFixedLen = 24;
  if (bytes.length < legacyHeaderFixedLen) {
    throw new Error('Invalid encrypted payload.');
  }

  const magic = new TextDecoder().decode(bytes.slice(0, 7));
  if (magic !== cfg.magic) {
    throw new Error('Unsupported file format.');
  }

  const version = bytes[7];
  if (version !== LEGACY_FORMAT_VERSION && version !== cfg.formatVersion) {
    throw new Error('Unsupported file format version.');
  }
  const headerFixedLen = version >= cfg.formatVersion ? cfg.headerFixedLen : legacyHeaderFixedLen;

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
  const headerSize = headerFixedLen + saltLen + checkIvLen + checkCipherLen + pqCipherLen + wrapIvLen + wrappedDekLen + ivLen;
  if (bytes.length < headerSize) {
    throw new Error('Incomplete encrypted header.');
  }
  return {
    version,
    time: bytes[10],
    mem,
    parallelism: bytes[11],
    chunkPlainSize: version >= cfg.formatVersion ? view.getUint32(24, false) : 0,
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

const getAutoDownloadPassword = () => {
  const hash = String(window.location.hash || '').replace(/^#/, '');
  if (!hash) {
    return null;
  }
  const params = new URLSearchParams(hash);
  const password = params.get('key') || params.get('password');
  const shouldAutoStart = params.get('auto') === '1' || params.has('key');
  return password && shouldAutoStart ? password : null;
};

const scrubAutoDownloadHash = () => {
  if (!window.location.hash || !window.history || typeof window.history.replaceState !== 'function') {
    return;
  }
  window.history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
};

const loadInfo = async (id) => {
  try {
    const response = await fetch(`/api/file/${encodeURIComponent(id)}/info`);
    const payload = await parseApiResponse(response);

    if (!response.ok) {
      throw new Error(payload.error || 'File unavailable');
    }

    fileMeta = payload;
    fileMetaEl.textContent = `File ID: ${payload.id} | Size: ${payload.size} bytes | Expires: ${new Date(payload.expiresAt).toLocaleString()}`;
    if (receiverDeleteBtn) {
      const allowReceiverDelete = payload && payload.allowReceiverDelete === true && typeof payload.deleteUrl === 'string' && payload.deleteUrl;
      receiverDeleteBtn.classList.toggle('hidden', !allowReceiverDelete);
      if (allowReceiverDelete) {
        receiverDeleteBtn.onclick = () => {
          window.location.href = payload.deleteUrl;
        };
      } else {
        receiverDeleteBtn.onclick = null;
      }
    }
    return true;
  } catch (error) {
    fileMetaEl.textContent = error.message;
    downloadBtn.disabled = true;
    fileMeta = null;
    if (receiverDeleteBtn) {
      receiverDeleteBtn.classList.add('hidden');
      receiverDeleteBtn.onclick = null;
    }
    if (noteCardEl) {
      noteCardEl.classList.add('hidden');
    }
    return false;
  }
};

if (passwordToggleBtn && passwordInputEl) {
  passwordToggleBtn.addEventListener('click', () => {
    const nextType = passwordInputEl.type === 'password' ? 'text' : 'password';
    passwordInputEl.type = nextType;
    passwordToggleBtn.setAttribute('aria-label', nextType === 'password' ? 'Show password' : 'Hide password');
  });
}

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

  const verified = await runWithSlowCryptoWarning(() => callWorker(
    'decrypt-init',
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
  ));

  showStepStatus('Password accepted. Preparing download');
  const filename = verified && verified.originalName ? verified.originalName : `decrypted-${id}`;
  const isNote = Boolean(fileMeta && fileMeta.isNote);
  const plaintextChunks = [];

  if (!verified.chunkPlainSize || verified.chunkPlainSize <= 0) {
    try {
      showStepStatus('Downloading encrypted file');
      const fullResponse = await fetch(`/api/file/${encodeURIComponent(id)}/download`);
      const fullPayload = fullResponse.ok ? null : await parseApiResponse(fullResponse);
      if (!fullResponse.ok) {
        throw new Error(fullPayload?.error || 'Download failed');
      }

      const encryptedBuffer = await fullResponse.arrayBuffer();
      showStepStatus('Decrypting file');
      const decrypted = await runWithSlowCryptoWarning(() => callWorker(
        'decrypt',
        {
          encryptedBuffer,
          password,
          pim,
        },
        [encryptedBuffer],
        {
          timeoutMs: DECRYPT_TIMEOUT_MS,
        }
      ));
      plaintextChunks.push(new Uint8Array(decrypted.plaintextBuffer));
    } finally {
      try {
        await callWorker('decrypt-finish', { sessionId: verified.sessionId });
      } catch {
        // Ignore worker cleanup failures.
      }
    }
  } else {
    const response = await fetch(`/api/file/${encodeURIComponent(id)}/download`, {
      headers: {
        range: `bytes=${verified.headerSize}-`,
      },
    });
    const payload = response.ok ? null : await parseApiResponse(response);
    if (!response.ok) {
      throw new Error(payload?.error || 'Download failed');
    }

    const totalCipherBytes = Number(response.headers.get('content-length') || 0);

    try {
      if (!response.body) {
        throw new Error('Streaming response body is unavailable in this browser.');
      }

      const reader = response.body.getReader();
      let pending = new Uint8Array(0);
      let receivedCipherBytes = 0;
      let chunkIndex = 0;
      const fullChunkCipherSize = verified.chunkPlainSize + 16;

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }

        receivedCipherBytes += value.byteLength;
        pending = concatUint8Arrays(pending, value);
        if (totalCipherBytes > 0) {
          showStatus(`Downloading encrypted file ${formatMb(receivedCipherBytes)}/${formatMb(totalCipherBytes)} MB`);
        } else {
          showStatus(`Downloading encrypted file ${formatMb(receivedCipherBytes)} MB...`);
        }

        while (pending.length > 0) {
          const remainingCipherBytes = totalCipherBytes > 0 ? totalCipherBytes - (receivedCipherBytes - pending.length) : null;
          const expectedCipherSize = remainingCipherBytes && remainingCipherBytes <= fullChunkCipherSize
            ? remainingCipherBytes
            : fullChunkCipherSize;
          if (pending.length < expectedCipherSize) {
            break;
          }
          const encryptedChunk = pending.slice(0, expectedCipherSize);
          pending = pending.slice(expectedCipherSize);
          const decryptedChunk = await runWithSlowCryptoWarning(() => callWorker('decrypt-chunk', {
            sessionId: verified.sessionId,
            chunkIndex,
            chunkBuffer: encryptedChunk.buffer,
          }, [encryptedChunk.buffer], {
            timeoutMs: DECRYPT_TIMEOUT_MS,
          }));
          plaintextChunks.push(new Uint8Array(decryptedChunk.chunkBuffer));
          chunkIndex += 1;
        }
      }

      if (pending.length > 0) {
        throw new Error('Encrypted payload ended mid-chunk.');
      }
    } finally {
      try {
        await callWorker('decrypt-finish', { sessionId: verified.sessionId });
      } catch {
        // Ignore worker cleanup failures.
      }
    }
  }

  const decryptedBlob = new Blob(plaintextChunks, { type: 'application/octet-stream' });

  if (isNote && noteOutputEl && noteCardEl) {
    try {
      noteOutputEl.value = textDecoder.decode(await decryptedBlob.arrayBuffer());
      noteCardEl.classList.remove('hidden');
    } catch {
      noteOutputEl.value = '[Unable to decode note text]';
      noteCardEl.classList.remove('hidden');
    }
    if (noteDownloadBtn) {
      noteDownloadBtn.classList.remove('hidden');
      noteDownloadBtn.onclick = () => {
        const url = URL.createObjectURL(decryptedBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      };
    }
    showStatus('Note ready. Use Download Note to save a file.');
    return;
  }

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
const startDecryptedDownload = async (password, { auto = false } = {}) => {
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
    showStepStatus(auto ? 'QR Mode key detected. Starting download...' : `Downloading encrypted file (fixed profile PIM=${cfg.defaultPim})`);
    await downloadDecryptedFile(fileId, password, pim);
    showStatus(Boolean(fileMeta && fileMeta.isNote) ? 'Note ready.' : 'Decrypted download started.');
  } catch (error) {
    showStatus(error.message || 'Download failed', true);
    console.error('[download flow]', error);
  } finally {
    hideSlowWarning();
    downloadBtn.disabled = false;
  }
};

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

  const loaded = await loadInfo(fileId);
  const autoPassword = getAutoDownloadPassword();
  if (loaded && autoPassword && !autoDownloadStarted) {
    autoDownloadStarted = true;
    passwordInputEl.value = '';
    passwordInputEl.placeholder = 'QR Mode key detected';
    scrubAutoDownloadHash();
    await startDecryptedDownload(autoPassword, { auto: true });
    passwordInputEl.placeholder = '';
  }
};

downloadForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  await startDecryptedDownload(passwordInputEl.value);
});

initializeDownload();
