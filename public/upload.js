const CALIBRATION_CACHE_KEY = 'eshare_argon_calibration_v3';
const ATTACKER_REF_ARGON = Object.freeze({ time: 4, mem: 65536, parallelism: 1 });
const ATTACKER_REF_GUESSES_PER_SECOND = 0.55;
const ATTACKER_PQ_WRAPPING_OVERHEAD = 1.08;
const ATTACKER_REFERENCE_NOTE = 'Approximate offline-attack model, not a guarantee.';
const MAX_PARALLEL_PART_UPLOADS = 3;
let encryptionConfig = null;

const uploadForm = document.getElementById('upload-form');
const statusEl = document.getElementById('status');
const linksEl = document.getElementById('links');
const accessCodeEl = document.getElementById('access-code');
const uploadCompleteExpiryEl = document.getElementById('upload-complete-expiry');
const copyCodeBtn = document.getElementById('copy-code-btn');
const copyDownloadBtn = document.getElementById('copy-download-btn');
const copyDeleteBtn = document.getElementById('copy-delete-btn');
const deleteRowEl = document.getElementById('delete-row');
const uploadBtn = document.getElementById('upload-btn');
const benchmarkStatusEl = document.getElementById('benchmark-status');
const securityEstimateEl = document.getElementById('security-estimate');
const securityDetailsEl = document.getElementById('security-details');
const bruteForceEstimateEl = document.getElementById('bruteforce-estimate');
const securityProfileLabelEl = document.getElementById('security-profile-label');
const passwordInputEl = document.getElementById('password-input');
const passwordToggleBtnEl = document.getElementById('password-toggle-btn');
const passwordNoteEl = document.getElementById('password-note');
const encryptionTypeInputEl = document.getElementById('encryption-type-input');
const allowReceiverDeleteInputEl = document.getElementById('allow-receiver-delete-input');
const qrModeInputEl = document.getElementById('qr-mode-input');
const contentTypeInputEl = document.getElementById('content-type-input');
const fileInputWrapEl = document.getElementById('file-input-wrap');
const fileInputEl = document.getElementById('file-input');
const uploadDropEl = document.querySelector('.upload-drop');
const fileDropTextEl = document.getElementById('file-drop-text');
const noteInputWrapEl = document.getElementById('note-input-wrap');
const noteInputEl = document.getElementById('note-input');
const noteInputLabelEl = document.getElementById('note-input-label');
const brandHomeBtnEl = document.getElementById('brand-home-btn');
const heroShareBtnEl = document.getElementById('hero-share-btn');
const tabShareEl = document.getElementById('tab-share');
const tabDownloadEl = document.getElementById('tab-download');
const tabCliEl = document.getElementById('tab-cli');
const panelHomeEl = document.getElementById('panel-home');
const panelShareEl = document.getElementById('panel-share');
const panelDownloadEl = document.getElementById('panel-download');
const panelCliEl = document.getElementById('panel-cli');
const contentTypeFileBtnEl = document.getElementById('content-type-file-btn');
const contentTypeNoteBtnEl = document.getElementById('content-type-note-btn');
const codeDownloadForm = document.getElementById('code-download-form');
const codeInputEl = document.getElementById('code-input');
const codeStatusEl = document.getElementById('code-status');
const qrRowEl = document.getElementById('qr-row');
const qrCodeEl = document.getElementById('qr-code');
const qrLinkEl = document.getElementById('qr-link');
const copyQrBtn = document.getElementById('copy-qr-btn');
const completeNoteEl = document.getElementById('complete-note');
const codeSegmentEls = Array.from(document.querySelectorAll('.download-code-input'));
const startupOverlayEl = document.getElementById('startup-overlay');
const ENCRYPTION_TYPE_STANDARD = 'standard';
const ENCRYPTION_TYPE_PARANOID = 'paranoid';
const CONTENT_TYPE_FILE = 'file';
const CONTENT_TYPE_NOTE = 'note';
const encoder = new TextEncoder();
const MAX_NOTE_BYTES = 10 * 1024 * 1024;

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

let calibrationPromise = null;
let calibrationProfile = null;
let statusDotsTimer = null;
let selectedFile = null;

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

const hideStatus = () => {
  stopStatusDots();
  statusEl.classList.add('hidden');
  statusEl.classList.remove('error');
  statusEl.textContent = '';
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

const showCodeStatus = (message, isError = false) => {
  codeStatusEl.textContent = message;
  codeStatusEl.classList.remove('hidden');
  codeStatusEl.classList.toggle('error', isError);
};

const hideCodeStatus = () => {
  codeStatusEl.textContent = '';
  codeStatusEl.classList.add('hidden');
  codeStatusEl.classList.remove('error');
};

const finishStartupLoading = () => {
  document.body.classList.remove('app-loading');
  if (startupOverlayEl) {
    startupOverlayEl.setAttribute('aria-hidden', 'true');
  }
};

const copyToClipboard = async (value, button) => {
  try {
    await navigator.clipboard.writeText(value);
    const prev = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => {
      button.textContent = prev;
    }, 1200);
  } catch {
    button.textContent = 'Failed';
    setTimeout(() => {
      button.textContent = 'Copy';
    }, 1200);
  }
};

const formatMbProgress = (bytes) => {
  return `${Math.round(bytes / (1024 * 1024))}`;
};

const formatFileSize = (bytes) => {
  const value = Number(bytes || 0);
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  if (value < 1024 * 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  }
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const updateFileDropText = () => {
  if (!fileDropTextEl) {
    return;
  }
  if (!selectedFile) {
    fileDropTextEl.textContent = 'Select or drop a file to upload';
    return;
  }
  fileDropTextEl.textContent = `Selected: ${selectedFile.name} (${formatFileSize(selectedFile.size)})`;
};

const setSelectedFile = (file) => {
  selectedFile = file || null;
  updateFileDropText();
};

const syncFileInput = (file) => {
  if (!fileInputEl || !file) {
    return;
  }
  try {
    const transfer = new DataTransfer();
    transfer.items.add(file);
    fileInputEl.files = transfer.files;
  } catch {
  }
};

const base64UrlEncode = (bytes) => {
  let binary = '';
  for (const value of bytes) {
    binary += String.fromCharCode(value);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const generateRandomPassword = () => {
  const cryptoApi = window.crypto || window.msCrypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('Secure random generation is unavailable in this browser.');
  }
  const bytes = new Uint8Array(32);
  cryptoApi.getRandomValues(bytes);
  return base64UrlEncode(bytes);
};

const buildQrDownloadUrl = (downloadUrl, password) => {
  const url = new URL(downloadUrl, window.location.origin);
  const params = new URLSearchParams();
  params.set('key', password);
  params.set('auto', '1');
  url.hash = params.toString();
  return url.toString();
};

const setQrModeState = () => {
  const enabled = Boolean(qrModeInputEl && qrModeInputEl.checked);
  if (passwordInputEl) {
    passwordInputEl.disabled = enabled;
    passwordInputEl.required = !enabled;
    passwordInputEl.placeholder = enabled ? 'generated in browser for QR Mode' : '';
    if (enabled) {
      passwordInputEl.value = '';
      passwordInputEl.type = 'password';
      updateBruteForceEstimate();
    }
  }
  if (passwordToggleBtnEl) {
    passwordToggleBtnEl.disabled = enabled;
    passwordToggleBtnEl.setAttribute('aria-pressed', 'false');
    passwordToggleBtnEl.setAttribute('aria-label', 'Show encryption key');
  }
  if (passwordNoteEl) {
    passwordNoteEl.textContent = enabled
      ? 'QR Mode generates a random 256-bit key in this browser.'
      : 'Min 32 chars.';
  }
};

const clearQrResult = () => {
  if (qrRowEl) {
    qrRowEl.classList.add('hidden');
  }
  if (qrCodeEl) {
    qrCodeEl.textContent = '';
  }
  if (qrLinkEl) {
    qrLinkEl.href = '#';
    qrLinkEl.textContent = '';
  }
};

const renderQrResult = async (qrDownloadUrl) => {
  if (!qrRowEl || !qrCodeEl || !qrLinkEl) {
    return;
  }
  qrLinkEl.href = qrDownloadUrl;
  qrLinkEl.textContent = qrDownloadUrl;
  if (!window.ReivenQR || typeof window.ReivenQR.toString !== 'function') {
    qrCodeEl.textContent = 'QR unavailable. Copy the QR link instead.';
    qrRowEl.classList.remove('hidden');
    return;
  }
  try {
    const svg = await window.ReivenQR.toString(qrDownloadUrl, {
      type: 'svg',
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 192,
    });
    qrCodeEl.innerHTML = svg;
  } catch {
    qrCodeEl.textContent = 'QR unavailable. Copy the QR link instead.';
  }
  qrRowEl.classList.remove('hidden');
};

const requestJson = async (url, options = {}) => {
  const response = await fetch(url, options);
  let payload = {};
  try {
    payload = await response.json();
  } catch {
    payload = { error: `HTTP ${response.status}` };
  }

  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status})`);
  }
  return payload;
};

const loadEncryptionConfig = async () => {
  return requestJson('/api/encryption-config', { method: 'GET' });
};

const getEncryptionConfig = () => {
  if (!encryptionConfig) {
    throw new Error('Encryption config is not loaded yet');
  }
  return encryptionConfig;
};

const getDefaultPim = () => getEncryptionConfig().defaultPim;
const getDefaultEncryptionType = () => {
  const value = String(getEncryptionConfig().defaultEncryptionType || ENCRYPTION_TYPE_STANDARD).toLowerCase();
  if (value === ENCRYPTION_TYPE_PARANOID) {
    return ENCRYPTION_TYPE_PARANOID;
  }
  return ENCRYPTION_TYPE_STANDARD;
};

const getSelectedEncryptionType = () => {
  const selected = String(encryptionTypeInputEl?.value || getDefaultEncryptionType()).toLowerCase();
  return selected === ENCRYPTION_TYPE_PARANOID ? ENCRYPTION_TYPE_PARANOID : ENCRYPTION_TYPE_STANDARD;
};

const getEncryptionProfile = (encryptionType) => {
  const cfg = getEncryptionConfig();
  const profiles = cfg.encryptionProfiles && typeof cfg.encryptionProfiles === 'object' ? cfg.encryptionProfiles : null;
  const type = encryptionType === ENCRYPTION_TYPE_PARANOID ? ENCRYPTION_TYPE_PARANOID : ENCRYPTION_TYPE_STANDARD;
  const profile = (profiles && profiles[type]) || cfg.argon2FixedProfile || {};
  const fallbackLabel = type === ENCRYPTION_TYPE_PARANOID ? 'Paranoid' : 'Standard';
  return clampArgonParams({
    label: String(profile.label || fallbackLabel),
    time: profile.time,
    mem: profile.mem,
    parallelism: profile.parallelism,
  });
};

const uploadPart = ({ uploadId, partNumber, chunkBlob, onProgress }) => {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/upload/part?uploadId=${encodeURIComponent(uploadId)}&partNumber=${partNumber}`, true);
    xhr.setRequestHeader('content-type', 'application/octet-stream');

    xhr.upload.onprogress = (event) => {
      if (typeof onProgress === 'function') {
        onProgress(event.lengthComputable ? event.loaded : 0);
      }
    };

    xhr.onerror = () => reject(new Error('Network error during upload'));
    xhr.ontimeout = () => reject(new Error('Upload timed out'));
    xhr.timeout = 180000;

    xhr.onload = () => {
      let payload = {};
      try {
        payload = xhr.responseText ? JSON.parse(xhr.responseText) : {};
      } catch {
        payload = { error: xhr.responseText || `HTTP ${xhr.status}` };
      }

      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(payload.error || 'Upload failed'));
        return;
      }
      if (typeof onProgress === 'function') {
        onProgress(chunkBlob.size);
      }
      resolve(payload);
    };

    xhr.send(chunkBlob);
  });
};

const initMultipartUpload = async ({ originalName, size, allowReceiverDelete, isNote }) => {
  const init = await requestJson('/api/upload/init', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      originalName,
      size,
      allowReceiverDelete: Boolean(allowReceiverDelete),
      isNote: Boolean(isNote),
    }),
  });

  const uploadId = init.uploadId;
  const partSize = Number(init.partSizeBytes || 50 * 1024 * 1024);
  if (!uploadId || !Number.isFinite(partSize) || partSize <= 0) {
    throw new Error('Upload initialization returned invalid session data');
  }
  return { uploadId, partSize };
};

const completeMultipartUpload = ({ uploadId, size, parts }) => {
  return requestJson('/api/upload/complete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      uploadId,
      size,
      parts,
    }),
  });
};

const abortMultipartUpload = async (uploadId) => {
  try {
    await fetch('/api/upload/abort', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ uploadId }),
    });
  } catch {
    // Ignore abort failures in client cleanup path.
  }
};

const uploadEncryptedBlobMultipart = async ({ blob, originalName, statusPrefix, allowReceiverDelete, isNote }) => {
  const { uploadId, partSize } = await initMultipartUpload({
    originalName,
    size: blob.size,
    allowReceiverDelete,
    isNote,
  });

  const parts = [];
  const partCount = Math.ceil(blob.size / partSize);
  const loadedByPart = new Map();
  const updateStatus = () => {
    let uploaded = 0;
    for (const value of loadedByPart.values()) {
      uploaded += value;
    }
    const loadedMb = formatMbProgress(uploaded);
    const totalMb = formatMbProgress(blob.size);
    showStatus(`${statusPrefix} Uploading ${loadedMb}/${totalMb} MB`);
  };

  try {
    let nextPartIndex = 0;
    const workers = [];

    const runWorker = async () => {
      while (nextPartIndex < partCount) {
        const index = nextPartIndex;
        nextPartIndex += 1;

        const partNumber = index + 1;
        const start = index * partSize;
        const chunkBlob = blob.slice(start, Math.min(start + partSize, blob.size));
        loadedByPart.set(partNumber, 0);
        updateStatus();

        const partPayload = await uploadPart({
          uploadId,
          partNumber,
          chunkBlob,
          onProgress: (loadedBytes) => {
            loadedByPart.set(partNumber, Math.min(loadedBytes, chunkBlob.size));
            updateStatus();
          },
        });

        parts[index] = {
          partNumber: partPayload.partNumber,
          etag: partPayload.etag,
        };
        loadedByPart.set(partNumber, chunkBlob.size);
        updateStatus();
      }
    };

    const parallelism = Math.min(MAX_PARALLEL_PART_UPLOADS, partCount);
    for (let i = 0; i < parallelism; i += 1) {
      workers.push(runWorker());
    }
    await Promise.all(workers);

    for (const part of parts) {
      if (!part || !part.partNumber || !part.etag) {
        throw new Error('Upload failed: missing part metadata');
      }
    }

    return completeMultipartUpload({
      uploadId,
      size: blob.size,
      parts,
    });
  } catch (err) {
    await abortMultipartUpload(uploadId);
    throw err;
  }
};

const uploadEncryptedFileStreaming = async ({ file, originalName, password, statusPrefix, allowReceiverDelete }) => {
  const pim = getDefaultPim();
  const encryptionType = getSelectedEncryptionType();
  const session = await callWorker('encrypt-init', {
    password,
    pim,
    encryptionType,
    originalName,
  }, [], {
    timeoutMs: 180000,
    onProgress: (progress) => {
      const message = progress.message || 'Preparing encryption session...';
      if (message.startsWith('Deriving key with Argon2id')) {
        startStatusDots('Deriving key with Argon2id');
        return;
      }
      showStatus(message);
    },
  });

  const sessionId = session.sessionId;
  const headerBuffer = session.headerBuffer;
  const chunkPlainSize = Number(session.chunkPlainSize || 0);
  if (!sessionId || !(headerBuffer instanceof ArrayBuffer) || !Number.isFinite(chunkPlainSize) || chunkPlainSize <= 0) {
    throw new Error('Encryption session returned invalid metadata');
  }

  const chunkCount = Math.ceil(file.size / chunkPlainSize);
  const encryptedSize = headerBuffer.byteLength + file.size + (chunkCount * 16);
  let uploadId = '';
  try {
    ({ uploadId } = await initMultipartUpload({
      originalName: 'encrypted.bin',
      size: encryptedSize,
      allowReceiverDelete,
      isNote: false,
    }));

    const parts = [];
    let uploadedBytes = 0;

    const updateStatus = (extra = '') => {
      const loadedMb = formatMbProgress(uploadedBytes);
      const totalMb = formatMbProgress(encryptedSize);
      showStatus(`${statusPrefix} Uploading ${loadedMb}/${totalMb} MB${extra}`);
    };

    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
      const start = chunkIndex * chunkPlainSize;
      const end = Math.min(start + chunkPlainSize, file.size);
      const plainChunkBuffer = await file.slice(start, end).arrayBuffer();
      showStatus(`${statusPrefix} Encrypting chunk ${chunkIndex + 1}/${chunkCount}`);
      const encryptedChunk = await callWorker('encrypt-chunk', {
        sessionId,
        chunkIndex,
        chunkBuffer: plainChunkBuffer,
      }, [plainChunkBuffer], {
        timeoutMs: 180000,
      });
      const encryptedChunkBuffer = encryptedChunk.chunkBuffer;
      const chunkBlob = chunkIndex === 0
        ? new Blob([headerBuffer, encryptedChunkBuffer], { type: 'application/octet-stream' })
        : new Blob([encryptedChunkBuffer], { type: 'application/octet-stream' });
      const baseUploadedBytes = uploadedBytes;
      const partNumber = chunkIndex + 1;
      updateStatus();
      const partPayload = await uploadPart({
        uploadId,
        partNumber,
        chunkBlob,
        onProgress: (loadedBytes) => {
          uploadedBytes = baseUploadedBytes + Math.min(loadedBytes, chunkBlob.size);
          updateStatus();
        },
      });
      uploadedBytes = baseUploadedBytes + chunkBlob.size;
      parts.push({
        partNumber: partPayload.partNumber,
        etag: partPayload.etag,
      });
    }

    return await completeMultipartUpload({
      uploadId,
      size: encryptedSize,
      parts,
    });
  } catch (err) {
    if (uploadId) {
      await abortMultipartUpload(uploadId);
    }
    throw err;
  } finally {
    try {
      await callWorker('encrypt-finish', { sessionId });
    } catch {
      // Ignore worker session cleanup failures.
    }
  }
};

const normalizeCode = (value) => {
  const digits = String(value || '').replace(/\D/g, '');
  return digits.length === 8 ? digits : null;
};

const formatCode = (value) => {
  const normalized = normalizeCode(value);
  return normalized ? normalized.match(/.{1,2}/g).join('-') : null;
};

const sanitizeCodeSegment = (value) => {
  return String(value || '').replace(/\D/g, '').slice(0, 2);
};

const syncCodeInput = () => {
  if (!codeInputEl) {
    return null;
  }
  const value = codeSegmentEls.map((input) => sanitizeCodeSegment(input.value)).join('');
  codeInputEl.value = value;
  return value;
};

const applyCodeDigits = (digits) => {
  const normalized = String(digits || '').replace(/\D/g, '').slice(0, 8);
  codeSegmentEls.forEach((input, index) => {
    input.value = normalized.slice(index * 2, index * 2 + 2);
  });
  syncCodeInput();
};

const initializeCodeInputs = () => {
  if (!codeSegmentEls.length) {
    return;
  }

  codeSegmentEls.forEach((input, index) => {
    input.addEventListener('input', (event) => {
      const sanitized = sanitizeCodeSegment(event.target.value);
      event.target.value = sanitized;
      syncCodeInput();
      hideCodeStatus();
      if (sanitized.length === 2 && index < codeSegmentEls.length - 1) {
        codeSegmentEls[index + 1].focus();
        codeSegmentEls[index + 1].select();
      }
    });

    input.addEventListener('keydown', (event) => {
      if (event.key === 'Backspace' && !event.currentTarget.value && index > 0) {
        codeSegmentEls[index - 1].focus();
        codeSegmentEls[index - 1].select();
      }
    });

    input.addEventListener('paste', (event) => {
      event.preventDefault();
      const pasted = event.clipboardData?.getData('text') || '';
      const digits = pasted.replace(/\D/g, '');
      if (!digits) {
        return;
      }
      applyCodeDigits(digits);
      const nextIndex = Math.min(Math.ceil(Math.min(digits.length, 8) / 2), codeSegmentEls.length - 1);
      codeSegmentEls[nextIndex].focus();
      codeSegmentEls[nextIndex].select();
      hideCodeStatus();
    });
  });
};

const setActiveTab = (tab) => {
  const isHome = tab === 'home';
  const isShare = tab === 'share';
  const isDownload = tab === 'download';
  const isCli = tab === 'cli';
  if (tabShareEl) {
    tabShareEl.classList.toggle('active', isShare);
    tabShareEl.setAttribute('aria-selected', String(isShare));
  }
  if (tabDownloadEl) {
    tabDownloadEl.classList.toggle('active', isDownload);
    tabDownloadEl.setAttribute('aria-selected', String(isDownload));
  }
  if (tabCliEl) {
    tabCliEl.classList.toggle('active', isCli);
    tabCliEl.setAttribute('aria-selected', String(isCli));
  }
  panelHomeEl.classList.toggle('hidden', !isHome);
  panelShareEl.classList.toggle('hidden', !isShare);
  panelDownloadEl.classList.toggle('hidden', !isDownload);
  panelCliEl.classList.toggle('hidden', !isCli);
};

const setContentType = (value) => {
  const type = value === CONTENT_TYPE_NOTE ? CONTENT_TYPE_NOTE : CONTENT_TYPE_FILE;
  if (contentTypeInputEl) {
    contentTypeInputEl.value = type;
  }
  if (contentTypeFileBtnEl) {
    const isFile = type === CONTENT_TYPE_FILE;
    contentTypeFileBtnEl.classList.toggle('active', isFile);
    contentTypeFileBtnEl.setAttribute('aria-selected', String(isFile));
  }
  if (contentTypeNoteBtnEl) {
    const isNote = type === CONTENT_TYPE_NOTE;
    contentTypeNoteBtnEl.classList.toggle('active', isNote);
    contentTypeNoteBtnEl.setAttribute('aria-selected', String(isNote));
  }
  if (fileInputWrapEl) {
    fileInputWrapEl.classList.toggle('hidden', type === CONTENT_TYPE_NOTE);
  }
  if (noteInputEl) {
    noteInputEl.required = type === CONTENT_TYPE_NOTE;
    noteInputEl.disabled = type !== CONTENT_TYPE_NOTE;
    noteInputEl.placeholder = '';
  }
  if (noteInputLabelEl) {
    noteInputLabelEl.textContent = 'PAYLOAD';
  }
  if (noteInputWrapEl) {
    noteInputWrapEl.classList.toggle('hidden', type !== CONTENT_TYPE_NOTE);
    noteInputWrapEl.classList.toggle('note-mode', type === CONTENT_TYPE_NOTE);
  }
  if (fileInputEl) {
    fileInputEl.required = false;
  }
};

const clampArgonParams = (params) => {
  return {
    label: String(params.label || 'Standard'),
    time: Math.max(1, Math.min(8, Math.floor(Number(params.time) || 2))),
    mem: Math.max(16384, Math.min(262144, Math.floor(Number(params.mem) || 32768))),
    parallelism: 1,
  };
};

const estimateMs = (baseParams, baseMs, targetParams) => {
  const baseCost = Math.max(1, baseParams.time * baseParams.mem);
  const targetCost = Math.max(1, targetParams.time * targetParams.mem);
  return Math.max(100, Math.round((baseMs || 700) * (targetCost / baseCost)));
};

const estimateAttackerGuessesPerSecond = (targetParams) => {
  const refCost = Math.max(1, ATTACKER_REF_ARGON.time * ATTACKER_REF_ARGON.mem);
  const targetCost = Math.max(1, targetParams.time * targetParams.mem);
  const scaled = ATTACKER_REF_GUESSES_PER_SECOND * (refCost / targetCost);
  return Math.max(1e-9, scaled / ATTACKER_PQ_WRAPPING_OVERHEAD);
};

const formatMs = (ms) => {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  return `${(ms / 1000).toFixed(1)}s`;
};

const guessCharsetSize = (password) => {
  let size = 0;
  if (/[a-z]/.test(password)) {
    size += 26;
  }
  if (/[A-Z]/.test(password)) {
    size += 26;
  }
  if (/[0-9]/.test(password)) {
    size += 10;
  }
  if (/[^a-zA-Z0-9]/.test(password)) {
    size += 33;
  }
  return size;
};

const formatDuration = (seconds) => {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return 'N/A';
  }
  if (seconds < 1) {
    return `${(seconds * 1000).toFixed(0)}ms`;
  }
  const units = [
    ['year', 365 * 24 * 3600],
    ['day', 24 * 3600],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ];
  for (const [name, value] of units) {
    if (seconds >= value) {
      const count = seconds / value;
      return `${count.toFixed(count >= 100 ? 0 : count >= 10 ? 1 : 2)} ${name}${count >= 2 ? 's' : ''}`;
    }
  }
  return `${seconds.toFixed(2)} seconds`;
};

const updateBruteForceEstimate = () => {
  if (qrModeInputEl && qrModeInputEl.checked) {
    bruteForceEstimateEl.textContent = 'QR Mode uses a random 256-bit key generated in this browser. The QR link itself becomes the secret.';
    return;
  }
  if (!encryptionConfig) {
    bruteForceEstimateEl.textContent = 'Password strength estimate: loading encryption profile...';
    return;
  }

  const password = passwordInputEl.value || '';
  const passwordLen = password.length;
  const charsetSize = guessCharsetSize(password);
  if (passwordLen === 0 || charsetSize === 0) {
    bruteForceEstimateEl.textContent = `Password strength estimate appears after you type a password. ${ATTACKER_REFERENCE_NOTE}`;
    return;
  }

  const selectedParams = getEncryptionProfile(getSelectedEncryptionType());
  const attackerGuessesPerSecond = estimateAttackerGuessesPerSecond(selectedParams);

  const log10SearchSpace = passwordLen * Math.log10(charsetSize);
  const log10ExpectedGuesses = log10SearchSpace - Math.log10(2);
  const log10Seconds = log10ExpectedGuesses - Math.log10(Math.max(attackerGuessesPerSecond, 1e-9));

  let crackedIn;
  if (log10Seconds > 14) {
    crackedIn = `~10^${log10Seconds.toFixed(1)} seconds`;
  } else {
    crackedIn = `~${formatDuration(10 ** log10Seconds)}`;
  }

  bruteForceEstimateEl.textContent = `Estimated offline attack time: ${crackedIn}. Assumes a random password of length ${passwordLen} over charset size ${charsetSize}, ${selectedParams.label} profile, PIM=${getDefaultPim()}, and ML-KEM wrap overhead. ${ATTACKER_REFERENCE_NOTE}`;
};

const updateSecurityEstimate = () => {
  if (!calibrationProfile) {
    securityEstimateEl.textContent = 'Estimated key setup time on this device: calculating...';
    return;
  }

  const base = calibrationProfile.params;
  const baseMs = calibrationProfile.measuredMs;
  const selectedParams = getEncryptionProfile(getSelectedEncryptionType());
  const selectedTime = estimateMs(base, baseMs, selectedParams);
  const memMb = Math.round(selectedParams.mem / 1024);
  if (securityProfileLabelEl) {
    securityProfileLabelEl.textContent = `Security profile: ${selectedParams.label}`;
  }
  securityEstimateEl.textContent = `Estimated key setup time on this device: ~${formatMs(selectedTime)}.`;
  securityDetailsEl.textContent = `Your password is processed locally with Argon2id (PIM=${getDefaultPim()}, iterations=${selectedParams.time}, memory=${memMb}MB). Reiven wraps a random file key with ML-KEM-768, then encrypts notes and file chunks in-browser with AES-256-GCM before upload. The server stores only ciphertext. Strong passwords remain critical.`;
  updateBruteForceEstimate();
};

const readCachedCalibration = () => {
  try {
    const raw = localStorage.getItem(CALIBRATION_CACHE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    const params = clampArgonParams(parsed.params || parsed);
    const measuredMs = Number.isFinite(parsed.measuredMs) ? Math.max(100, Math.round(parsed.measuredMs)) : 700;
    return { params, measuredMs };
  } catch {
    return null;
  }
};

const writeCachedCalibration = (profile) => {
  try {
    localStorage.setItem(CALIBRATION_CACHE_KEY, JSON.stringify(profile));
  } catch {
    // Ignore cache failures.
  }
};

const getCalibrationProfile = async () => {
  const cached = readCachedCalibration();
  if (cached) {
    console.debug('[argon2] using cached calibration', cached);
    return cached;
  }

  if (calibrationPromise) {
    return calibrationPromise;
  }

  calibrationPromise = (async () => {
    await workerReady;
    const result = await callWorker(
      'calibrate',
      {
        targetMinMs: 200,
        targetMaxMs: 400,
        maxRuns: 3,
      },
      [],
      {
        timeoutMs: 180000,
        onProgress: (progress) => {
          benchmarkStatusEl.textContent = progress.message || 'Calibrating Argon2id...';
        },
      }
    );
    const profile = {
      params: clampArgonParams(result.params),
      measuredMs: Number.isFinite(result.measuredMs) ? Math.max(100, Math.round(result.measuredMs)) : 700,
    };
    console.debug('[argon2] calibration result', profile);
    writeCachedCalibration(profile);
    return profile;
  })();

  try {
    return await calibrationPromise;
  } finally {
    calibrationPromise = null;
  }
};

const initializeSecurityControls = async () => {
  uploadBtn.disabled = true;
  benchmarkStatusEl.textContent = 'Preparing in-browser encryption...';

  try {
    await workerReady;
    calibrationProfile = await getCalibrationProfile();
    benchmarkStatusEl.textContent = 'In-browser encryption ready.';
    uploadBtn.disabled = false;
    updateSecurityEstimate();
  } catch (error) {
    console.error('[argon2 init]', error);
    benchmarkStatusEl.textContent = 'In-browser encryption ready with safe defaults.';
    calibrationProfile = {
      params: clampArgonParams({ time: 2, mem: 32768, parallelism: 1 }),
      measuredMs: 700,
    };
    uploadBtn.disabled = false;
    updateSecurityEstimate();
  } finally {
    finishStartupLoading();
  }
};

passwordInputEl.addEventListener('input', updateBruteForceEstimate);
if (passwordToggleBtnEl && passwordInputEl) {
  passwordToggleBtnEl.addEventListener('click', () => {
    const shouldShow = passwordInputEl.type === 'password';
    passwordInputEl.type = shouldShow ? 'text' : 'password';
    passwordToggleBtnEl.setAttribute('aria-label', shouldShow ? 'Hide encryption key' : 'Show encryption key');
    passwordToggleBtnEl.setAttribute('aria-pressed', String(shouldShow));
    passwordInputEl.focus();
  });
}
if (qrModeInputEl) {
  qrModeInputEl.addEventListener('change', () => {
    setQrModeState();
    updateBruteForceEstimate();
  });
}
if (encryptionTypeInputEl) {
  encryptionTypeInputEl.addEventListener('change', updateSecurityEstimate);
}
if (contentTypeInputEl) {
  contentTypeInputEl.addEventListener('change', () => {
    setContentType(contentTypeInputEl.value);
  });
}
if (contentTypeFileBtnEl) {
  contentTypeFileBtnEl.addEventListener('click', () => setContentType(CONTENT_TYPE_FILE));
}
if (contentTypeNoteBtnEl) {
  contentTypeNoteBtnEl.addEventListener('click', () => setContentType(CONTENT_TYPE_NOTE));
}
if (fileInputEl) {
  fileInputEl.addEventListener('change', () => {
    const file = fileInputEl.files && fileInputEl.files.length > 0 ? fileInputEl.files[0] : null;
    setSelectedFile(file);
  });
}
if (uploadDropEl) {
  const isFileDrag = (event) => Array.from(event.dataTransfer?.types || []).includes('Files');
  const showDragState = (event) => {
    if (!isFileDrag(event)) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    uploadDropEl.classList.add('drag-over');
  };
  const hideDragState = (event) => {
    if (isFileDrag(event)) {
      event.preventDefault();
      event.stopPropagation();
    }
    uploadDropEl.classList.remove('drag-over');
  };
  uploadDropEl.addEventListener('dragenter', showDragState);
  uploadDropEl.addEventListener('dragover', showDragState);
  uploadDropEl.addEventListener('dragleave', hideDragState);
  uploadDropEl.addEventListener('drop', (event) => {
    event.preventDefault();
    event.stopPropagation();
    uploadDropEl.classList.remove('drag-over');
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files.length > 0
      ? event.dataTransfer.files[0]
      : null;
    if (!file) {
      return;
    }
    setContentType(CONTENT_TYPE_FILE);
    setSelectedFile(file);
    syncFileInput(file);
  });
}
if (brandHomeBtnEl) {
  brandHomeBtnEl.addEventListener('click', () => setActiveTab('home'));
}
if (heroShareBtnEl) {
  heroShareBtnEl.addEventListener('click', () => {
    setContentType(CONTENT_TYPE_NOTE);
    setActiveTab('share');
  });
}
tabShareEl.addEventListener('click', () => setActiveTab('share'));
tabDownloadEl.addEventListener('click', () => setActiveTab('download'));
tabCliEl.addEventListener('click', () => setActiveTab('cli'));
codeInputEl.addEventListener('input', () => {
  const digits = String(codeInputEl.value || '').replace(/\D/g, '').slice(0, 8);
  const groups = digits.match(/.{1,2}/g);
  codeInputEl.value = groups ? groups.join('-') : '';
});

uploadForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const passwordInput = document.getElementById('password-input');
  const file = selectedFile || (fileInputEl ? fileInputEl.files?.[0] : null);
  const qrMode = Boolean(qrModeInputEl && qrModeInputEl.checked);

  const contentType = contentTypeInputEl && contentTypeInputEl.value === CONTENT_TYPE_NOTE
    ? CONTENT_TYPE_NOTE
    : CONTENT_TYPE_FILE;

  let originalName = 'encrypted.bin';
  let payloadBytes = null;
  if (contentType === CONTENT_TYPE_NOTE) {
    const noteText = String(noteInputEl?.value || '').trimEnd();
    if (!noteText) {
      showStatus('Please enter a note.', true);
      return;
    }
    payloadBytes = encoder.encode(noteText);
    if (payloadBytes.length > MAX_NOTE_BYTES) {
      showStatus(`Note is too large (${Math.round(payloadBytes.length / (1024 * 1024))} MB). Limit is 10 MB.`, true);
      return;
    }
    originalName = 'note.txt';
  } else {
    if (!file) {
      showStatus('Please select a file.', true);
      return;
    }
    originalName = file.name;
  }

  let password = '';
  try {
    password = qrMode ? generateRandomPassword() : String(passwordInput ? passwordInput.value : '');
  } catch (error) {
    showStatus(error.message || 'Could not generate QR Mode key', true);
    return;
  }

  if (!password) {
    showStatus('Please provide a password.', true);
    return;
  }

  try {
    const pim = getDefaultPim();
    const encryptionType = getSelectedEncryptionType();
    const allowReceiverDelete = Boolean(allowReceiverDeleteInputEl && allowReceiverDeleteInputEl.checked);
    uploadBtn.disabled = true;
    linksEl.classList.add('hidden');
    clearQrResult();
    uploadForm.classList.remove('hidden');
    await workerReady;

    if (!calibrationProfile) {
      calibrationProfile = await getCalibrationProfile();
    }

    let payload;
    const selectedProfile = getEncryptionProfile(encryptionType);

    if (contentType === CONTENT_TYPE_NOTE) {
      showStepStatus('Preparing note');
      const fileBuffer = payloadBytes.buffer;
      const encryptedResult = await callWorker(
        'encrypt',
        {
          fileBuffer,
          password,
          pim,
          encryptionType,
          baseParams: calibrationProfile.params,
          originalName,
        },
        [fileBuffer],
        {
          timeoutMs: 180000,
          onProgress: (progress) => {
            const message = progress.message || 'Encrypting in worker...';
            if (message.startsWith('Deriving key with Argon2id')) {
              startStatusDots('Deriving key with Argon2id');
              return;
            }
            showStatus(message);
          },
        }
      );

      const statusPrefix = `Profile ${selectedProfile.label}: Argon2id time=${encryptedResult.argonParams.time}, mem=${Math.round(encryptedResult.argonParams.mem / 1024)}MB, PIM=${pim}.`;
      showStatus(`${statusPrefix} Uploading...`);
      const encryptedBlob = new Blob([encryptedResult.envelopeBuffer], { type: 'application/octet-stream' });
      payload = await uploadEncryptedBlobMultipart({
        blob: encryptedBlob,
        originalName: 'encrypted.bin',
        statusPrefix,
        allowReceiverDelete,
        isNote: true,
      });
    } else {
      const statusPrefix = `Profile ${selectedProfile.label}: streaming encryption, PIM=${pim}.`;
      payload = await uploadEncryptedFileStreaming({
        file,
        originalName,
        password,
        statusPrefix,
        allowReceiverDelete,
      });
    }

    const expiresAtText = payload.expiresAt ? new Date(payload.expiresAt).toLocaleString() : 'Unknown';
    document.getElementById('download-link').href = payload.downloadUrl;
    document.getElementById('download-link').textContent = payload.downloadUrl;
    document.getElementById('delete-link').href = payload.deleteUrl || '#';
    document.getElementById('delete-link').textContent = payload.deleteUrl || 'Receiver delete disabled.';
    accessCodeEl.textContent = payload.accessCode || 'N/A';
    uploadCompleteExpiryEl.textContent = `Expires at ${expiresAtText}.`;
    deleteRowEl.classList.toggle('hidden', !payload.deleteUrl);
    if (qrMode) {
      await renderQrResult(buildQrDownloadUrl(payload.downloadUrl, password));
    } else {
      clearQrResult();
    }
    if (completeNoteEl) {
      completeNoteEl.textContent = qrMode
        ? 'QR Mode embeds the decryption key in the QR/link. Anyone with it can decrypt before expiry.'
        : 'Share the download URL/code and password separately.';
    }

    uploadForm.classList.add('hidden');
    linksEl.classList.remove('hidden');
    hideStatus();
  } catch (error) {
    showStatus(error.message || 'Upload failed', true);
    console.error('[upload flow]', error);
  } finally {
    uploadBtn.disabled = false;
  }
});

copyCodeBtn.addEventListener('click', async () => {
  const value = accessCodeEl.textContent || '';
  if (!value) {
    return;
  }
  await copyToClipboard(value, copyCodeBtn);
});

copyDownloadBtn.addEventListener('click', async () => {
  const value = document.getElementById('download-link').textContent || '';
  if (!value) {
    return;
  }
  await copyToClipboard(value, copyDownloadBtn);
});

copyDeleteBtn.addEventListener('click', async () => {
  const value = document.getElementById('delete-link').textContent || '';
  if (!value) {
    return;
  }
  await copyToClipboard(value, copyDeleteBtn);
});

if (copyQrBtn && qrLinkEl) {
  copyQrBtn.addEventListener('click', async () => {
    const value = qrLinkEl.textContent || '';
    if (!value) {
      return;
    }
    await copyToClipboard(value, copyQrBtn);
  });
}

codeDownloadForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const codeRaw = normalizeCode(syncCodeInput());
  if (!codeRaw) {
    showCodeStatus('Invalid code. Use 8 digits, for example 12-34-56-78.', true);
    return;
  }

  const displayCode = formatCode(codeRaw);
  showCodeStatus(`Resolving code ${displayCode}...`);

  try {
    const payload = await requestJson(`/api/file/code/${encodeURIComponent(codeRaw)}/info`, {
      method: 'GET',
    });

    if (!payload || !payload.id) {
      throw new Error('File not found for this code');
    }

    window.location.href = `/download?id=${encodeURIComponent(payload.id)}`;
  } catch (error) {
    showCodeStatus(error.message || 'Could not resolve file code', true);
  }
});

const initializeApp = async () => {
  initializeCodeInputs();
  try {
    encryptionConfig = await loadEncryptionConfig();
  } catch (error) {
    uploadBtn.disabled = true;
    benchmarkStatusEl.textContent = error.message || 'Could not load encryption config.';
    showStatus(error.message || 'Could not load encryption config.', true);
    finishStartupLoading();
    return;
  }
  if (encryptionTypeInputEl) {
    encryptionTypeInputEl.value = getDefaultEncryptionType();
  }
  setQrModeState();
  clearQrResult();
  setContentType(contentTypeInputEl?.value || CONTENT_TYPE_FILE);
  initializeSecurityControls();
};

initializeApp();
