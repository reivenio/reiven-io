const CALIBRATION_CACHE_KEY = 'eshare_argon_calibration_v3';
const ATTACKER_CPU_NAME = 'AMD Threadripper PRO 9995WX (96 cores)';
const ATTACKER_REF_ARGON = Object.freeze({ time: 4, mem: 65536, parallelism: 1 });
const ATTACKER_REF_GUESSES_PER_SECOND = 0.55;
const ATTACKER_PQ_WRAPPING_OVERHEAD = 1.08;
const ATTACKER_REFERENCE_NOTE = 'Model anchored to fixed Argon2id benchmark assumptions for this hardware class (tuned constant, not local calibration).';
const MAX_PARALLEL_PART_UPLOADS = 3;
let encryptionConfig = null;

const uploadForm = document.getElementById('upload-form');
const statusEl = document.getElementById('status');
const linksEl = document.getElementById('links');
const accessCodeEl = document.getElementById('access-code');
const copyCodeBtn = document.getElementById('copy-code-btn');
const copyDownloadBtn = document.getElementById('copy-download-btn');
const copyDeleteBtn = document.getElementById('copy-delete-btn');
const uploadBtn = document.getElementById('upload-btn');
const benchmarkStatusEl = document.getElementById('benchmark-status');
const securityEstimateEl = document.getElementById('security-estimate');
const securityDetailsEl = document.getElementById('security-details');
const bruteForceEstimateEl = document.getElementById('bruteforce-estimate');
const passwordInputEl = document.getElementById('password-input');
const tabShareEl = document.getElementById('tab-share');
const tabDownloadEl = document.getElementById('tab-download');
const tabCliEl = document.getElementById('tab-cli');
const panelShareEl = document.getElementById('panel-share');
const panelDownloadEl = document.getElementById('panel-download');
const panelCliEl = document.getElementById('panel-cli');
const codeDownloadForm = document.getElementById('code-download-form');
const codeInputEl = document.getElementById('code-input');
const codeStatusEl = document.getElementById('code-status');
const startupOverlayEl = document.getElementById('startup-overlay');

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
const getDefaultSecurityLevel = () => getEncryptionConfig().defaultSecurityLevel;
const getFixedLevelLabel = () => getEncryptionConfig().fixedLevelLabel;

const getArgonFixedProfile = () => {
  const cfg = getEncryptionConfig();
  const profile = cfg.argon2FixedProfile || {};
  return clampArgonParams({
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

const uploadEncryptedBlobMultipart = async ({ blob, originalName, statusPrefix }) => {
  const init = await requestJson('/api/upload/init', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      originalName,
      size: blob.size,
    }),
  });

  const uploadId = init.uploadId;
  const partSize = Number(init.partSizeBytes || 50 * 1024 * 1024);
  if (!uploadId || !Number.isFinite(partSize) || partSize <= 0) {
    throw new Error('Upload initialization returned invalid session data');
  }

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

    return requestJson('/api/upload/complete', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        uploadId,
        size: blob.size,
        parts,
      }),
    });
  } catch (err) {
    try {
      await fetch('/api/upload/abort', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ uploadId }),
      });
    } catch {
      // Ignore abort failures in client cleanup path.
    }
    throw err;
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

const setActiveTab = (tab) => {
  const isShare = tab === 'share';
  const isDownload = tab === 'download';
  const isCli = tab === 'cli';
  tabShareEl.classList.toggle('active', isShare);
  tabDownloadEl.classList.toggle('active', isDownload);
  tabCliEl.classList.toggle('active', isCli);
  tabShareEl.setAttribute('aria-selected', String(isShare));
  tabDownloadEl.setAttribute('aria-selected', String(isDownload));
  tabCliEl.setAttribute('aria-selected', String(isCli));
  panelShareEl.classList.toggle('hidden', !isShare);
  panelDownloadEl.classList.toggle('hidden', !isDownload);
  panelCliEl.classList.toggle('hidden', !isCli);
};

const clampArgonParams = (params) => ({
  time: Math.max(1, Math.min(8, Math.floor(Number(params.time) || 2))),
  mem: Math.max(16384, Math.min(262144, Math.floor(Number(params.mem) || 32768))),
  parallelism: 1,
});

const paramsForLevel = (baseParams, securityLevel, pim) => {
  // Keep estimator aligned with crypto-worker fixed Argon2 profile.
  return getArgonFixedProfile();
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
  if (!encryptionConfig) {
    bruteForceEstimateEl.textContent = `Brute-force baseline (${ATTACKER_CPU_NAME}): loading encryption profile...`;
    return;
  }

  const password = passwordInputEl.value || '';
  const passwordLen = password.length;
  const charsetSize = guessCharsetSize(password);
  if (passwordLen === 0 || charsetSize === 0) {
    bruteForceEstimateEl.textContent = `Brute-force baseline (${ATTACKER_CPU_NAME}): enter a password to estimate crack time. ${ATTACKER_REFERENCE_NOTE}`;
    return;
  }

  const selectedParams = getArgonFixedProfile();
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

  bruteForceEstimateEl.textContent = `Estimated average crack time (${ATTACKER_CPU_NAME}, highly optimized CPU attack): ${crackedIn}. Assumes random password of length ${passwordLen} over charset size ${charsetSize}, fixed ${getFixedLevelLabel()} profile, PIM=${getDefaultPim()}, and includes ML-KEM wrap overhead. ${ATTACKER_REFERENCE_NOTE}`;
};

const updateSecurityEstimate = () => {
  if (!calibrationProfile) {
    securityEstimateEl.textContent = 'Estimated encryption time on your device: calculating...';
    return;
  }

  const base = calibrationProfile.params;
  const baseMs = calibrationProfile.measuredMs;
  const selectedParams = paramsForLevel(base, getDefaultSecurityLevel(), getDefaultPim());
  const selectedTime = estimateMs(base, baseMs, selectedParams);
  const memMb = Math.round(selectedParams.mem / 1024);
  securityEstimateEl.textContent = `Estimated encryption time on your device: ~${formatMs(selectedTime)}.`;
  securityDetailsEl.textContent = `Encryption is done in-browser using Argon2id (PIM=${getDefaultPim()}, iterations=${selectedParams.time}, memory=${memMb}MB, parallelism=${selectedParams.parallelism}) to derive a KEK seed. A deterministic ML-KEM-768 keypair is derived from that seed, the DEK is wrapped via ML-KEM shared secret, and file payload uses AES-256-GCM with a random 256-bit DEK.`;
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
  benchmarkStatusEl.textContent = 'Running browser benchmark...';

  try {
    await workerReady;
    calibrationProfile = await getCalibrationProfile();
    benchmarkStatusEl.textContent = `Baseline ready (${formatMs(calibrationProfile.measuredMs)}).`;
    uploadBtn.disabled = false;
    updateSecurityEstimate();
  } catch (error) {
    console.error('[argon2 init]', error);
    benchmarkStatusEl.textContent = 'Benchmark failed, using safe defaults.';
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

  const fileInput = document.getElementById('file-input');
  const passwordInput = document.getElementById('password-input');
  const file = fileInput.files?.[0];
  const password = passwordInput.value;

  if (!file) {
    showStatus('Please select a file.', true);
    return;
  }

  if (!password) {
    showStatus('Please provide a password.', true);
    return;
  }

  try {
    const pim = getDefaultPim();
    const securityLevel = getDefaultSecurityLevel();
    uploadBtn.disabled = true;
    linksEl.classList.add('hidden');
    uploadForm.classList.remove('hidden');
    await workerReady;

    if (!calibrationProfile) {
      calibrationProfile = await getCalibrationProfile();
    }

    showStepStatus('Reading file in browser');
    const fileBuffer = await file.arrayBuffer();
    const encryptedResult = await callWorker(
      'encrypt',
      {
        fileBuffer,
        password,
        pim,
        securityLevel,
        baseParams: calibrationProfile.params,
        originalName: file.name,
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

    const statusPrefix = `Profile ${getFixedLevelLabel()}: Argon2id time=${encryptedResult.argonParams.time}, mem=${Math.round(encryptedResult.argonParams.mem / 1024)}MB, PIM=${pim}.`;
    showStatus(`${statusPrefix} Uploading...`);
    const encryptedBlob = new Blob([encryptedResult.envelopeBuffer], { type: 'application/octet-stream' });
    const encryptedName = 'encrypted.bin';

    const payload = await uploadEncryptedBlobMultipart({
      blob: encryptedBlob,
      originalName: encryptedName,
      statusPrefix,
    });

    document.getElementById('download-link').href = payload.downloadUrl;
    document.getElementById('download-link').textContent = payload.downloadUrl;
    document.getElementById('delete-link').href = payload.deleteUrl;
    document.getElementById('delete-link').textContent = payload.deleteUrl;
    accessCodeEl.textContent = payload.accessCode || 'N/A';

    uploadForm.classList.add('hidden');
    linksEl.classList.remove('hidden');
    showStatus(`Upload complete. Expires at ${new Date(payload.expiresAt).toLocaleString()}.`);
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

codeDownloadForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const codeRaw = normalizeCode(codeInputEl.value);
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

    window.location.href = `/download.html?id=${encodeURIComponent(payload.id)}`;
  } catch (error) {
    showCodeStatus(error.message || 'Could not resolve file code', true);
  }
});

const initializeApp = async () => {
  try {
    encryptionConfig = await loadEncryptionConfig();
  } catch (error) {
    uploadBtn.disabled = true;
    benchmarkStatusEl.textContent = error.message || 'Could not load encryption config.';
    showStatus(error.message || 'Could not load encryption config.', true);
    finishStartupLoading();
    return;
  }
  initializeSecurityControls();
};

initializeApp();
