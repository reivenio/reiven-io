let initError = null;
try {
  importScripts('https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js');
} catch (err) {
  initError = err && err.message ? err.message : 'Failed to load Argon2 bundle.';
}

let MAGIC = new TextEncoder().encode('ESHARE1');
let MAGIC_TEXT = 'ESHARE1';
let FORMAT_VERSION = 4;
let SALT_LEN = 16;
let IV_LEN = 12;
let CHECK_IV_LEN = 12;
let WRAP_IV_LEN = 12;
const DEK_LEN = 32;
const PQ_CT_LEN_FIELD_SIZE = 2;
let CHECK_MARKER = 'RAVEN_OK_V2';
let HEADER_FIXED_LEN = 24;
const ML_KEM_VARIANT = 'ML-KEM-768';
let ML_KEM_SEED_DOMAIN = 'REIVEN_MLKEM_SEED_V1';
const ENCRYPTION_TYPE_STANDARD = 'standard';
const ENCRYPTION_TYPE_PARANOID = 'paranoid';
let DEFAULT_ENCRYPTION_TYPE = ENCRYPTION_TYPE_STANDARD;
let ARGON2_PROFILES = {
  standard: { time: 4, mem: 65536, parallelism: 1 },
  paranoid: { time: 6, mem: 131072, parallelism: 1 },
};
let mlKem = null;

const applyEncryptionConfig = (cfg) => {
  MAGIC_TEXT = String(cfg.magic || MAGIC_TEXT);
  MAGIC = new TextEncoder().encode(MAGIC_TEXT);
  FORMAT_VERSION = Number(cfg.formatVersion || FORMAT_VERSION);
  SALT_LEN = Number(cfg.saltLen || SALT_LEN);
  IV_LEN = Number(cfg.ivLen || IV_LEN);
  CHECK_IV_LEN = Number(cfg.checkIvLen || CHECK_IV_LEN);
  WRAP_IV_LEN = Number(cfg.wrapIvLen || WRAP_IV_LEN);
  HEADER_FIXED_LEN = Number(cfg.headerFixedLen || HEADER_FIXED_LEN);
  CHECK_MARKER = String(cfg.checkMarker || CHECK_MARKER);
  ML_KEM_SEED_DOMAIN = String(cfg.mlKemSeedDomain || ML_KEM_SEED_DOMAIN);
  DEFAULT_ENCRYPTION_TYPE = String(cfg.defaultEncryptionType || DEFAULT_ENCRYPTION_TYPE).toLowerCase() === ENCRYPTION_TYPE_PARANOID
    ? ENCRYPTION_TYPE_PARANOID
    : ENCRYPTION_TYPE_STANDARD;
  if (cfg && typeof cfg.encryptionProfiles === 'object') {
    const standard = cfg.encryptionProfiles.standard || {};
    const paranoid = cfg.encryptionProfiles.paranoid || {};
    ARGON2_PROFILES = {
      standard: {
        time: Number(standard.time || ARGON2_PROFILES.standard.time),
        mem: Number(standard.mem || ARGON2_PROFILES.standard.mem),
        parallelism: Number(standard.parallelism || 1),
      },
      paranoid: {
        time: Number(paranoid.time || ARGON2_PROFILES.paranoid.time),
        mem: Number(paranoid.mem || ARGON2_PROFILES.paranoid.mem),
        parallelism: Number(paranoid.parallelism || 1),
      },
    };
  }
  if (cfg && typeof cfg.argon2FixedProfile === 'object') {
    ARGON2_PROFILES.standard = {
      time: Number(cfg.argon2FixedProfile.time || ARGON2_PROFILES.standard.time),
      mem: Number(cfg.argon2FixedProfile.mem || ARGON2_PROFILES.standard.mem),
      parallelism: Number(cfg.argon2FixedProfile.parallelism || ARGON2_PROFILES.standard.parallelism),
    };
  }
};

const loadEncryptionConfig = async () => {
  const response = await fetch('/api/encryption-config', {
    method: 'GET',
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Failed to load encryption config (${response.status})`);
  }
  const payload = await response.json();
  applyEncryptionConfig(payload || {});
  return payload;
};
const emitProgress = (id, stage, message, data = {}) => {
  self.postMessage({ type: 'progress', id, stage, message, data });
};

const getWebCrypto = () => self.crypto || self.msCrypto || globalThis.crypto || null;
const getSubtle = () => {
  const wc = getWebCrypto();
  const subtle = wc && (wc.subtle || wc.webkitSubtle);
  if (!subtle) {
    throw new Error('WebCrypto SubtleCrypto is unavailable in this browser context. Open the app over HTTPS.');
  }
  return subtle;
};

const randomBytes = (length) => {
  const wc = getWebCrypto();
  if (!wc || typeof wc.getRandomValues !== 'function') {
    throw new Error('WebCrypto getRandomValues is unavailable in this browser context.');
  }
  return wc.getRandomValues(new Uint8Array(length));
};

const initPromise = (async () => {
  if (initError) {
    return;
  }
  try {
    await loadEncryptionConfig();
    const mod = await import('https://esm.sh/@noble/post-quantum/ml-kem');
    mlKem = mod && mod.ml_kem768 ? mod.ml_kem768 : null;
    if (!mlKem || typeof mlKem.keygen !== 'function' || typeof mlKem.encapsulate !== 'function' || typeof mlKem.decapsulate !== 'function') {
      throw new Error('ML-KEM runtime missing required functions');
    }
  } catch (err) {
    initError = err && err.message ? `Failed to load ML-KEM runtime: ${err.message}` : 'Failed to load ML-KEM runtime.';
  }
})();

const concatUint8 = (...arrays) => {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
};

const clampArgonParams = (params) => ({
  time: Math.max(1, Math.min(8, Math.floor(Number(params.time) || 2))),
  mem: Math.max(16384, Math.min(262144, Math.floor(Number(params.mem) || 32768))),
  parallelism: 1,
});

const paramsWithSecurity = (encryptionType) => {
  const selectedType = String(encryptionType || DEFAULT_ENCRYPTION_TYPE).toLowerCase() === ENCRYPTION_TYPE_PARANOID
    ? ENCRYPTION_TYPE_PARANOID
    : ENCRYPTION_TYPE_STANDARD;
  const profile = ARGON2_PROFILES[selectedType] || ARGON2_PROFILES[ENCRYPTION_TYPE_STANDARD];
  return clampArgonParams(profile);
};

const deriveKek = async (password, pim, salt, params) => {
  if (!self.argon2 || !self.argon2.hash || !self.argon2.ArgonType) {
    throw new Error('Argon2 runtime not loaded in worker.');
  }

  const argonParams = clampArgonParams(params);
  const derivationSecret = `${password}\u0000${pim}`;
  const result = await self.argon2.hash({
    pass: derivationSecret,
    salt,
    hashLen: 32,
    time: argonParams.time,
    mem: argonParams.mem,
    parallelism: argonParams.parallelism,
    type: self.argon2.ArgonType.Argon2id,
  });

  const keyBytes = result.hash instanceof Uint8Array
    ? result.hash
    : new Uint8Array(result.hash);

  return { keyBytes };
};

const buildMlKemSeed = async (kekBytes) => {
  const subtle = getSubtle();
  const domain = new TextEncoder().encode(ML_KEM_SEED_DOMAIN);
  const seedMaterial = concatUint8(domain, kekBytes);
  const digest = await subtle.digest('SHA-512', seedMaterial);
  return new Uint8Array(digest);
};

const deriveMlKemKeys = async (kekBytes) => {
  if (!mlKem) {
    throw new Error('ML-KEM runtime is unavailable.');
  }
  const seed = await buildMlKemSeed(kekBytes);
  const keyPair = mlKem.keygen(seed);
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
    throw new Error('ML-KEM key generation failed.');
  }
  return keyPair;
};

const importAesKeyFromBytes = (bytes, usage) => {
  return getSubtle().importKey(
    'raw',
    bytes,
    { name: 'AES-GCM' },
    false,
    [usage]
  );
};

const buildEnvelope = (salt, checkIv, checkCiphertext, pqCiphertext, wrapIv, wrappedDek, fileIv, ciphertext, argonParams) => {
  const header = new Uint8Array(HEADER_FIXED_LEN);
  header.set(MAGIC, 0);
  header[7] = FORMAT_VERSION;
  header[8] = SALT_LEN;
  header[9] = IV_LEN;
  header[10] = argonParams.time;
  header[11] = argonParams.parallelism;
  new DataView(header.buffer).setUint32(12, argonParams.mem, false);
  header[16] = CHECK_IV_LEN;
  new DataView(header.buffer).setUint16(17, checkCiphertext.length, false);
  header[19] = WRAP_IV_LEN;
  new DataView(header.buffer).setUint16(20, wrappedDek.length, false);
  new DataView(header.buffer).setUint16(22, pqCiphertext.length, false);

  return concatUint8(header, salt, checkIv, checkCiphertext, pqCiphertext, wrapIv, wrappedDek, fileIv, ciphertext);
};

const parseEnvelope = (bytes) => {
  if (bytes.length < HEADER_FIXED_LEN + SALT_LEN + CHECK_IV_LEN + PQ_CT_LEN_FIELD_SIZE + WRAP_IV_LEN + IV_LEN + 1) {
    throw new Error('Invalid encrypted payload.');
  }

  const magic = new TextDecoder().decode(bytes.slice(0, 7));
  if (magic !== MAGIC_TEXT) {
    throw new Error('Unsupported file format.');
  }

  const version = bytes[7];
  if (version !== FORMAT_VERSION) {
    throw new Error('Unsupported file format version.');
  }

  const saltLen = bytes[8];
  const ivLen = bytes[9];
  if (saltLen !== SALT_LEN || ivLen !== IV_LEN) {
    throw new Error('Unsupported envelope layout.');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const checkIvLen = bytes[16];
  const checkCipherLen = view.getUint16(17, false);
  const wrapIvLen = bytes[19];
  const wrappedDekLen = view.getUint16(20, false);
  const pqCipherLen = view.getUint16(22, false);
  if (checkIvLen !== CHECK_IV_LEN || checkCipherLen <= 0) {
    throw new Error('Unsupported encrypted check layout.');
  }
  if (wrapIvLen !== WRAP_IV_LEN || wrappedDekLen <= 0) {
    throw new Error('Unsupported key-wrap layout.');
  }
  if (pqCipherLen <= 0) {
    throw new Error('Unsupported ML-KEM ciphertext layout.');
  }

  const time = bytes[10];
  const parallelism = bytes[11];
  const mem = view.getUint32(12, false);

  const saltStart = HEADER_FIXED_LEN;
  const checkIvStart = saltStart + saltLen;
  const checkCipherStart = checkIvStart + checkIvLen;
  const pqCipherStart = checkCipherStart + checkCipherLen;
  const wrapIvStart = pqCipherStart + pqCipherLen;
  const wrappedDekStart = wrapIvStart + wrapIvLen;
  const fileIvStart = wrappedDekStart + wrappedDekLen;
  const cipherStart = fileIvStart + ivLen;

  if (bytes.length <= cipherStart) {
    throw new Error('Encrypted payload is incomplete.');
  }

  return {
    salt: bytes.slice(saltStart, checkIvStart),
    checkIv: bytes.slice(checkIvStart, checkCipherStart),
    checkCiphertext: bytes.slice(checkCipherStart, pqCipherStart),
    pqCiphertext: bytes.slice(pqCipherStart, wrapIvStart),
    wrapIv: bytes.slice(wrapIvStart, wrappedDekStart),
    wrappedDek: bytes.slice(wrappedDekStart, fileIvStart),
    iv: bytes.slice(fileIvStart, cipherStart),
    ciphertext: bytes.slice(cipherStart),
    argonParams: clampArgonParams({ time, mem, parallelism }),
  };
};

const parseEnvelopeHeader = (bytes) => {
  if (bytes.length < HEADER_FIXED_LEN) {
    throw new Error('Encrypted header is incomplete.');
  }

  const magic = new TextDecoder().decode(bytes.slice(0, 7));
  if (magic !== MAGIC_TEXT) {
    throw new Error('Unsupported file format.');
  }

  const version = bytes[7];
  if (version !== FORMAT_VERSION) {
    throw new Error('Unsupported file format version.');
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const saltLen = bytes[8];
  const ivLen = bytes[9];
  if (saltLen !== SALT_LEN || ivLen !== IV_LEN) {
    throw new Error('Unsupported envelope layout.');
  }
  const checkIvLen = bytes[16];
  const checkCipherLen = view.getUint16(17, false);
  const wrapIvLen = bytes[19];
  const wrappedDekLen = view.getUint16(20, false);
  const pqCipherLen = view.getUint16(22, false);
  if (checkIvLen !== CHECK_IV_LEN || checkCipherLen <= 0) {
    throw new Error('Unsupported encrypted check layout.');
  }
  if (wrapIvLen !== WRAP_IV_LEN || wrappedDekLen <= 0) {
    throw new Error('Unsupported key-wrap layout.');
  }
  if (pqCipherLen <= 0) {
    throw new Error('Unsupported ML-KEM ciphertext layout.');
  }

  const time = bytes[10];
  const parallelism = bytes[11];
  const mem = view.getUint32(12, false);

  const saltStart = HEADER_FIXED_LEN;
  const checkIvStart = saltStart + saltLen;
  const checkCipherStart = checkIvStart + checkIvLen;
  const pqCipherStart = checkCipherStart + checkCipherLen;
  const wrapIvStart = pqCipherStart + pqCipherLen;
  const wrappedDekStart = wrapIvStart + wrapIvLen;
  const fileIvStart = wrappedDekStart + wrappedDekLen;
  const headerSize = fileIvStart + ivLen;
  if (bytes.length < headerSize) {
    throw new Error('Encrypted header is incomplete.');
  }

  return {
    salt: bytes.slice(saltStart, checkIvStart),
    checkIv: bytes.slice(checkIvStart, checkCipherStart),
    checkCiphertext: bytes.slice(checkCipherStart, pqCipherStart),
    pqCiphertext: bytes.slice(pqCipherStart, wrapIvStart),
    wrapIv: bytes.slice(wrapIvStart, wrappedDekStart),
    wrappedDek: bytes.slice(wrappedDekStart, fileIvStart),
    argonParams: clampArgonParams({ time, mem, parallelism }),
    headerSize,
  };
};

const buildCheckPayload = (originalName) => {
  const payload = {
    m: CHECK_MARKER,
    n: String(originalName || 'download.bin').slice(0, 255),
  };
  return new TextEncoder().encode(JSON.stringify(payload));
};

const parseCheckPayload = (plainBuffer) => {
  let parsed;
  try {
    const text = new TextDecoder().decode(plainBuffer);
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Invalid check payload');
  }

  if (!parsed || parsed.m !== CHECK_MARKER || typeof parsed.n !== 'string' || !parsed.n.trim()) {
    throw new Error('Invalid check marker');
  }

  return {
    originalName: parsed.n.slice(0, 255),
  };
};

const benchmarkArgon = async (params) => {
  const salt = randomBytes(SALT_LEN);
  const start = performance.now();
  await self.argon2.hash({
    pass: 'calibrate',
    salt,
    hashLen: 32,
    time: params.time,
    mem: params.mem,
    parallelism: params.parallelism,
    type: self.argon2.ArgonType.Argon2id,
  });
  return performance.now() - start;
};

const calibrate = async ({ targetMinMs = 500, targetMaxMs = 1000, maxRuns = 3 } = {}, id) => {
  let params = { time: 2, mem: 32768, parallelism: 1 };
  let lastMs = 0;

  for (let i = 0; i < maxRuns; i += 1) {
    emitProgress(id, 'calibrate-run-start', `Calibration run ${i + 1}/${maxRuns}`, { params });
    lastMs = await benchmarkArgon(params);
    emitProgress(id, 'calibrate-run-end', `Calibration run ${i + 1}/${maxRuns} took ${Math.round(lastMs)}ms`, { params, measuredMs: Math.round(lastMs) });
    if (lastMs >= targetMinMs && lastMs <= targetMaxMs) {
      break;
    }

    if (lastMs < targetMinMs) {
      if (params.mem < 65536) {
        params.mem += 8192;
      } else {
        params.time = Math.min(6, params.time + 1);
      }
    } else {
      if (params.time > 1) {
        params.time -= 1;
      } else {
        params.mem = Math.max(16384, params.mem - 8192);
      }
    }
  }

  return { params: clampArgonParams(params), measuredMs: Math.round(lastMs) };
};

const encrypt = async ({ fileBuffer, password, pim, encryptionType, originalName }) => {
  const subtle = getSubtle();
  const salt = randomBytes(SALT_LEN);
  const checkIv = randomBytes(CHECK_IV_LEN);
  const wrapIv = randomBytes(WRAP_IV_LEN);
  const fileIv = randomBytes(IV_LEN);
  const argonParams = paramsWithSecurity(encryptionType);

  const { keyBytes: kekBytes } = await deriveKek(password, pim, salt, argonParams);
  const rawDek = randomBytes(DEK_LEN);
  const fileKey = await subtle.importKey(
    'raw',
    rawDek,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
  const mlKemKeys = await deriveMlKemKeys(kekBytes);
  const pqShared = mlKem.encapsulate(mlKemKeys.publicKey);
  if (!pqShared || !pqShared.cipherText || !pqShared.sharedSecret) {
    throw new Error('ML-KEM encapsulation failed.');
  }
  const pqCiphertext = pqShared.cipherText;
  const pqKey = await importAesKeyFromBytes(pqShared.sharedSecret, 'encrypt');
  const checkPayload = buildCheckPayload(originalName);
  const checkCiphertext = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: checkIv },
    fileKey,
    checkPayload
  ));
  const wrappedDek = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: wrapIv },
    pqKey,
    rawDek
  ));
  const plaintext = new Uint8Array(fileBuffer);
  const ciphertext = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: fileIv },
    fileKey,
    plaintext
  ));

  const envelope = buildEnvelope(salt, checkIv, checkCiphertext, pqCiphertext, wrapIv, wrappedDek, fileIv, ciphertext, argonParams);
  return {
    envelopeBuffer: envelope.buffer,
    argonParams,
    pqc: ML_KEM_VARIANT,
  };
};

const decrypt = async ({ encryptedBuffer, password, pim }) => {
  const bytes = new Uint8Array(encryptedBuffer);
  const parsed = parseEnvelope(bytes);
  const subtle = getSubtle();
  const { keyBytes: kekBytes } = await deriveKek(password, pim, parsed.salt, parsed.argonParams);

  let plaintext;
  let checkInfo;
  try {
    const mlKemKeys = await deriveMlKemKeys(kekBytes);
    const pqSharedSecret = mlKem.decapsulate(parsed.pqCiphertext, mlKemKeys.secretKey);
    if (!pqSharedSecret) {
      throw new Error('ML-KEM decapsulation failed.');
    }
    const pqKey = await importAesKeyFromBytes(pqSharedSecret, 'decrypt');
    const rawDek = await subtle.decrypt(
      { name: 'AES-GCM', iv: parsed.wrapIv },
      pqKey,
      parsed.wrappedDek
    );
    const fileKey = await subtle.importKey(
      'raw',
      rawDek,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    const checkPlain = await subtle.decrypt(
      { name: 'AES-GCM', iv: parsed.checkIv },
      fileKey,
      parsed.checkCiphertext
    );
    checkInfo = parseCheckPayload(checkPlain);

    plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: parsed.iv },
      fileKey,
      parsed.ciphertext
    );
  } catch (err) {
    throw new Error('Decryption failed. Check password/PIM.');
  }

  return {
    plaintextBuffer: plaintext,
    argonParams: parsed.argonParams,
    originalName: checkInfo.originalName,
  };
};

const verifyKeyFromHeader = async ({ headerBuffer, password, pim }) => {
  const bytes = new Uint8Array(headerBuffer);
  const header = parseEnvelopeHeader(bytes);
  const subtle = getSubtle();
  const { keyBytes: kekBytes } = await deriveKek(password, pim, header.salt, header.argonParams);

  try {
    const mlKemKeys = await deriveMlKemKeys(kekBytes);
    const pqSharedSecret = mlKem.decapsulate(header.pqCiphertext, mlKemKeys.secretKey);
    if (!pqSharedSecret) {
      throw new Error('ML-KEM decapsulation failed.');
    }
    const pqKey = await importAesKeyFromBytes(pqSharedSecret, 'decrypt');
    const rawDek = await subtle.decrypt(
      { name: 'AES-GCM', iv: header.wrapIv },
      pqKey,
      header.wrappedDek
    );
    const fileKey = await subtle.importKey(
      'raw',
      rawDek,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    const checkPlain = await subtle.decrypt(
      { name: 'AES-GCM', iv: header.checkIv },
      fileKey,
      header.checkCiphertext
    );
    const checkInfo = parseCheckPayload(checkPlain);
    return {
      argonParams: header.argonParams,
      headerSize: header.headerSize,
      originalName: checkInfo.originalName,
      pqc: ML_KEM_VARIANT,
    };
  } catch (err) {
    throw new Error('Decryption failed. Check password/PIM.');
  }
};

initPromise.finally(() => {
  self.postMessage({
    type: 'ready',
    ok: !initError,
    error: initError || null,
    pqc: mlKem ? ML_KEM_VARIANT : null,
  });
});

self.onmessage = async (event) => {
  const { id, type, payload } = event.data || {};
  if (typeof id === 'undefined' || !type) {
    return;
  }

  await initPromise;
  if (initError) {
    self.postMessage({ id, ok: false, error: initError });
    return;
  }

  try {
    let result;
    if (type === 'calibrate') {
      result = await calibrate(payload || {}, id);
      self.postMessage({ id, ok: true, result });
      return;
    }
    if (type === 'encrypt') {
      emitProgress(id, 'encrypt-derive', 'Deriving key with Argon2id');
      result = await encrypt(payload || {});
      emitProgress(id, 'encrypt-done', 'Encryption finished', { argonParams: result.argonParams });
      self.postMessage({ id, ok: true, result }, [result.envelopeBuffer]);
      return;
    }
    if (type === 'decrypt') {
      emitProgress(id, 'decrypt-derive', 'Deriving key with Argon2id');
      result = await decrypt(payload || {});
      emitProgress(id, 'decrypt-done', 'Decryption finished');
      self.postMessage({ id, ok: true, result }, [result.plaintextBuffer]);
      return;
    }
    if (type === 'verify-header') {
      emitProgress(id, 'verify-derive', 'Verifying password from encrypted header');
      result = await verifyKeyFromHeader(payload || {});
      emitProgress(id, 'verify-done', 'Password check succeeded', { argonParams: result.argonParams });
      self.postMessage({ id, ok: true, result });
      return;
    }

    throw new Error(`Unsupported worker action: ${type}`);
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: error && error.message ? error.message : 'Worker error',
    });
  }
};
