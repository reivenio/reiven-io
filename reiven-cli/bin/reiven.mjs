#!/usr/bin/env node

import { writeFile, access, readFile, stat } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { webcrypto } from 'node:crypto';
import { argon2id } from 'hash-wasm';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ENCRYPTION_CONFIG } from '../../shared/encryption-config.mjs';

const MAGIC = ENCRYPTION_CONFIG.magic;
const FORMAT_VERSION = ENCRYPTION_CONFIG.formatVersion;
const SALT_LEN = ENCRYPTION_CONFIG.saltLen;
const IV_LEN = ENCRYPTION_CONFIG.ivLen;
const CHECK_IV_LEN = ENCRYPTION_CONFIG.checkIvLen;
const WRAP_IV_LEN = ENCRYPTION_CONFIG.wrapIvLen;
const HEADER_FIXED_LEN = ENCRYPTION_CONFIG.headerFixedLen;
const HEADER_PROBE_BYTES = ENCRYPTION_CONFIG.headerProbeBytes;
const DEFAULT_PIM = ENCRYPTION_CONFIG.defaultPim;
const CHECK_MARKER = ENCRYPTION_CONFIG.checkMarker;
const ML_KEM_SEED_DOMAIN = ENCRYPTION_CONFIG.mlKemSeedDomain;
const ARGON2_FIXED_PROFILE = ENCRYPTION_CONFIG.argon2FixedProfile || { time: 4, mem: 65536, parallelism: 1 };
const MAGIC_BYTES = new TextEncoder().encode(MAGIC);
const DEK_LEN = 32;
const DEFAULT_PART_SIZE_BYTES = 50 * 1024 * 1024;
const UPLOAD_PROGRESS_CHUNK_BYTES = 5 * 1024 * 1024;
const REQUEST_STREAM_CHUNK_BYTES = 256 * 1024;

const subtle = webcrypto.subtle;
const isTTY = Boolean(process.stdout && process.stdout.isTTY);

const formatProgressBytes = (bytes) => {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const fixed = value >= 100 || unitIndex === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(fixed)} ${units[unitIndex]}`;
};

const createProgressRenderer = (label) => {
  let lastLength = 0;
  let active = false;
  return {
    update(loaded, total = 0) {
      const hasTotal = Number.isFinite(total) && total > 0;
      const percent = hasTotal ? Math.max(0, Math.min(100, (loaded / total) * 100)) : null;
      const line = hasTotal
        ? `${label}: ${percent.toFixed(1)}% (${formatProgressBytes(loaded)}/${formatProgressBytes(total)})`
        : `${label}: ${formatProgressBytes(loaded)}`;
      if (isTTY && typeof process.stdout.clearLine === 'function' && typeof process.stdout.cursorTo === 'function') {
        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        process.stdout.write(line);
        lastLength = line.length;
        active = true;
      } else {
        console.log(line);
      }
    },
    done() {
      if (isTTY && active) {
        process.stdout.write('\n');
      } else if (!isTTY && lastLength > 0) {
        console.log(`${label}: done`);
      }
      active = false;
      lastLength = 0;
    },
  };
};

const printUsage = () => {
  console.log(`Usage:
  reiven get <file-id-or-access-code> [--base https://reiven.io] [--out <directory>] [--pim 100] [--debug]
  reiven put <file-path> [--base https://reiven.io] [--storage r2|mem] [--mem] [--pim 100] [--debug]
  reiven upload <file-path> [--base https://reiven.io] [--storage r2|mem] [--mem] [--pim 100] [--debug]

Examples:
  reiven get 23287345
  reiven get 12-34-56-78
  reiven get f8a91c2de --out ./downloads
  reiven get 23287345 --base https://reiven.io
  reiven put ./report.pdf
  reiven put ./report.pdf --mem`);
};

const fail = (message, code = 1) => {
  console.error(`Error: ${message}`);
  process.exit(code);
};

const parseArgs = (argv) => {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    return { help: true };
  }

  const [commandRaw, target, ...rest] = argv;
  const command = commandRaw === 'upload' ? 'put' : commandRaw;
  if (command !== 'get' && command !== 'put') {
    fail(`Unsupported command: ${commandRaw}`);
  }
  if (!target) {
    fail(command === 'get' ? 'Missing file id or access code.' : 'Missing file path.');
  }

  let base = process.env.REIVEN_BASE_URL || 'https://reiven.io';
  let outDir = process.cwd();
  let pim = DEFAULT_PIM;
  let debug = false;
  let storage = STORAGE_R2;

  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (arg === '--base') {
      const value = rest[i + 1];
      if (!value) fail('Missing value for --base.');
      base = value;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = rest[i + 1];
      if (!value) fail('Missing value for --out.');
      outDir = value;
      i += 1;
      continue;
    }
    if (arg === '--pim') {
      const value = Number(rest[i + 1]);
      if (!Number.isInteger(value) || value < 1) fail('Invalid --pim value.');
      pim = value;
      i += 1;
      continue;
    }
    if (arg === '--debug') {
      debug = true;
      continue;
    }
    if (arg === '--mem') {
      storage = STORAGE_MEM;
      continue;
    }
    if (arg === '--storage') {
      const value = normalizeStorage(rest[i + 1]);
      if (!rest[i + 1]) fail('Missing value for --storage.');
      storage = value;
      i += 1;
      continue;
    }
    fail(`Unknown argument: ${arg}`);
  }

  let normalizedBase;
  try {
    normalizedBase = new URL(base).origin;
  } catch {
    fail(`Invalid --base URL: ${base}`);
  }

  return {
    help: false,
    command,
    target,
    base: normalizedBase,
    outDir: command === 'get' ? path.resolve(outDir) : undefined,
    pim,
    debug,
    storage,
  };
};

const STORAGE_R2 = 'r2';
const STORAGE_MEM = 'mem';

const normalizeStorage = (value) => {
  const v = String(value || '').toLowerCase();
  return v === STORAGE_MEM ? STORAGE_MEM : STORAGE_R2;
};

const parseApiResponse = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      return await response.json();
    } catch {
      return { error: `HTTP ${response.status}` };
    }
  }

  try {
    const text = await response.text();
    return { error: text || `HTTP ${response.status}` };
  } catch {
    return { error: `HTTP ${response.status}` };
  }
};

const normalizeAccessCode = (value) => {
  const digits = String(value || '').replace(/\D/g, '');
  return digits.length === 8 ? digits : null;
};

const apiGet = async (url) => {
  const response = await fetch(url);
  const payload = response.ok ? await response.json() : await parseApiResponse(response);
  return { response, payload };
};

const resolveFileId = async (base, target) => {
  const code = normalizeAccessCode(target);
  if (code) {
    const { response, payload } = await apiGet(`${base}/api/file/code/${code}/info`);
    if (!response.ok) {
      throw new Error(payload?.error || 'Failed to resolve access code');
    }
    return {
      id: String(payload.id),
      size: Number(payload.size || 0),
      source: 'code',
    };
  }

  const id = encodeURIComponent(target);
  const { response, payload } = await apiGet(`${base}/api/file/${id}/info`);
  if (!response.ok) {
    throw new Error(payload?.error || 'Failed to load file info');
  }
  return {
    id: String(payload.id),
    size: Number(payload.size || 0),
    source: 'id',
  };
};

const clampArgonParams = (params) => ({
  time: Math.max(1, Math.min(8, Math.floor(Number(params.time) || 2))),
  mem: Math.max(16384, Math.min(262144, Math.floor(Number(params.mem) || 32768))),
  parallelism: 1,
});

const randomBytes = (length) => {
  const out = new Uint8Array(length);
  webcrypto.getRandomValues(out);
  return out;
};

const buildCheckPayload = (originalName) => {
  const payload = {
    m: CHECK_MARKER,
    n: String(originalName || 'download.bin').slice(0, 255),
  };
  return new TextEncoder().encode(JSON.stringify(payload));
};

const buildEnvelope = (salt, checkIv, checkCiphertext, pqCiphertext, wrapIv, wrappedDek, fileIv, ciphertext, argonParams) => {
  const header = new Uint8Array(HEADER_FIXED_LEN);
  header.set(MAGIC_BYTES, 0);
  header[7] = FORMAT_VERSION;
  header[8] = SALT_LEN;
  header[9] = IV_LEN;
  header[10] = argonParams.time;
  header[11] = argonParams.parallelism;
  const view = new DataView(header.buffer);
  view.setUint32(12, argonParams.mem, false);
  header[16] = CHECK_IV_LEN;
  view.setUint16(17, checkCiphertext.length, false);
  header[19] = WRAP_IV_LEN;
  view.setUint16(20, wrappedDek.length, false);
  view.setUint16(22, pqCiphertext.length, false);

  const total = header.length
    + salt.length
    + checkIv.length
    + checkCiphertext.length
    + pqCiphertext.length
    + wrapIv.length
    + wrappedDek.length
    + fileIv.length
    + ciphertext.length;
  const envelope = new Uint8Array(total);

  let offset = 0;
  for (const segment of [header, salt, checkIv, checkCiphertext, pqCiphertext, wrapIv, wrappedDek, fileIv, ciphertext]) {
    envelope.set(segment, offset);
    offset += segment.length;
  }
  return envelope;
};

const parseEnvelopeHeader = (bytes) => {
  if (bytes.length < HEADER_FIXED_LEN) {
    throw new Error('Encrypted header is incomplete.');
  }

  const magic = new TextDecoder().decode(bytes.slice(0, 7));
  if (magic !== MAGIC) {
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

const parseEnvelope = (bytes) => {
  const header = parseEnvelopeHeader(bytes);
  const ivStart = header.headerSize - IV_LEN;
  const cipherStart = header.headerSize;
  if (bytes.length <= cipherStart) {
    throw new Error('Encrypted payload is incomplete.');
  }

  return {
    ...header,
    iv: bytes.slice(ivStart, ivStart + IV_LEN),
    ciphertext: bytes.slice(cipherStart),
  };
};

const deriveKek = async (password, pim, salt, params) => {
  const argonParams = clampArgonParams(params);
  const derivationSecret = `${password}\u0000${pim}`;

  const keyBytes = await argon2id({
    password: derivationSecret,
    salt,
    iterations: argonParams.time,
    memorySize: argonParams.mem,
    parallelism: argonParams.parallelism,
    hashLength: 32,
    outputType: 'binary',
  });

  return new Uint8Array(keyBytes);
};

const paramsWithSecurity = () => clampArgonParams(ARGON2_FIXED_PROFILE);

const buildMlKemSeed = async (kekBytes) => {
  const domain = new TextEncoder().encode(ML_KEM_SEED_DOMAIN);
  const seedMaterial = new Uint8Array(domain.length + kekBytes.length);
  seedMaterial.set(domain, 0);
  seedMaterial.set(kekBytes, domain.length);
  const digest = await subtle.digest('SHA-512', seedMaterial);
  return new Uint8Array(digest);
};

const deriveMlKemKeys = async (kekBytes) => {
  const seed = await buildMlKemSeed(kekBytes);
  const keyPair = ml_kem768.keygen(seed);
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
    throw new Error('ML-KEM key generation failed.');
  }
  return keyPair;
};

const importAesKeyFromBytes = (bytes, usage) => subtle.importKey(
  'raw',
  bytes,
  { name: 'AES-GCM' },
  false,
  [usage]
);

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

const encryptPayload = async (fileBytes, password, pim, originalName) => {
  const salt = randomBytes(SALT_LEN);
  const checkIv = randomBytes(CHECK_IV_LEN);
  const wrapIv = randomBytes(WRAP_IV_LEN);
  const fileIv = randomBytes(IV_LEN);
  const argonParams = paramsWithSecurity();

  const kekBytes = await deriveKek(password, pim, salt, argonParams);
  const rawDek = randomBytes(DEK_LEN);
  const fileKey = await subtle.importKey(
    'raw',
    rawDek,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  const mlKemKeys = await deriveMlKemKeys(kekBytes);
  const pqShared = ml_kem768.encapsulate(mlKemKeys.publicKey);
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
  const ciphertext = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: fileIv },
    fileKey,
    fileBytes
  ));

  return {
    envelopeBytes: buildEnvelope(
      salt,
      checkIv,
      checkCiphertext,
      pqCiphertext,
      wrapIv,
      wrappedDek,
      fileIv,
      ciphertext,
      argonParams
    ),
    argonParams,
  };
};

const verifyHeaderPassword = async (headerBytes, password, pim) => {
  const header = parseEnvelopeHeader(headerBytes);
  const kekBytes = await deriveKek(password, pim, header.salt, header.argonParams);

  try {
    const mlKemKeys = await deriveMlKemKeys(kekBytes);
    const pqSharedSecret = ml_kem768.decapsulate(header.pqCiphertext, mlKemKeys.secretKey);
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
      originalName: checkInfo.originalName,
      headerSize: header.headerSize,
      argonParams: header.argonParams,
    };
  } catch {
    throw new Error('Decryption failed. Check password/PIM.');
  }
};

const decryptPayload = async (encryptedBytes, password, pim) => {
  const parsed = parseEnvelope(encryptedBytes);
  const kekBytes = await deriveKek(password, pim, parsed.salt, parsed.argonParams);

  try {
    const mlKemKeys = await deriveMlKemKeys(kekBytes);
    const pqSharedSecret = ml_kem768.decapsulate(parsed.pqCiphertext, mlKemKeys.secretKey);
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
    const checkInfo = parseCheckPayload(checkPlain);

    const plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: parsed.iv },
      fileKey,
      parsed.ciphertext
    );

    return {
      plaintext: new Uint8Array(plaintext),
      originalName: checkInfo.originalName,
    };
  } catch {
    throw new Error('Decryption failed. Check password/PIM.');
  }
};

const askPassword = async (prompt = 'Password: ') => new Promise((resolve, reject) => {
  if (!process.stdin.isTTY || !process.stdout.isTTY || typeof process.stdin.setRawMode !== 'function') {
    reject(new Error('Interactive TTY is required for password input.'));
    return;
  }

  process.stdout.write(prompt);
  let password = '';

  const finish = (error) => {
    process.stdin.setRawMode(false);
    process.stdin.pause();
    process.stdin.removeListener('data', onData);
    process.stdout.write('\n');
    if (error) {
      reject(error);
      return;
    }
    if (!password) {
      reject(new Error('Password is required.'));
      return;
    }
    resolve(password);
  };

  const onData = (chunk) => {
    const text = chunk.toString('utf8');
    for (const ch of text) {
      if (ch === '\u0003') {
        finish(new Error('Aborted.'));
        return;
      }
      if (ch === '\r' || ch === '\n') {
        finish();
        return;
      }
      if (ch === '\u007f' || ch === '\b') {
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.write('\b \b');
        }
        continue;
      }
      if (ch >= ' ') {
        password += ch;
        process.stdout.write('*');
      }
    }
  };

  process.stdin.resume();
  process.stdin.setRawMode(true);
  process.stdin.on('data', onData);
});

const sanitizeFileName = (value) => {
  const name = path.basename(String(value || '').trim());
  if (!name || name === '.' || name === '..') {
    return 'download.bin';
  }
  return name.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 255) || 'download.bin';
};

const fileExists = async (filePath) => {
  try {
    await access(filePath, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
};

const uniqueOutputPath = async (dir, desiredName) => {
  const parsed = path.parse(desiredName);
  const baseName = parsed.name || 'download';
  const ext = parsed.ext || '';

  const firstPath = path.join(dir, `${baseName}${ext}`);
  if (!(await fileExists(firstPath))) {
    return firstPath;
  }

  for (let i = 1; i < 1000; i += 1) {
    const candidate = path.join(dir, `${baseName} (${i})${ext}`);
    if (!(await fileExists(candidate))) {
      return candidate;
    }
  }

  throw new Error('Could not find a free output filename.');
};

const getHeaderProbe = async (base, fileId) => {
  const url = `${base}/api/file/${encodeURIComponent(fileId)}/download`;
  const response = await fetch(url, {
    headers: {
      range: `bytes=0-${HEADER_PROBE_BYTES - 1}`,
    },
  });

  if (!response.ok) {
    const payload = await parseApiResponse(response);
    throw new Error(payload?.error || 'Failed to download encrypted header');
  }

  return new Uint8Array(await response.arrayBuffer());
};

const getEncryptedPayload = async (base, fileId) => {
  const url = `${base}/api/file/${encodeURIComponent(fileId)}/download`;
  const response = await fetch(url);

  if (!response.ok) {
    const payload = await parseApiResponse(response);
    throw new Error(payload?.error || 'Failed to download encrypted payload');
  }

  const total = Number(response.headers.get('content-length') || 0);
  const progress = createProgressRenderer('Download');

  if (!response.body) {
    const buffer = new Uint8Array(await response.arrayBuffer());
    progress.update(buffer.byteLength, total);
    progress.done();
    return buffer;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let loaded = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    chunks.push(value);
    loaded += value.byteLength;
    progress.update(loaded, total);
  }
  progress.done();

  const merged = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
};

const postJson = async (url, body) => {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  const payload = await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload?.error || `Request failed (${response.status})`);
  }
  return payload;
};

const uploadPart = async (base, uploadId, partNumber, chunkBytes, onProgress) => {
  const url = `${base}/api/upload/part?uploadId=${encodeURIComponent(uploadId)}&partNumber=${partNumber}`;
  let offset = 0;
  const total = chunkBytes.byteLength;
  const bodyStream = new ReadableStream({
    pull(controller) {
      if (offset >= total) {
        controller.close();
        return;
      }
      const end = Math.min(offset + REQUEST_STREAM_CHUNK_BYTES, total);
      controller.enqueue(chunkBytes.subarray(offset, end));
      offset = end;
      if (typeof onProgress === 'function') {
        onProgress(offset, total);
      }
    },
  });

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: bodyStream,
    duplex: 'half',
  });

  const payload = await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload?.error || `Part upload failed (${response.status})`);
  }
  if (!payload || !payload.etag) {
    throw new Error('Part upload failed: missing etag');
  }
  return {
    partNumber,
    etag: String(payload.etag),
  };
};

const uploadEncryptedMultipart = async (base, encryptedBytes, storage, debug = false) => {
  const init = await postJson(`${base}/api/upload/init`, {
    originalName: 'encrypted.bin',
    size: encryptedBytes.byteLength,
    storage: normalizeStorage(storage),
  });

  const uploadId = String(init.uploadId || '');
  const serverPartSize = Number(init.partSizeBytes || DEFAULT_PART_SIZE_BYTES);
  if (!uploadId || !Number.isFinite(serverPartSize) || serverPartSize <= 0) {
    throw new Error('Upload initialization returned invalid session data');
  }
  const partSize = Math.max(1, Math.min(serverPartSize, UPLOAD_PROGRESS_CHUNK_BYTES));

  const partCount = Math.ceil(encryptedBytes.byteLength / partSize);
  const parts = [];
  const progress = createProgressRenderer('Upload');
  let uploaded = 0;

  try {
    for (let i = 0; i < partCount; i += 1) {
      const partNumber = i + 1;
      const start = i * partSize;
      const end = Math.min(start + partSize, encryptedBytes.byteLength);
      const chunk = encryptedBytes.slice(start, end);
      const uploadedBeforePart = uploaded;
      if (debug) {
        console.log(`Uploading part ${partNumber}/${partCount}...`);
      }
      const part = await uploadPart(base, uploadId, partNumber, chunk, (partLoaded, partTotal) => {
        progress.update(uploadedBeforePart + partLoaded, encryptedBytes.byteLength);
        if (debug && partTotal > 0) {
          // no-op branch keeps partTotal used for lint friendliness in strict environments
        }
      });
      parts.push(part);
      uploaded += chunk.byteLength;
      progress.update(uploaded, encryptedBytes.byteLength);
    }
    progress.done();

    return postJson(`${base}/api/upload/complete`, {
      uploadId,
      size: encryptedBytes.byteLength,
      parts,
    });
  } catch (err) {
    progress.done();
    try {
      await fetch(`${base}/api/upload/abort`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ uploadId }),
      });
    } catch {
      // Ignore abort cleanup errors.
    }
    throw err;
  }
};

const runGet = async ({ target, base, outDir, pim, debug = false }) => {
  const debugLog = (...args) => {
    if (debug) {
      console.log(...args);
    }
  };

  const resolved = await resolveFileId(base, target);
  debugLog(`Resolved file: ${resolved.id} (${resolved.source === 'code' ? 'from access code' : 'from file id'})`);

  const password = await askPassword();
  debugLog('Checking password against encrypted header...');

  const headerBytes = await getHeaderProbe(base, resolved.id);
  const verified = await verifyHeaderPassword(headerBytes, password, pim);
  const outputName = sanitizeFileName(verified.originalName);
  debugLog('Password valid. Downloading encrypted file...');

  const encrypted = await getEncryptedPayload(base, resolved.id);
  debugLog('Decrypting...');

  const decrypted = await decryptPayload(encrypted, password, pim);
  const outputPath = await uniqueOutputPath(outDir, sanitizeFileName(decrypted.originalName || outputName));
  await writeFile(outputPath, decrypted.plaintext);

  console.log(`Saved: ${outputPath}`);
};

const runPut = async ({ target, base, pim, storage = STORAGE_R2, debug = false }) => {
  const debugLog = (...args) => {
    if (debug) {
      console.log(...args);
    }
  };

  const filePath = path.resolve(target);
  const fileName = path.basename(filePath);
  const info = await stat(filePath);
  if (!info.isFile()) {
    throw new Error('Provided path is not a file.');
  }
  if (!Number.isFinite(info.size) || info.size <= 0) {
    throw new Error('File is empty.');
  }

  debugLog(`File: ${filePath} (${info.size} bytes)`);
  const password = await askPassword('Password: ');
  const confirmPassword = await askPassword('Confirm password: ');
  if (password !== confirmPassword) {
    throw new Error('Passwords do not match.');
  }

  debugLog('Reading file...');
  const fileBuffer = await readFile(filePath);

  debugLog('Encrypting locally...');
  const encrypted = await encryptPayload(new Uint8Array(fileBuffer), password, pim, fileName);
  debugLog(`Encrypted (${encrypted.envelopeBytes.byteLength} bytes).`);
  debugLog(`Argon2id profile: time=${encrypted.argonParams.time}, mem=${Math.round(encrypted.argonParams.mem / 1024)}MB, parallelism=${encrypted.argonParams.parallelism}, PIM=${pim}`);

  debugLog('Starting multipart upload...');
  const payload = await uploadEncryptedMultipart(base, encrypted.envelopeBytes, storage, debug);

  console.log(`Access code: *** ${payload.accessCode || 'N/A'} ***`);
  console.log(`Download URL: ${payload.downloadUrl}`);
  console.log(`Delete URL: ${payload.deleteUrl}`);
  console.log(`Expires at: ${payload.expiresAt}`);
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printUsage();
    return;
  }

  if (args.command === 'get') {
    await runGet(args);
    return;
  }

  if (args.command === 'put') {
    await runPut(args);
    return;
  }

  fail('Unsupported command.');
};

main().catch((err) => {
  const message = err && err.message ? err.message : String(err);
  console.error(`Error: ${message}`);
  if (err && err.stack) {
    console.error(err.stack);
  }
  process.exit(1);
});
