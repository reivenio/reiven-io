export const FORMAT_VERSION = 6;
export const CHUNK_SIZE = 8 * 1024 * 1024;
export const MAX_PLAINTEXT_SIZE = 512 * 1024 * 1024;
export const HEADER_FIXED_SIZE = 1196;
const PREFIX_SIZE = 1148;
const TAG_SIZE = 16;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const magic = encoder.encode('ESHARE1');
export const ENCRYPTION_PROFILES = Object.freeze({
  standard: Object.freeze({ time: 4, mem: 65536, parallelism: 1 }),
  paranoid: Object.freeze({ time: 6, mem: 131072, parallelism: 1 }),
});

export const concatBytes = (...arrays) => {
  const output = new Uint8Array(arrays.reduce((total, bytes) => total + bytes.length, 0));
  let offset = 0;
  for (const bytes of arrays) {
    output.set(bytes, offset);
    offset += bytes.length;
  }
  return output;
};

export const readBoundedResponse = async (response, limit) => {
  if (!response.body) throw new Error('Response body unavailable.');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return concatBytes(...chunks);
      total += value.length;
      if (total > limit) throw new Error('Encrypted response exceeds its size limit.');
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => {}); }
};

const uint64 = (value) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
};

const validateSize = (size) => {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_PLAINTEXT_SIZE) {
    throw new Error('Invalid or oversized encrypted file.');
  }
};

export const parseHeader = (input) => {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 8 || !magic.every((value, index) => bytes[index] === value)) throw new Error('Unsupported encrypted file.');
  if (bytes[7] !== FORMAT_VERSION) throw new Error('Legacy or unsupported encryption format. Ask the sender to create a new share.');
  if (bytes.length < HEADER_FIXED_SIZE) throw new Error('Incomplete encrypted header.');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const argonParams = { time: bytes[8], parallelism: bytes[9], mem: view.getUint32(10) };
  if (!Object.values(ENCRYPTION_PROFILES).some(profile => Object.keys(profile).every(key => profile[key] === argonParams[key]))) throw new Error('Unsupported encryption profile.');
  if (view.getUint32(14) !== CHUNK_SIZE) throw new Error('Invalid chunk size.');
  const plainSize = Number(view.getBigUint64(18));
  validateSize(plainSize);
  const metadataSize = view.getUint16(26);
  if (metadataSize < TAG_SIZE + 1 || metadataSize > 2048 + TAG_SIZE) throw new Error('Invalid metadata size.');
  const headerSize = HEADER_FIXED_SIZE + metadataSize;
  if (bytes.length < headerSize) throw new Error('Incomplete encrypted header.');
  const chunkCount = Math.max(1, Math.ceil(plainSize / CHUNK_SIZE));
  return {
    version: FORMAT_VERSION, argonParams, plainSize, chunkCount, chunkPlainSize: CHUNK_SIZE,
    headerSize, encryptedSize: headerSize + plainSize + chunkCount * TAG_SIZE,
    header: bytes.slice(0, headerSize), prefix: bytes.slice(0, PREFIX_SIZE),
    salt: bytes.slice(28, 44), noncePrefix: bytes.slice(44, 48), wrapIv: bytes.slice(48, 60),
    pqCiphertext: bytes.slice(60, PREFIX_SIZE), wrappedDek: bytes.slice(PREFIX_SIZE, HEADER_FIXED_SIZE),
    metadata: bytes.slice(HEADER_FIXED_SIZE, headerSize),
  };
};

export const createCodec = ({ crypto, argon2id, mlKem }) => {
  const subtle = crypto.subtle;
  const random = (size) => crypto.getRandomValues(new Uint8Array(size));
  const aad = (role, ...bytes) => concatBytes(encoder.encode(`REIVEN_V6_${role}\0`), ...bytes);
  const nonce = (prefix, index) => concatBytes(prefix, uint64(index));
  const importDek = (bytes) => subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const derivePair = async (password, pim, salt, params) => {
    if (typeof password !== 'string' || !password || password.length > 4096 || !Number.isSafeInteger(pim) || pim < 1) throw new Error('Invalid password or PIM.');
    const kek = await argon2id(`${password}\0${pim}`, salt, params);
    const seedInput = aad('MLKEM_SEED', kek);
    let seed;
    try {
      seed = new Uint8Array(await subtle.digest('SHA-512', seedInput));
      return mlKem.keygen(seed);
    } finally {
      kek.fill(0);
      seedInput.fill(0);
      seed?.fill(0);
    }
  };
  const wrappingKey = async (secret, salt) => {
    const material = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: aad('WRAP_KEY') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  };
  const destroy = (session) => {
    session.closed = true;
    session.fileKey = null;
  };
  const finish = (session) => {
    if (session.closed || session.busy || session.nextIndex !== session.chunkCount) {
      destroy(session);
      throw new Error('Incomplete encrypted file or invalid session.');
    }
    destroy(session);
  };
  const createSession = async (parsed, fileKey, originalName) => ({
    ...parsed, fileKey, originalName, nextIndex: 0, busy: false, closed: false,
    headerHash: new Uint8Array(await subtle.digest('SHA-256', parsed.header)),
  });
  const createEncryption = async ({ password, pim = 100, encryptionType = 'standard', originalName = 'download.bin', plainSize }) => {
    validateSize(plainSize);
    const argonParams = ENCRYPTION_PROFILES[encryptionType];
    if (!argonParams) throw new Error('Unsupported encryption profile.');
    const name = String(originalName).slice(0, 255);
    if (!name.trim()) throw new Error('Invalid filename.');
    const metadata = encoder.encode(JSON.stringify({ name }));
    if (metadata.length > 2048) throw new Error('Filename too long.');
    const prefix = new Uint8Array(PREFIX_SIZE);
    const view = new DataView(prefix.buffer);
    prefix.set(magic);
    prefix[7] = FORMAT_VERSION;
    prefix[8] = argonParams.time;
    prefix[9] = argonParams.parallelism;
    view.setUint32(10, argonParams.mem);
    view.setUint32(14, CHUNK_SIZE);
    view.setBigUint64(18, BigInt(plainSize));
    view.setUint16(26, metadata.length + TAG_SIZE);
    prefix.set(random(16), 28);
    prefix.set(random(4), 44);
    prefix.set(random(12), 48);
    const salt = prefix.slice(28, 44);
    const pair = await derivePair(password, pim, salt, argonParams);
    const rawDek = random(32);
    let shared;
    try {
      shared = mlKem.encapsulate(pair.publicKey);
      prefix.set(shared.cipherText, 60);
      const fileKey = await importDek(rawDek);
      const wrapKey = await wrappingKey(shared.sharedSecret, salt);
      const wrapped = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: prefix.slice(48, 60), additionalData: aad('WRAP', prefix), tagLength: 128 }, wrapKey, rawDek));
      const encryptedMetadata = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce(prefix.slice(44, 48), 0), additionalData: aad('METADATA', prefix, wrapped), tagLength: 128 }, fileKey, metadata));
      return createSession(parseHeader(concatBytes(prefix, wrapped, encryptedMetadata)), fileKey, name);
    } finally {
      rawDek.fill(0);
      pair.secretKey.fill(0);
      shared?.sharedSecret.fill(0);
      metadata.fill(0);
    }
  };
  const createDecryption = async (input, password, pim = 100) => {
    const parsed = parseHeader(input);
    const pair = await derivePair(password, pim, parsed.salt, parsed.argonParams);
    let secret;
    let rawDek;
    let metadata;
    try {
      secret = mlKem.decapsulate(parsed.pqCiphertext, pair.secretKey);
      const wrapKey = await wrappingKey(secret, parsed.salt);
      rawDek = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: parsed.wrapIv, additionalData: aad('WRAP', parsed.prefix), tagLength: 128 }, wrapKey, parsed.wrappedDek));
      if (rawDek.length !== 32) throw new Error('Invalid key length.');
      const fileKey = await importDek(rawDek);
      metadata = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce(parsed.noncePrefix, 0), additionalData: aad('METADATA', parsed.prefix, parsed.wrappedDek), tagLength: 128 }, fileKey, parsed.metadata));
      const decoded = JSON.parse(decoder.decode(metadata));
      if (typeof decoded.name !== 'string' || !decoded.name.trim() || decoded.name.length > 255 || Object.keys(decoded).length !== 1) throw new Error('Invalid metadata.');
      return await createSession(parsed, fileKey, decoded.name);
    } catch {
      throw new Error('Authentication failed. Incorrect password/PIM or altered file.');
    } finally {
      pair.secretKey.fill(0);
      secret?.fill(0);
      rawDek?.fill(0);
      metadata?.fill(0);
    }
  };
  const transformChunk = async (session, index, input, decrypting) => {
    if (session.closed || session.busy || !Number.isSafeInteger(index) || index !== session.nextIndex || index >= session.chunkCount) throw new Error('Invalid or repeated chunk index.');
    const size = Math.min(CHUNK_SIZE, session.plainSize - index * CHUNK_SIZE);
    if (!(input instanceof Uint8Array) || input.length !== size + (decrypting ? TAG_SIZE : 0)) {
      destroy(session);
      throw new Error('Incorrect encrypted file length.');
    }
    session.busy = true;
    const bytes = input.slice();
    try {
      const result = new Uint8Array(await subtle[decrypting ? 'decrypt' : 'encrypt']({
        name: 'AES-GCM', iv: nonce(session.noncePrefix, index + 1), tagLength: 128,
        additionalData: aad('CHUNK', session.headerHash, uint64(index), uint64(size), new Uint8Array([index === session.chunkCount - 1 ? 1 : 0])),
      }, session.fileKey, bytes));
      session.nextIndex += 1;
      return result;
    } catch {
      destroy(session);
      throw new Error('Chunk authentication failed.');
    } finally {
      bytes.fill(0);
      session.busy = false;
    }
  };
  const encrypt = async (bytes, options) => {
    const session = await createEncryption({ ...options, plainSize: bytes.length });
    const chunks = [session.header];
    try {
      for (let index = 0; index < session.chunkCount; index += 1) chunks.push(await transformChunk(session, index, bytes.subarray(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE), false));
      finish(session);
      return { envelopeBytes: concatBytes(...chunks), argonParams: session.argonParams };
    } finally { destroy(session); }
  };
  const decrypt = async (bytes, password, pim = 100) => {
    const parsed = parseHeader(bytes);
    if (bytes.length !== parsed.encryptedSize) throw new Error('Incorrect encrypted file length.');
    const session = await createDecryption(bytes, password, pim);
    const output = new Uint8Array(session.plainSize);
    let offset = session.headerSize;
    try {
      for (let index = 0; index < session.chunkCount; index += 1) {
        const size = Math.min(CHUNK_SIZE, session.plainSize - index * CHUNK_SIZE) + TAG_SIZE;
        const chunk = await transformChunk(session, index, bytes.subarray(offset, offset + size), true);
        output.set(chunk, index * CHUNK_SIZE);
        chunk.fill(0);
        offset += size;
      }
      finish(session);
      return { plaintext: output, originalName: session.originalName, argonParams: session.argonParams };
    } catch (error) {
      output.fill(0);
      throw error;
    } finally { destroy(session); }
  };
  return {
    createEncryption, createDecryption, encrypt, decrypt, finish, destroy,
    encryptChunk: (session, index, bytes) => transformChunk(session, index, bytes, false),
    decryptChunk: (session, index, bytes) => transformChunk(session, index, bytes, true),
  };
};
