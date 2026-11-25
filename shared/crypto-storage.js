// shared/crypto-storage.js — AES-256-GCM encrypted local vault & passphrase backup helpers

const VAULT_KEY_STORAGE = 'pmVaultKey';

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function getOrCreateVaultKey() {
  const existing = await chrome.storage.local.get([VAULT_KEY_STORAGE]);
  const storedJwk = existing[VAULT_KEY_STORAGE];

  if (storedJwk && typeof storedJwk === 'object') {
    try {
      return await crypto.subtle.importKey(
        'jwk',
        storedJwk,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    } catch {
      // Regenerate below if corrupted
    }
  }

  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const jwk = await crypto.subtle.exportKey('jwk', key);
  await chrome.storage.local.set({ [VAULT_KEY_STORAGE]: jwk });
  return key;
}

export async function encryptStatePayload(data) {
  const key = await getOrCreateVaultKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  return {
    v: 1,
    alg: 'AES-256-GCM',
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(cipherBuf))
  };
}

export async function decryptStatePayload(envelope) {
  if (!envelope || typeof envelope !== 'object' || !envelope.iv || !envelope.ct) {
    return null;
  }
  const key = await getOrCreateVaultKey();
  const iv = base64ToBytes(envelope.iv);
  const ct = base64ToBytes(envelope.ct);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

async function derivePassphraseKey(passphrase, saltBytes) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 150000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptBackupWithPassphrase(data, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePassphraseKey(passphrase, salt);
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  return {
    format: 'proxyflow-encrypted-backup',
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: 150000,
    alg: 'AES-256-GCM',
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(cipherBuf))
  };
}

export async function decryptBackupWithPassphrase(envelope, passphrase) {
  if (!envelope?.salt || !envelope?.iv || !envelope?.ct) {
    throw new Error('Malformed encrypted backup file.');
  }
  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const key = await derivePassphraseKey(passphrase, salt);
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    base64ToBytes(envelope.ct)
  );
  return JSON.parse(new TextDecoder().decode(plainBuf));
}
