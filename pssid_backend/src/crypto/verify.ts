// src/crypto/verify.ts
import * as ed from '@noble/ed25519';
// noble/ed25519 v2 requires you to set the hash function


// Verifies that `signature` over `message` was made by `publicKeyHex`.
// Both signature and publicKey are hex strings (as produced by Rust).
export async function verifySignature(
  publicKeyHex: string,
  message:      string,
  signatureHex: string,
): Promise<boolean> {
  try {
    const pubKey = hexToBytes(publicKeyHex);
    const sig    = hexToBytes(signatureHex);
    const msg    = new TextEncoder().encode(message);
    return await ed.verifyAsync(sig, msg, pubKey);
  } catch {
    return false;
  }
}

// Verifies a signed challenge nonce.
// The app signs: `pssid-challenge:${nonce}:${did}`
export async function verifyChallenge(
  publicKeyHex: string,
  nonce:        string,
  did:          string,
  signatureHex: string,
): Promise<boolean> {
  const message = `pssid-challenge:${nonce}:${did}`;
  return verifySignature(publicKeyHex, message, signatureHex);
}

// Verifies an enrollment payload.
// The app signs: `pssid-enroll:${did}:${publicKeyHex}`
export async function verifyEnrollment(
  publicKeyHex: string,
  did:          string,
  signatureHex: string,
): Promise<boolean> {
  const message = `pssid-enroll:${did}:${publicKeyHex}`;
  return verifySignature(publicKeyHex, message, signatureHex);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}