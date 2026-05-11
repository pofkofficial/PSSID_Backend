// src/routes/recovery.ts
// Handles encrypted seed storage and retrieval for cross-device recovery.
// The backend never sees the plain seed or PIN — only the encrypted result.
// Phone numbers are hashed before they reach us.

import { FastifyInstance } from 'fastify';
import { z }              from 'zod';
import { db }             from '../db/client.js';
import { verifyChallenge } from '../crypto/verify.js';

// ── Schemas ───────────────────────────────────────────────────────────────────

const StoreBody = z.object({
  did:           z.string().startsWith('did:key:'),
  phoneHash:     z.string().length(64),    // SHA-256 hex
  encryptedSeed: z.string().length(64),    // XOR-encrypted seed hex
  nonce:         z.string(),
  signatureHex:  z.string().length(128),
});

const RetrieveBody = z.object({
  phoneHash:     z.string().length(64),
  encryptedSeed: z.string().length(64),   // we return this to the app
});

// ── Routes ────────────────────────────────────────────────────────────────────

export async function recoveryRoutes(app: FastifyInstance) {

  // POST /recovery/store
  // Called once after enrollment.
  // Stores the encrypted seed linked to the phone hash.
  // Requires a signed challenge to prove DID ownership.
  app.post('/recovery/store', async (req, reply) => {
    const body = StoreBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({
        error:   'invalid_request',
        details: body.error.flatten(),
      });
    }

    const { did, phoneHash, encryptedSeed, nonce, signatureHex } = body.data;

    // Validate challenge
    const challenge = await db.queryOne(
      `SELECT id FROM auth_challenges
       WHERE nonce = $1 AND did = $2
         AND used = false AND expires_at > NOW()`,
      [nonce, did]
    );

    if (!challenge) {
      return reply.status(401).send({ error: 'Invalid or expired challenge' });
    }

    // Verify signature
    const user = await db.queryOne(
      'SELECT public_key_hex FROM users WHERE did = $1', [did]
    );
    if (!user) return reply.status(404).send({ error: 'DID not found' });

    const valid = await verifyChallenge(
      user.public_key_hex, nonce, did, signatureHex
    );
    if (!valid) return reply.status(401).send({ error: 'Invalid signature' });

    // Mark challenge used
    await db.query(
      'UPDATE auth_challenges SET used = true WHERE id = $1', [challenge.id]
    );

    // Check if phone hash already exists for a DIFFERENT did
    const existingPhone = await db.queryOne(
      'SELECT did FROM encrypted_seeds WHERE phone_hash = $1', [phoneHash]
    );

    if (existingPhone && existingPhone.did !== did) {
      return reply.status(409).send({
        error:   'phone_already_registered',
        message: 'This phone number is already linked to a different identity.',
      });
    }

    // Store or update encrypted seed
    await db.query(
      `INSERT INTO encrypted_seeds (phone_hash, encrypted_seed, did)
       VALUES ($1, $2, $3)
       ON CONFLICT (did) DO UPDATE SET
         phone_hash     = EXCLUDED.phone_hash,
         encrypted_seed = EXCLUDED.encrypted_seed,
         updated_at     = NOW()`,
      [phoneHash, encryptedSeed, did]
    );

    return reply.send({ stored: true });
  });


  // POST /recovery/retrieve
  // Called on reinstall when user enters phone + PIN.
  // Returns the encrypted seed + full identity if phone hash matches.
  // The app decrypts the seed locally using the PIN — we never see the PIN.
  app.post('/recovery/retrieve', async (req, reply) => {
    const body = RetrieveBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'invalid_request' });
    }

    const { phoneHash } = body.data;

    // Look up by phone hash
    const record = await db.queryOne(
      'SELECT did, encrypted_seed FROM encrypted_seeds WHERE phone_hash = $1',
      [phoneHash]
    );

    if (!record) {
      return reply.status(404).send({
        error:   'not_found',
        message: 'No PSSID account found for this phone number.',
      });
    }

    // Fetch verification + trust score
    const verification = await db.queryOne(
      'SELECT verified, verified_at FROM verification WHERE user_did = $1',
      [record.did]
    );

    const trust = await db.queryOne(
      'SELECT score, total_gained, total_lost FROM trust_score WHERE user_did = $1',
      [record.did]
    );

    // Return the encrypted seed — app decrypts it with PIN locally
    // If the PIN is wrong, decryption produces garbage → keypair won't match
    // → signin will fail → wrong PIN is naturally rejected
    return reply.send({
      did:           record.did,
      encryptedSeed: record.encrypted_seed,
      verification: {
        verified:   verification?.verified ?? false,
        verifiedAt: verification?.verified_at ?? null,
        badge:      verification?.verified ? '✅' : '⬜',
      },
      trust: {
        score:       Number(trust?.score ?? 0),
        totalGained: Number(trust?.total_gained ?? 0),
        totalLost:   Number(trust?.total_lost ?? 0),
      },
    });
  });


  // POST /recovery/check-phone
  // Lightweight check — is this phone number already registered?
  // Used during enrollment to warn user before they set their PIN.
  app.post('/recovery/check-phone', async (req, reply) => {
    const body = z.object({
      phoneHash: z.string().length(64),
    }).safeParse(req.body);

    if (!body.success) {
      return reply.status(400).send({ error: 'invalid_request' });
    }

    const record = await db.queryOne(
      'SELECT did FROM encrypted_seeds WHERE phone_hash = $1',
      [body.data.phoneHash]
    );

    return reply.send({ registered: !!record });
  });
}