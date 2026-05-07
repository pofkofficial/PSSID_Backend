// src/routes/verification.ts
// Verification = biometric confirmation only.
// Binary: verified (true) or not (false).
// Permanent — once verified, always verified.

import { FastifyInstance } from 'fastify';
import { z }              from 'zod';
import crypto             from 'crypto';
import { db }             from '../db/client.js';
import { verifyEnrollment, verifyChallenge } from '../crypto/verify.js';

// ── Schemas ───────────────────────────────────────────────────────────────────

const EnrollBody = z.object({
  did:          z.string().startsWith('did:key:'),
  publicKeyHex: z.string().length(64),
  signatureHex: z.string().length(128),
  deviceHint:   z.string().max(50).optional(), // e.g. "android" or "ios"
});

const ChallengeBody = z.object({
  did: z.string().startsWith('did:key:'),
});

const SignedBody = z.object({
  did:          z.string().startsWith('did:key:'),
  nonce:        z.string(),
  signatureHex: z.string().length(128),
});

// ── Routes ────────────────────────────────────────────────────────────────────

export async function verificationRoutes(app: FastifyInstance) {

  // ── POST /verification/enroll ────────────────────────────────────────────────
  // Called once when the user creates their PSSID identity.
  // Biometric is confirmed on-device before this is called.
  // We receive the DID + public key + a signature proving key ownership.
  // Enrollment = verified. No separate verification step needed.

  app.post('/verification/enroll', async (req, reply) => {
    const body = EnrollBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({
        error:   'invalid_request',
        details: body.error.flatten(),
      });
    }

    const { did, publicKeyHex, signatureHex, deviceHint } = body.data;

    // Check for duplicate DID or public key
    const existing = await db.queryOne(
      'SELECT did, public_key_hex FROM users WHERE did = $1 OR public_key_hex = $2',
      [did, publicKeyHex]
    );

    if (existing) {
      // Same public key, different DID = attempt to create a second identity
      if (existing.public_key_hex === publicKeyHex && existing.did !== did) {
        return reply.status(409).send({
          error:   'duplicate_identity',
          message: 'A PSSID identity already exists for this biometric. One person, one DID.',
        });
      }
      return reply.status(409).send({
        error:   'already_enrolled',
        message: 'This identity is already registered. Sign in instead.',
      });
    }

    // Verify the enrollment signature
    // App must have signed: `pssid-enroll:${did}:${publicKeyHex}`
    const valid = await verifyEnrollment(publicKeyHex, did, signatureHex);
    if (!valid) {
      return reply.status(401).send({ error: 'Invalid enrollment signature' });
    }

    // Create user + verification + trust_score atomically
    // enroll_user() also applies the +50 biometric verification boost
    await db.query('SELECT enroll_user($1, $2)', [did, publicKeyHex]);

    // Store optional device hint on the verification record
    if (deviceHint) {
      await db.query(
        'UPDATE verification SET device_hint = $1 WHERE user_did = $2',
        [deviceHint, did]
      );
    }

    return reply.status(201).send({
      enrolled:   true,
      verified:   true,   // biometric enrollment = verified
      did,
      trustBoost: 50,
      message:    'Identity created and biometrically verified.',
    });
  });


  // ── POST /verification/challenge ─────────────────────────────────────────────
  // Get a nonce to sign. Call this before signin or optin.

  app.post('/verification/challenge', async (req, reply) => {
    const body = ChallengeBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'invalid_request' });
    }

    const { did } = body.data;

    const user = await db.queryOne(
      'SELECT did FROM users WHERE did = $1', [did]
    );

    if (!user) {
      return reply.status(404).send({
        error:   'not_found',
        message: 'DID not registered. Enroll first.',
      });
    }

    const nonce = crypto.randomBytes(32).toString('hex');
    await db.query(
      'INSERT INTO auth_challenges (did, nonce) VALUES ($1, $2)',
      [did, nonce]
    );

    return reply.send({ nonce, expiresIn: 120 });
  });


  // ── POST /verification/signin ────────────────────────────────────────────────
  // App signs the nonce with the private key.
  // Backend verifies → returns identity state + trust score.

  app.post('/verification/signin', async (req, reply) => {
    const body = SignedBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'invalid_request' });
    }

    const { did, nonce, signatureHex } = body.data;

    // Validate challenge — must be unused and not expired
    const challenge = await db.queryOne(
      `SELECT id, did FROM auth_challenges
       WHERE nonce = $1 AND used = false AND expires_at > NOW()`,
      [nonce]
    );

    if (!challenge || challenge.did !== did) {
      return reply.status(401).send({ error: 'Invalid or expired challenge' });
    }

    // Fetch user
    const user = await db.queryOne(
      'SELECT did, public_key_hex, opted_in FROM users WHERE did = $1', [did]
    );
    if (!user) return reply.status(404).send({ error: 'DID not found' });

    // Verify signature
    const valid = await verifyChallenge(
      user.public_key_hex, nonce, did, signatureHex
    );
    if (!valid) return reply.status(401).send({ error: 'Invalid signature' });

    // Mark challenge used — prevents replay attacks
    await db.query(
      'UPDATE auth_challenges SET used = true WHERE id = $1', [challenge.id]
    );
    await db.query(
      'UPDATE users SET last_seen = NOW() WHERE did = $1', [did]
    );

    // Fetch verification state
    const verification = await db.queryOne(
      'SELECT verified, verified_at FROM verification WHERE user_did = $1', [did]
    );

    // Fetch trust score
    const trust = await db.queryOne(
      'SELECT score, total_gained, total_lost FROM trust_score WHERE user_did = $1', [did]
    );

    return reply.send({
      authenticated: true,
      did:           user.did,
      optedIn:       user.opted_in,

      // Verification — binary
      verification: {
        verified:   verification.verified,
        verifiedAt: verification.verified_at,
        label:      verification.verified ? 'Biometrically Verified' : 'Unverified',
        badge:      verification.verified ? '✅' : '⬜',
      },

      // Trust score — continuous
      trust: {
        score:       Number(trust.score),
        totalGained: Number(trust.total_gained),
        totalLost:   Number(trust.total_lost),
      },
    });
  });


  // ── POST /verification/optin ─────────────────────────────────────────────────
  // User opts in to sharing trust score with platforms.
  // Requires a signed challenge to prove they own the DID.

  app.post('/verification/optin', async (req, reply) => {
    const body = SignedBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'invalid_request' });
    }

    const { did, nonce, signatureHex } = body.data;

    const challenge = await db.queryOne(
      `SELECT id FROM auth_challenges
       WHERE nonce = $1 AND did = $2
         AND used = false AND expires_at > NOW()`,
      [nonce, did]
    );
    if (!challenge) {
      return reply.status(401).send({ error: 'Invalid or expired challenge' });
    }

    const user = await db.queryOne(
      'SELECT public_key_hex FROM users WHERE did = $1', [did]
    );
    if (!user) return reply.status(404).send({ error: 'DID not found' });

    const valid = await verifyChallenge(
      user.public_key_hex, nonce, did, signatureHex
    );
    if (!valid) return reply.status(401).send({ error: 'Invalid signature' });

    await db.query(
      'UPDATE auth_challenges SET used = true WHERE id = $1', [challenge.id]
    );
    await db.query(
      'UPDATE users SET opted_in = true WHERE did = $1', [did]
    );
    await db.query(
      'INSERT INTO consent_log (user_did, opted_in) VALUES ($1, true)', [did]
    );

    return reply.send({ optedIn: true, did });
  });


  // ── GET /verification/:did ───────────────────────────────────────────────────
  // Returns verification status for a DID.
  // No opt-in required — verification is public identity state.
  // Requires platform API key.

  app.get('/verification/:did', async (req, reply) => {
    const apiKey = (req.headers['authorization'] ?? '').replace('Bearer ', '').trim();
    if (!apiKey) return reply.status(401).send({ error: 'Missing API key' });

    const client = await db.queryOne(
      'SELECT name, active, permissions FROM api_clients WHERE api_key = $1', [apiKey]
    );
    if (!client?.active || !client.permissions.includes('read_verification')) {
      return reply.status(401).send({ error: 'Invalid API key or insufficient permissions' });
    }

    const { did } = req.params as { did: string };

    const result = await db.queryOne(
      `SELECT v.verified, v.verified_at, u.created_at
       FROM verification v
       JOIN users u ON u.did = v.user_did
       WHERE v.user_did = $1`,
      [did]
    );

    if (!result) return reply.status(404).send({ error: 'DID not found' });

    return reply.send({
      did,
      verified:    result.verified,
      verifiedAt:  result.verified_at,
      label:       result.verified ? 'Biometrically Verified' : 'Unverified',
      badge:       result.verified ? '✅' : '⬜',
      memberSince: result.created_at,
      issuedAt:    new Date().toISOString(),
    });
  });
}