// src/routes/public.ts
// What social platforms call.
// Verification and trust score returned as clearly separate objects.

import { FastifyInstance } from 'fastify';
import { db }             from '../db/client';

async function getClient(apiKey: string) {
  return db.queryOne(
    'SELECT name, permissions, active FROM api_clients WHERE api_key = $1',
    [apiKey]
  );
}

async function requireKey(req: any, reply: any) {
  const apiKey = (req.headers['authorization'] ?? '').replace('Bearer ', '').trim();
  if (!apiKey) return reply.status(401).send({ error: 'Missing API key' });
  const client = await getClient(apiKey);
  if (!client?.active) return reply.status(401).send({ error: 'Invalid API key' });
  req.apiClient = client;
}

export async function publicRoutes(app: FastifyInstance) {

  // GET /v1/health
  app.get('/v1/health', async (_req, reply) => {
    return reply.send({
      status:    'ok',
      service:   'PSSID Identity & Trust API',
      version:   '1.0.0',
      timestamp: new Date().toISOString(),
    });
  });


  // ── GET /v1/profile/:did ─────────────────────────────────────────────────────
  // Full profile: verification + trust score.
  // The two systems are clearly separated in the response.
  //
  // Verification: always returned — it's public identity state, no opt-in needed.
  // Trust score:  only returned if user has opted in, otherwise returns a clear message.

  app.get('/v1/profile/:did', { preHandler: requireKey }, async (req: any, reply) => {
    const { did } = req.params as { did: string };
    const client  = req.apiClient;

    const user = await db.queryOne(
      'SELECT did, opted_in, created_at FROM users WHERE did = $1', [did]
    );
    if (!user) return reply.status(404).send({ error: 'DID not found' });

    // ── Verification (always available) ──────────────────────────────────────
    let verification = null;
    if (client.permissions.includes('read_verification')) {
      const v = await db.queryOne(
        'SELECT verified, verified_at FROM verification WHERE user_did = $1', [did]
      );
      verification = {
        verified:   v?.verified ?? false,
        verifiedAt: v?.verified_at ?? null,
        label:      v?.verified ? 'Biometrically Verified' : 'Unverified',
        badge:      v?.verified ? '✅' : '⬜',
      };
    }

    // ── Trust score (requires opt-in) ────────────────────────────────────────
    let trust = null;
    if (client.permissions.includes('read_trust')) {
      if (!user.opted_in) {
        trust = {
          available: false,
          reason:    'User has not opted in to trust score sharing.',
          hint:      'The user can enable this in their PSSID wallet under Settings.',
        };
      } else {
        const t = await db.queryOne(
          'SELECT score, total_gained, total_lost FROM trust_score WHERE user_did = $1',
          [did]
        );

        // 30-day summary
        const activity = await db.query(
          `SELECT event_type, COUNT(*) as count, SUM(delta) as total
           FROM trust_events
           WHERE user_did = $1 AND created_at > NOW() - INTERVAL '30 days'
           GROUP BY event_type`,
          [did]
        );

        const a: Record<string, number> = {};
        for (const r of activity.rows) a[r.event_type] = Number(r.total);

        trust = {
          available:   true,
          score:       Number(t.score),       // can be negative
          totalGained: Number(t.total_gained),
          totalLost:   Number(t.total_lost),
          last30Days: {
            daysActive:      a['daily_active']                ?? 0,
            contentCreated:  a['content_created']             ?? 0,
            vouchesReceived: (a['vouch_received_verified']    ?? 0) +
                             (a['vouch_received_unverified']  ?? 0),
            complaints:       a['complaint_received']         ?? 0,
          },
        };
      }
    }

    return reply.send({
      did,
      memberSince:  user.created_at,

      // ── VERIFICATION ── identity layer
      verification,

      // ── TRUST SCORE ── behaviour layer
      trust,

      meta: {
        issuedAt:    new Date().toISOString(),
        issuedBy:    'PSSID',
        requestedBy: client.name,
      },
    });
  });


  // ── GET /v1/verification/:did ────────────────────────────────────────────────
  // Verification only — fastest endpoint.
  // No opt-in required.

  app.get('/v1/verification/:did', { preHandler: requireKey }, async (req: any, reply) => {
    if (!req.apiClient.permissions.includes('read_verification')) {
      return reply.status(403).send({ error: 'Insufficient permissions' });
    }

    const { did } = req.params as { did: string };

    const result = await db.queryOne(
      `SELECT v.verified, v.verified_at, u.created_at
       FROM verification v JOIN users u ON u.did = v.user_did
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


  // ── GET /v1/trust/:did ───────────────────────────────────────────────────────
  // Trust score only. Requires opt-in.

  app.get('/v1/trust/:did', { preHandler: requireKey }, async (req: any, reply) => {
    if (!req.apiClient.permissions.includes('read_trust')) {
      return reply.status(403).send({ error: 'Insufficient permissions' });
    }

    const { did } = req.params as { did: string };

    const user = await db.queryOne(
      'SELECT did, opted_in FROM users WHERE did = $1', [did]
    );
    if (!user) return reply.status(404).send({ error: 'DID not found' });

    if (!user.opted_in) {
      return reply.status(403).send({
        error:   'not_opted_in',
        message: 'User has not opted in to trust score sharing.',
        hint:    'The user can enable this in their PSSID wallet under Settings.',
      });
    }

    const trust = await db.queryOne(
      'SELECT score, total_gained, total_lost, updated_at FROM trust_score WHERE user_did = $1',
      [did]
    );

    return reply.send({
      did,
      score:       Number(trust.score),   // can be negative
      totalGained: Number(trust.total_gained),
      totalLost:   Number(trust.total_lost),
      lastUpdated: trust.updated_at,
      issuedAt:    new Date().toISOString(),
      requestedBy: req.apiClient.name,
    });
  });


  // ── GET /v1/exists/:did ──────────────────────────────────────────────────────
  // Is this DID registered? Returns nothing sensitive.

  app.get('/v1/exists/:did', { preHandler: requireKey }, async (req: any, reply) => {
    const { did } = req.params as { did: string };

    const user = await db.queryOne(
      'SELECT did, created_at FROM users WHERE did = $1', [did]
    );

    return reply.send({
      did,
      registered:  !!user,
      memberSince: user?.created_at ?? null,
    });
  });
}