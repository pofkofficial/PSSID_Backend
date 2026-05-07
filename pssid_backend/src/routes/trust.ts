// src/routes/trust.ts
// Trust score — social behaviour layer only.
// No floor (can go negative). No ceiling.
// Moves like Snap score but bidirectional.

import { FastifyInstance } from 'fastify';
import { z }              from 'zod';
import { db }             from '../db/client';

// ── Event definitions ─────────────────────────────────────────────────────────

export const TRUST_EVENTS: Record<string, {
  delta:       number;
  description: string;
  reportable:  boolean;  // true = platforms can report, false = system only
  dailyCap:    number | null; // max times per platform per day (null = unlimited)
}> = {
  // System events
  biometric_verified: {
    delta: 50, description: 'Biometric enrollment confirmed',
    reportable: false, dailyCap: null,
  },
  account_age_milestone: {
    delta: 5, description: 'Account active for another 30 days',
    reportable: false, dailyCap: null,
  },

  // Social — positive (platforms report)
  daily_active: {
    delta: 1, description: 'Active on platform today',
    reportable: true, dailyCap: 1,
  },
  content_created: {
    delta: 2, description: 'Created content on platform',
    reportable: true, dailyCap: 5,
  },
  vouch_received_verified: {
    delta: 10, description: 'Vouched by a verified PSSID user',
    reportable: true, dailyCap: null,
  },
  vouch_received_unverified: {
    delta: 3, description: 'Vouched by an unverified PSSID user',
    reportable: true, dailyCap: null,
  },
  vouch_given: {
    delta: 1, description: 'Vouched for another user',
    reportable: true, dailyCap: 5,
  },

  // Social — negative (platforms report)
  complaint_received: {
    delta: -20, description: 'Complaint filed against this user',
    reportable: true, dailyCap: null,
  },
  account_flagged: {
    delta: -30, description: 'Account flagged by platform',
    reportable: true, dailyCap: null,
  },

  // System-only negative (after internal review)
  complaint_upheld: {
    delta: -50, description: 'Complaint upheld after review',
    reportable: false, dailyCap: null,
  },
  spam_confirmed: {
    delta: -40, description: 'Spam or abuse confirmed',
    reportable: false, dailyCap: null,
  },
};

const PLATFORM_REPORTABLE = Object.entries(TRUST_EVENTS)
  .filter(([, v]) => v.reportable)
  .map(([k]) => k);

// ── API key middleware ─────────────────────────────────────────────────────────

async function requireApiKey(req: any, reply: any) {
  const apiKey = (req.headers['authorization'] ?? '').replace('Bearer ', '').trim();
  if (!apiKey) return reply.status(401).send({ error: 'Missing API key' });

  const client = await db.queryOne(
    'SELECT id, name, permissions, active FROM api_clients WHERE api_key = $1',
    [apiKey]
  );
  if (!client?.active) return reply.status(401).send({ error: 'Invalid API key' });

  req.apiClient = client;
}

// ── Daily cap check ───────────────────────────────────────────────────────────

async function withinDailyCap(
  userDid:   string,
  platform:  string,
  eventType: string,
  cap:       number,
): Promise<boolean> {
  const result = await db.queryOne(
    `SELECT COUNT(*) as cnt FROM trust_events
     WHERE user_did   = $1
       AND platform   = $2
       AND event_type = $3
       AND created_at > NOW() - INTERVAL '24 hours'`,
    [userDid, platform, eventType]
  );
  return Number(result.cnt) < cap;
}

// ── Routes ────────────────────────────────────────────────────────────────────

export async function trustRoutes(app: FastifyInstance) {

  // GET /trust/:did
  // Returns trust score. Requires opt-in.
  app.get('/trust/:did', { preHandler: requireApiKey }, async (req: any, reply) => {
    const { did } = req.params as { did: string };

    if (!req.apiClient.permissions.includes('read_trust')) {
      return reply.status(403).send({ error: 'Insufficient permissions' });
    }

    const user = await db.queryOne(
      'SELECT did, opted_in FROM users WHERE did = $1', [did]
    );
    if (!user) return reply.status(404).send({ error: 'DID not found' });

    if (!user.opted_in) {
      return reply.status(403).send({
        error:   'not_opted_in',
        message: 'User has not opted in to sharing their trust score.',
        hint:    'Ask the user to enable trust sharing in their PSSID wallet.',
      });
    }

    const trust = await db.queryOne(
      'SELECT score, total_gained, total_lost, updated_at FROM trust_score WHERE user_did = $1',
      [did]
    );

    // 30-day activity summary
    const activity = await db.query(
      `SELECT event_type, COUNT(*) as count, SUM(delta) as total
       FROM trust_events
       WHERE user_did = $1 AND created_at > NOW() - INTERVAL '30 days'
       GROUP BY event_type`,
      [did]
    );

    const actMap: Record<string, number> = {};
    for (const r of activity.rows) actMap[r.event_type] = Number(r.total);

    return reply.send({
      did,
      score:       Number(trust.score),  // can be negative
      totalGained: Number(trust.total_gained),
      totalLost:   Number(trust.total_lost),
      lastUpdated: trust.updated_at,

      last30Days: {
        daysActive:      actMap['daily_active']                 ?? 0,
        contentCreated:  actMap['content_created']              ?? 0,
        vouchesReceived: (actMap['vouch_received_verified']     ?? 0) +
                         (actMap['vouch_received_unverified']   ?? 0),
        vouchesGiven:     actMap['vouch_given']                 ?? 0,
        complaints:       actMap['complaint_received']          ?? 0,
      },

      issuedAt:    new Date().toISOString(),
      requestedBy: req.apiClient.name,
    });
  });


  // POST /trust/event
  // Platform reports a social activity event.
  app.post('/trust/event', { preHandler: requireApiKey }, async (req: any, reply) => {
    const body = z.object({
      userDid:   z.string().startsWith('did:key:'),
      eventType: z.string(),
      sourceDid: z.string().optional(),
      note:      z.string().max(200).optional(),
    }).safeParse(req.body);

    if (!body.success) {
      return reply.status(400).send({ error: 'invalid_request', details: body.error.flatten() });
    }

    const { userDid, eventType, sourceDid, note } = body.data;
    const client = req.apiClient;

    if (!client.permissions.includes('report_event')) {
      return reply.status(403).send({ error: 'This API key cannot report events' });
    }

    if (!PLATFORM_REPORTABLE.includes(eventType)) {
      return reply.status(400).send({
        error:   'event_not_allowed',
        allowed: PLATFORM_REPORTABLE,
      });
    }

    const eventConfig = TRUST_EVENTS[eventType];

    const user = await db.queryOne(
      'SELECT did, opted_in FROM users WHERE did = $1', [userDid]
    );
    if (!user) return reply.status(404).send({ error: 'User DID not found' });
    if (!user.opted_in) {
      return reply.status(403).send({ error: 'User has not opted in to trust score tracking' });
    }

    // Check daily cap if applicable
    if (eventConfig.dailyCap !== null) {
      const ok = await withinDailyCap(
        userDid, client.name, eventType, eventConfig.dailyCap
      );
      if (!ok) {
        return reply.status(429).send({
          error:   'daily_cap_reached',
          message: `Daily cap of ${eventConfig.dailyCap} for '${eventType}' from this platform reached.`,
        });
      }
    }

    const result = await db.queryOne(
      'SELECT apply_trust_event($1, $2, $3, $4, $5, $6) AS new_score',
      [userDid, eventType, eventConfig.delta, sourceDid ?? null, client.name, note ?? null]
    );

    return reply.send({
      applied:     true,
      eventType,
      description: eventConfig.description,
      delta:       eventConfig.delta,
      newScore:    Number(result.new_score),  // returned score may be negative
      platform:    client.name,
    });
  });


  // GET /trust/events/types
  // Lists all reportable event types. Useful for platform integration docs.
  app.get('/trust/events/types', { preHandler: requireApiKey }, async (_req, reply) => {
    return reply.send({
      reportable: PLATFORM_REPORTABLE.map(key => ({
        eventType:   key,
        delta:       TRUST_EVENTS[key].delta,
        description: TRUST_EVENTS[key].description,
        dailyCap:    TRUST_EVENTS[key].dailyCap,
      })),
    });
  });


  // GET /trust/:did/history
  // Returns event history. Platforms see only their own events.
  app.get('/trust/:did/history', { preHandler: requireApiKey }, async (req: any, reply) => {
    const { did }  = req.params as { did: string };
    const isSystem = req.apiClient.name === 'pssid_system';

    const events = await db.query(
      `SELECT event_type, delta, platform, source_did, note, created_at
       FROM trust_events
       WHERE user_did = $1
         AND ($2 OR platform = $3)
       ORDER BY created_at DESC
       LIMIT 100`,
      [did, isSystem, req.apiClient.name]
    );

    return reply.send({ did, events: events.rows });
  });


  // POST /trust/system/event
  // System-only events — complaint upheld, spam confirmed, age milestones.
  // Protected by SYSTEM_SECRET — not an API key.
  app.post('/trust/system/event', async (req, reply) => {
    if (req.headers['x-system-secret'] !== process.env.SYSTEM_SECRET) {
      return reply.status(401).send({ error: 'Unauthorized' });
    }

    const body = z.object({
      userDid:   z.string().startsWith('did:key:'),
      eventType: z.string(),
      note:      z.string().optional(),
    }).safeParse(req.body);

    if (!body.success) {
      return reply.status(400).send({ error: 'invalid_request' });
    }

    const { userDid, eventType, note } = body.data;
    const eventConfig = TRUST_EVENTS[eventType];

    if (!eventConfig) {
      return reply.status(400).send({
        error:   'unknown_event',
        allowed: Object.keys(TRUST_EVENTS),
      });
    }

    const result = await db.queryOne(
      'SELECT apply_trust_event($1, $2, $3, NULL, $4, $5) AS new_score',
      [userDid, eventType, eventConfig.delta, 'pssid_system', note ?? null]
    );

    return reply.send({
      applied:  true,
      eventType,
      delta:    eventConfig.delta,
      newScore: Number(result.new_score),
    });
  });
}