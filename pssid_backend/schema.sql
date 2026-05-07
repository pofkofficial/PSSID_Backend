-- =============================================================================
-- PSSID Backend Schema
-- Verification: biometric only (binary — verified or not)
-- Trust Score:  continuous, can go negative, no ceiling
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ─────────────────────────────────────────────────────────────────────
-- Core identity table. public_key_hex UNIQUE enforces
-- 1 fingerprint = 1 DID at the database level.

CREATE TABLE IF NOT EXISTS users (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  did            TEXT        NOT NULL UNIQUE,
  public_key_hex TEXT        NOT NULL UNIQUE,
  opted_in       BOOLEAN     NOT NULL DEFAULT false,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_did    ON users (did);
CREATE INDEX idx_users_pubkey ON users (public_key_hex);

-- ── Verification ──────────────────────────────────────────────────────────────
-- Binary. One row per user.
-- verified = false  →  registered but not biometrically verified
-- verified = true   →  biometric confirmed through PSSID enrollment
-- Once true, never goes back to false.

CREATE TABLE IF NOT EXISTS verification (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_did      TEXT        NOT NULL UNIQUE REFERENCES users(did) ON DELETE CASCADE,
  verified      BOOLEAN     NOT NULL DEFAULT false,
  verified_at   TIMESTAMPTZ,           -- when biometric was confirmed
  device_hint   TEXT                   -- anonymised device type hint (optional)
);

CREATE INDEX idx_verification_did      ON verification (user_did);
CREATE INDEX idx_verification_verified ON verification (verified);

-- ── Trust Score ───────────────────────────────────────────────────────────────
-- Running total. No floor. No ceiling.
-- Driven by social platform activity.
-- Note: score is BIGINT with NO check constraint — allows negative values.

CREATE TABLE IF NOT EXISTS trust_score (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_did     TEXT        NOT NULL UNIQUE REFERENCES users(did) ON DELETE CASCADE,
  score        BIGINT      NOT NULL DEFAULT 0,   -- no floor, no ceiling
  total_gained BIGINT      NOT NULL DEFAULT 0,
  total_lost   BIGINT      NOT NULL DEFAULT 0,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_trust_score_did   ON trust_score (user_did);
CREATE INDEX idx_trust_score_score ON trust_score (score DESC);

-- ── Trust Events ──────────────────────────────────────────────────────────────
-- Append-only log. Every point movement recorded here.

CREATE TABLE IF NOT EXISTS trust_events (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_did    TEXT        NOT NULL REFERENCES users(did) ON DELETE CASCADE,
  event_type  TEXT        NOT NULL,
  delta       INTEGER     NOT NULL,
  source_did  TEXT,        -- user who triggered (vouch / complaint)
  platform    TEXT,        -- platform that reported
  note        TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_did      ON trust_events (user_did);
CREATE INDEX idx_events_created  ON trust_events (created_at DESC);
CREATE INDEX idx_events_type     ON trust_events (event_type);
CREATE INDEX idx_events_platform ON trust_events (platform);

-- ── Auth Challenges ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS auth_challenges (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  did        TEXT        NOT NULL,
  nonce      TEXT        NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '2 minutes',
  used       BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX idx_challenges_nonce ON auth_challenges (nonce);

-- ── API Clients ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_clients (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT        NOT NULL UNIQUE,
  api_key     TEXT        NOT NULL UNIQUE,
  permissions TEXT[]      NOT NULL DEFAULT '{"read_trust","read_verification"}',
  active      BOOLEAN     NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_clients_key ON api_clients (api_key);

-- ── Consent Log ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS consent_log (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_did   TEXT        NOT NULL REFERENCES users(did) ON DELETE CASCADE,
  opted_in   BOOLEAN     NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Functions
-- =============================================================================

-- Enroll: creates all three linked rows atomically
CREATE OR REPLACE FUNCTION enroll_user(p_did TEXT, p_pubkey TEXT)
RETURNS void AS $$
BEGIN
  INSERT INTO users        (did, public_key_hex) VALUES (p_did, p_pubkey);
  INSERT INTO verification (user_did, verified)  VALUES (p_did, true);   -- biometric confirmed at enrollment
  INSERT INTO trust_score  (user_did, score)     VALUES (p_did, 0);

  -- Immediate one-time verification boost
  INSERT INTO trust_events (user_did, event_type, delta, platform, note)
  VALUES (p_did, 'biometric_verified', 50, 'pssid_system', 'Biometric enrollment confirmed');

  UPDATE trust_score SET
    score        = 50,
    total_gained = 50,
    updated_at   = NOW()
  WHERE user_did = p_did;
END;
$$ LANGUAGE plpgsql;

-- Apply a trust event and update score atomically
-- Score can go below 0 — no floor applied
CREATE OR REPLACE FUNCTION apply_trust_event(
  p_did      TEXT,
  p_type     TEXT,
  p_delta    INTEGER,
  p_source   TEXT DEFAULT NULL,
  p_platform TEXT DEFAULT NULL,
  p_note     TEXT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE new_score BIGINT;
BEGIN
  INSERT INTO trust_events (user_did, event_type, delta, source_did, platform, note)
  VALUES (p_did, p_type, p_delta, p_source, p_platform, p_note);

  UPDATE trust_score SET
    score        = score + p_delta,            -- no clamping — can go negative
    total_gained = CASE WHEN p_delta > 0 THEN total_gained + p_delta     ELSE total_gained END,
    total_lost   = CASE WHEN p_delta < 0 THEN total_lost   + ABS(p_delta) ELSE total_lost  END,
    updated_at   = NOW()
  WHERE user_did = p_did
  RETURNING score INTO new_score;

  RETURN new_score;
END;
$$ LANGUAGE plpgsql;

-- Seed: test API client
INSERT INTO api_clients (name, api_key, permissions)
VALUES (
  'pssid_test',
  'pssid_test_' || encode(gen_random_bytes(16), 'hex'),
  '{"read_trust","read_verification","report_event"}'
) ON CONFLICT DO NOTHING;