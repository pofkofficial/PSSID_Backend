// src/db/client.ts
import { Pool, QueryResultRow } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
  max:            10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
});

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err);
});

export const db = {
  query: <T extends QueryResultRow = any>(
    text: string,
    params?: any[]
  ) => pool.query<T>(text, params),

  // Convenience: get first row or null
  queryOne: async <T extends QueryResultRow = any>(
    text: string,
    params?: any[]
  ): Promise<T | null> => {
    const result = await pool.query<T>(text, params);
    return result.rows[0] ?? null;
  },
};