// src/server.ts
import Fastify          from 'fastify';
import cors             from '@fastify/cors';
import helmet           from '@fastify/helmet';
import rateLimit        from '@fastify/rate-limit';
import { config }       from 'dotenv';
import { verificationRoutes } from './routes/verification.js';
import { trustRoutes }        from './routes/trust.js';
import { publicRoutes }       from './routes/public.js';
import { recoveryRoutes } from './routes/recovery.js';
import { FastifyError } from 'fastify';

config();

const app = Fastify({
  logger: {
    level:     process.env.LOG_LEVEL ?? 'info',
    transport: process.env.NODE_ENV !== 'production'
      ? { target: 'pino-pretty' }
      : undefined,
  },
});

await app.register(helmet, { contentSecurityPolicy: false });
await app.register(cors, {
  origin:  process.env.ALLOWED_ORIGINS?.split(',') ?? '*',
  methods: ['GET', 'POST'],
});
await app.register(rateLimit, {
  global:      true,
  max:         100,
  timeWindow:  '1 minute',
  errorResponseBuilder: () => ({
    error:   'rate_limited',
    message: 'Too many requests.',
  }),
});

await app.register(verificationRoutes);
await app.register(trustRoutes);
await app.register(publicRoutes);
await app.register(recoveryRoutes);

app.setErrorHandler((error: FastifyError, _req, reply) => {
  app.log.error(error);
  reply.status(error.statusCode ?? 500).send({
    error:   error.name ?? 'InternalServerError',
    message: error.message,
  });
});

const PORT = Number(process.env.PORT ?? 3000);
const HOST = process.env.HOST ?? '0.0.0.0';

try {
  await app.listen({ port: PORT, host: HOST });
  console.log(`PSSID backend running on ${HOST}:${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}