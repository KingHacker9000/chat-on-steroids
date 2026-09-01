#!/usr/bin/env node
/**
 * Authenticated network adapter for the browser evidence bridge.
 *
 * The app's bridge intentionally stays loopback-only. This process is a separate, narrow
 * transport layer that can be placed on a trusted overlay network (for example Tailscale)
 * or behind a TLS reverse proxy. It never talks to the MCP server and never gains file,
 * command, desktop, permission, or secret-management routes.
 *
 * Security properties:
 *   - disabled unless somebody starts this process explicitly;
 *   - non-loopback HTTP requires --allow-remote-http;
 *   - every non-OPTIONS request requires a strong, user-supplied remote secret;
 *   - browser origins are limited to chrome-extension:// (or no Origin, as MV3 may omit it);
 *   - the remote secret is consumed here and never forwarded to the app bridge;
 *   - request bodies and rates are bounded before traffic reaches the local bridge;
 *   - the upstream is always a literal loopback HTTP endpoint; this can never become a general proxy.
 *
 * This is deliberately a sidecar instead of making bridge.ts bind to 0.0.0.0. The local
 * bridge keeps its original threat model and silent loopback pairing; this adapter is the
 * only component that accepts network traffic and therefore owns the extra authentication.
 */

import { timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import http from 'node:http';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

export const DEFAULT_LISTEN_HOST = '127.0.0.1';
export const DEFAULT_LISTEN_PORT = 8770;
export const LOCAL_BRIDGE_PORTS = [8765, 8766, 8767, 8768, 8769];
export const REMOTE_SECRET_HEADER = 'x-cos-remote-secret';
export const MAX_BODY_BYTES = 2 * 1024 * 1024;
const REQUESTS_PER_MINUTE = 1200;
const FAILED_AUTH_PER_MINUTE = 30;
const UPSTREAM_TIMEOUT_MS = 15_000;
const DISCOVERY_TIMEOUT_MS = 1_200;
const MIN_SECRET_CHARS = 32;

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

export function isLoopbackHost(host) {
  const normalized = String(host || '').trim().toLowerCase();
  return (
    normalized === '127.0.0.1' ||
    normalized === 'localhost' ||
    normalized === '::1' ||
    normalized === '[::1]'
  );
}

function isLiteralLoopbackHost(host) {
  const normalized = String(host || '').trim().toLowerCase();
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === '[::1]';
}

export function originAllowed(origin) {
  return origin === undefined || origin === null || origin === '' || String(origin).startsWith('chrome-extension://');
}

export function safeSecretEqual(actual, expected) {
  const a = Buffer.from(String(actual || ''), 'utf8');
  const b = Buffer.from(String(expected || ''), 'utf8');
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}

function usage() {
  return `Chat On Steroids remote browser bridge\n\n` +
    `Usage:\n` +
    `  npm run bridge:remote -- [options]\n\n` +
    `Options:\n` +
    `  --host <host>              Listen address (default 127.0.0.1)\n` +
    `  --port <port>              Listen port (default 8770; 0 asks the OS)\n` +
    `  --target <url>             Exact loopback bridge origin; otherwise scan 8765-8769\n` +
    `  --secret <value>           Remote secret (prefer environment or --secret-file)\n` +
    `  --secret-file <path>       Read the remote secret from a file\n` +
    `  --allow-remote-http        Required when HTTP listens beyond loopback\n` +
    `  --help                     Show this help\n\n` +
    `Environment:\n` +
    `  COS_REMOTE_BRIDGE_SECRET\n` +
    `  COS_REMOTE_BRIDGE_SECRET_FILE\n`;
}

export function parseArgs(argv) {
  const options = {
    host: DEFAULT_LISTEN_HOST,
    port: DEFAULT_LISTEN_PORT,
    target: null,
    secret: process.env.COS_REMOTE_BRIDGE_SECRET || null,
    secretFile: process.env.COS_REMOTE_BRIDGE_SECRET_FILE || null,
    allowRemoteHttp: false,
    help: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const take = (name) => {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
      index += 1;
      return value;
    };
    if (arg === '--host') options.host = take('--host');
    else if (arg === '--port') options.port = Number.parseInt(take('--port'), 10);
    else if (arg === '--target') options.target = take('--target');
    else if (arg === '--secret') options.secret = take('--secret');
    else if (arg === '--secret-file') options.secretFile = take('--secret-file');
    else if (arg === '--allow-remote-http') options.allowRemoteHttp = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`Unknown option: ${arg}`);
  }

  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) {
    throw new Error('--port must be an integer from 0 to 65535');
  }
  return options;
}

async function resolveSecret(options) {
  if (options.secret && options.secretFile) {
    throw new Error('Use only one of --secret/COS_REMOTE_BRIDGE_SECRET or --secret-file/COS_REMOTE_BRIDGE_SECRET_FILE');
  }
  const secret = options.secretFile ? (await fs.readFile(options.secretFile, 'utf8')).trim() : String(options.secret || '').trim();
  if (secret.length < MIN_SECRET_CHARS) {
    throw new Error(`Remote bridge secret must be at least ${MIN_SECRET_CHARS} characters`);
  }
  return secret;
}

function normalizedTarget(value) {
  const target = new URL(value);
  if (target.protocol !== 'http:') throw new Error('Bridge target must use loopback http://');
  if (!isLiteralLoopbackHost(target.hostname)) throw new Error('Bridge target must use a literal loopback address');
  if (target.username || target.password || target.search || target.hash) {
    throw new Error('Bridge target must not contain credentials, query parameters, or a fragment');
  }
  if (target.pathname !== '/' && target.pathname !== '') {
    throw new Error('Bridge target must be an origin, without a path');
  }
  target.pathname = '/';
  return target;
}

function requestBuffer(url, { method = 'GET', headers = {}, body = null, timeoutMs = UPSTREAM_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      url,
      { method, headers, timeout: timeoutMs },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          // Bridge responses are intentionally small. A runaway/misconfigured upstream is
          // not allowed to turn this adapter into an unbounded memory sink.
          if (size > MAX_BODY_BYTES) {
            req.destroy(new Error('upstream response exceeded body limit'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode || 502,
            headers: res.headers,
            body: Buffer.concat(chunks)
          });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('upstream request timed out')));
    req.on('error', reject);
    if (body && body.length) req.write(body);
    req.end();
  });
}

export async function discoverLocalBridge(ports = LOCAL_BRIDGE_PORTS) {
  for (const candidate of ports) {
    const url = new URL(`http://127.0.0.1:${candidate}/hello`);
    try {
      const response = await requestBuffer(url, { timeoutMs: DISCOVERY_TIMEOUT_MS });
      if (response.status !== 200) continue;
      const parsed = JSON.parse(response.body.toString('utf8'));
      if (parsed && parsed.app === 'chat-on-steroids') return new URL(`http://127.0.0.1:${candidate}`);
    } catch {
      // Discovery is best-effort across the fixed local range.
    }
  }
  return null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const chunks = [];
    let size = 0;

    const rejectTooLarge = () => {
      if (settled) return;
      settled = true;
      const error = new Error('request body too large');
      error.statusCode = 413;
      // Drain rather than destroy the socket: the caller still deserves the explicit 413.
      req.removeListener('data', onData);
      req.resume();
      reject(error);
    };

    const declared = Number.parseInt(String(req.headers['content-length'] || '0'), 10);
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      rejectTooLarge();
      return;
    }

    function onData(chunk) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        rejectTooLarge();
        return;
      }
      chunks.push(chunk);
    }

    req.on('data', onData);
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });
    req.on('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

function responseHeaders(headers, origin) {
  const result = {};
  for (const [name, value] of Object.entries(headers || {})) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || lower === 'access-control-allow-origin') continue;
    if (value !== undefined) result[name] = value;
  }
  result['cache-control'] = 'no-store';
  if (origin) result['access-control-allow-origin'] = origin;
  return result;
}

function forwardedHeaders(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers || {})) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || lower === 'host' || lower === REMOTE_SECRET_HEADER) continue;
    if (value !== undefined) result[name] = value;
  }
  return result;
}

function sendJson(res, status, body, origin = null) {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  const headers = {
    'content-type': 'application/json',
    'content-length': String(payload.length),
    'cache-control': 'no-store'
  };
  if (origin) {
    headers['access-control-allow-origin'] = origin;
    headers['access-control-allow-headers'] = `authorization, content-type, ${REMOTE_SECRET_HEADER}`;
    headers['access-control-allow-methods'] = 'GET, POST, OPTIONS';
  }
  res.writeHead(status, headers);
  res.end(payload);
}

function makeWindow(limit) {
  return { startedAt: Date.now(), count: 0, limit };
}

function consumeWindow(window) {
  const now = Date.now();
  if (now - window.startedAt >= 60_000) {
    window.startedAt = now;
    window.count = 0;
  }
  window.count += 1;
  return window.count <= window.limit;
}

export async function startRemoteBridge(options = {}) {
  const host = options.host ?? DEFAULT_LISTEN_HOST;
  const listenPort = options.port ?? DEFAULT_LISTEN_PORT;
  const secret = options.secret;
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_CHARS) {
    throw new Error(`Remote bridge secret must be at least ${MIN_SECRET_CHARS} characters`);
  }
  if (!isLoopbackHost(host) && options.allowRemoteHttp !== true) {
    throw new Error('Refusing non-loopback HTTP without --allow-remote-http');
  }

  const target = options.target ? normalizedTarget(String(options.target)) : await discoverLocalBridge();
  if (!target) {
    throw new Error('Local Chat On Steroids browser bridge not found on 127.0.0.1:8765-8769');
  }

  const requests = makeWindow(REQUESTS_PER_MINUTE);
  const authFailures = makeWindow(FAILED_AUTH_PER_MINUTE);

  const server = http.createServer(async (req, res) => {
    const origin = typeof req.headers.origin === 'string' ? req.headers.origin : null;
    if (!originAllowed(origin)) return sendJson(res, 403, { error: 'forbidden_origin' }, null);

    // A CORS preflight carries no credential value. It is safe to answer because only a
    // chrome-extension:// origin is accepted and the real request still has to authenticate.
    if (req.method === 'OPTIONS') {
      const requestedHeaders =
        typeof req.headers['access-control-request-headers'] === 'string'
          ? req.headers['access-control-request-headers']
          : `authorization, content-type, ${REMOTE_SECRET_HEADER}`;
      res.writeHead(204, {
        'cache-control': 'no-store',
        ...(origin ? { 'access-control-allow-origin': origin } : {}),
        'access-control-allow-headers': requestedHeaders,
        'access-control-allow-methods': 'GET, POST, OPTIONS'
      });
      res.end();
      return;
    }

    if (!consumeWindow(requests)) return sendJson(res, 429, { error: 'rate_limited' }, origin);

    const supplied = req.headers[REMOTE_SECRET_HEADER];
    const suppliedSecret = Array.isArray(supplied) ? supplied[0] : supplied;
    if (!safeSecretEqual(suppliedSecret, secret)) {
      if (!consumeWindow(authFailures)) return sendJson(res, 429, { error: 'auth_rate_limited' }, origin);
      // Do not use 401 here. That status belongs to bridge.ts's existing bearer token and
      // background.js treats it as a signal to rotate that token. A bad network-hop secret
      // must never invalidate a perfectly good browser/app pairing.
      return sendJson(res, 403, { error: 'remote_auth_required' }, origin);
    }

    try {
      const body = req.method === 'GET' || req.method === 'HEAD' ? null : await readBody(req);
      const upstream = new URL(req.url || '/', target);
      const result = await requestBuffer(upstream, {
        method: req.method || 'GET',
        headers: forwardedHeaders(req.headers),
        body
      });
      // App-side 401s are intentionally forwarded unchanged. The existing extension worker
      // then drops its stale app bearer and performs the normal one-shot /pair recovery.
      res.writeHead(result.status, responseHeaders(result.headers, origin));
      res.end(result.body);
    } catch (error) {
      const status = Number(error && error.statusCode) || 502;
      sendJson(res, status, { error: status === 413 ? 'body_too_large' : 'bridge_unavailable' }, origin);
    }
  });

  await new Promise((resolve, reject) => {
    const fail = (error) => reject(error);
    server.once('error', fail);
    server.listen(listenPort, host, () => {
      server.off('error', fail);
      resolve();
    });
  });

  return { server, target, address: server.address() };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }

  const secret = await resolveSecret(options);
  const result = await startRemoteBridge({ ...options, secret });
  const address = result.address;
  const actualPort = typeof address === 'object' && address ? address.port : options.port;
  const shownHost = options.host.includes(':') && !options.host.startsWith('[') ? `[${options.host}]` : options.host;
  process.stdout.write(`Remote browser bridge listening on http://${shownHost}:${actualPort}\n`);
  process.stdout.write(`Forwarding browser evidence to ${result.target.origin}\n`);
  if (!isLoopbackHost(options.host)) {
    process.stdout.write('Remote HTTP enabled explicitly. Use only on an encrypted/trusted overlay network or behind TLS.\n');
  }

  const stop = async () => {
    await new Promise((resolve) => result.server.close(resolve));
    process.exit(0);
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : null;
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`remote bridge: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
