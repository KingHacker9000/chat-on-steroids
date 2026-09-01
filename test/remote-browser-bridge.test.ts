import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const SECRET = 'test-secret-0123456789abcdef-0123456789abcdef';
const EXTENSION_ORIGIN = 'chrome-extension://abcdefghijklmnop';

let child: ChildProcessWithoutNullStreams | null = null;
let fake: http.Server | null = null;

async function closeServer(server: http.Server | null): Promise<void> {
  if (!server) return;
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function stopChild(): Promise<void> {
  if (!child || child.exitCode !== null) {
    child = null;
    return;
  }
  const exiting = once(child, 'exit');
  child.kill('SIGTERM');
  await exiting;
  child = null;
}

afterEach(async () => {
  await stopChild();
  await closeServer(fake);
  fake = null;
});

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      if (!address || typeof address === 'string') return reject(new Error('fake bridge did not get a TCP port'));
      resolve(address.port);
    });
  });
}

function waitForListening(proc: ChildProcessWithoutNullStreams): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error(`sidecar did not start: ${output}`)), 5_000);
    const onExit = (code: number | null) => {
      clearTimeout(timeout);
      reject(new Error(`sidecar exited before listening (${code}): ${output}`));
    };
    proc.once('exit', onExit);
    proc.stdout.setEncoding('utf8');
    proc.stderr.setEncoding('utf8');
    proc.stdout.on('data', (chunk: string) => {
      output += chunk;
      const match = output.match(/Remote browser bridge listening on (http:\/\/[^\s]+)/);
      if (!match) return;
      clearTimeout(timeout);
      proc.off('exit', onExit);
      resolve(match[1]!);
    });
    proc.stderr.on('data', (chunk: string) => {
      output += chunk;
    });
  });
}

function spawnSidecar(args: string[]): ChildProcessWithoutNullStreams {
  return spawn(process.execPath, [path.join(process.cwd(), 'scripts', 'remote-browser-bridge.mjs'), ...args], {
    stdio: 'pipe'
  });
}

async function startSidecar(targetPort: number): Promise<string> {
  child = spawnSidecar([
    '--host',
    '127.0.0.1',
    '--port',
    '0',
    '--target',
    `http://127.0.0.1:${targetPort}`,
    '--secret',
    SECRET
  ]);
  return waitForListening(child);
}

async function exited(proc: ChildProcessWithoutNullStreams): Promise<{ code: number | null; stderr: string }> {
  let stderr = '';
  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });
  const [code] = (await once(proc, 'exit')) as [number | null, NodeJS.Signals | null];
  return { code, stderr };
}

describe('remote browser bridge sidecar', () => {
  it('authenticates the network hop without forwarding that credential to the local bridge', async () => {
    const seenRemoteSecrets: Array<string | undefined> = [];
    fake = http.createServer((req, res) => {
      seenRemoteSecrets.push(req.headers['x-cos-remote-secret'] as string | undefined);
      const payload = Buffer.from(JSON.stringify({ app: 'chat-on-steroids', path: req.url }), 'utf8');
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(payload.length) });
      res.end(payload);
    });
    const targetPort = await listen(fake);
    const base = await startSidecar(targetPort);

    const unauthenticated = await fetch(`${base}/hello`, { headers: { origin: EXTENSION_ORIGIN } });
    expect(unauthenticated.status).toBe(403);
    expect(await unauthenticated.json()).toMatchObject({ error: 'remote_auth_required' });

    const authenticated = await fetch(`${base}/hello`, {
      headers: { origin: EXTENSION_ORIGIN, 'x-cos-remote-secret': SECRET }
    });
    expect(authenticated.status).toBe(200);
    expect(await authenticated.json()).toMatchObject({ app: 'chat-on-steroids', path: '/hello' });
    expect(seenRemoteSecrets).toEqual([undefined]);
  });

  it('passes an app-side 401 through unchanged for the existing bearer-token recovery', async () => {
    fake = http.createServer((_req, res) => {
      const payload = Buffer.from(JSON.stringify({ error: 'unauthorized' }), 'utf8');
      res.writeHead(401, { 'content-type': 'application/json', 'content-length': String(payload.length) });
      res.end(payload);
    });
    const targetPort = await listen(fake);
    const base = await startSidecar(targetPort);

    const response = await fetch(`${base}/activity`, {
      headers: { origin: EXTENSION_ORIGIN, 'x-cos-remote-secret': SECRET, authorization: 'Bearer stale' }
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: 'unauthorized' });
  });

  it('rejects ordinary web origins even when they know the remote secret', async () => {
    fake = http.createServer((_req, res) => {
      res.writeHead(200).end('should not be reached');
    });
    const targetPort = await listen(fake);
    const base = await startSidecar(targetPort);

    const response = await fetch(`${base}/hello`, {
      headers: { origin: 'https://chatgpt.com', 'x-cos-remote-secret': SECRET }
    });
    expect(response.status).toBe(403);
  });

  it('bounds request bodies before proxying them', async () => {
    let upstreamCalls = 0;
    fake = http.createServer((_req, res) => {
      upstreamCalls += 1;
      res.writeHead(200).end('ok');
    });
    const targetPort = await listen(fake);
    const base = await startSidecar(targetPort);

    const response = await fetch(`${base}/events`, {
      method: 'POST',
      headers: {
        origin: EXTENSION_ORIGIN,
        'x-cos-remote-secret': SECRET,
        'content-type': 'application/octet-stream'
      },
      body: Buffer.alloc(2 * 1024 * 1024 + 1)
    });
    expect(response.status).toBe(413);
    expect(upstreamCalls).toBe(0);
  });

  it('refuses network listening unless remote HTTP was explicitly enabled', async () => {
    fake = http.createServer((_req, res) => res.writeHead(200).end('ok'));
    const targetPort = await listen(fake);
    child = spawnSidecar([
      '--host',
      '0.0.0.0',
      '--port',
      '0',
      '--target',
      `http://127.0.0.1:${targetPort}`,
      '--secret',
      SECRET
    ]);
    const result = await exited(child);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Refusing non-loopback HTTP without --allow-remote-http');
  });

  it('refuses a non-loopback upstream target', async () => {
    child = spawnSidecar([
      '--host',
      '127.0.0.1',
      '--port',
      '0',
      '--target',
      'http://192.0.2.10:8765',
      '--secret',
      SECRET
    ]);
    const result = await exited(child);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Bridge target must use a literal loopback address');
  });
});

describe('remote bridge extension packaging', () => {
  it('loads the transport shim before the existing service worker and keeps remote hosts optional', async () => {
    const extension = path.join(process.cwd(), 'extension');
    const manifest = JSON.parse(await fs.readFile(path.join(extension, 'manifest.json'), 'utf8')) as {
      background: { service_worker: string; type: string };
      host_permissions: string[];
      optional_host_permissions?: string[];
      options_ui?: { page: string };
    };
    const entry = await fs.readFile(path.join(extension, 'background-entry.js'), 'utf8');

    expect(manifest.background).toEqual({ service_worker: 'background-entry.js', type: 'module' });
    expect(entry.indexOf("import './remote-bridge.js'")).toBeLessThan(entry.indexOf("import './background.js'"));
    expect(manifest.host_permissions).not.toContain('http://*/*');
    expect(manifest.host_permissions).not.toContain('https://*/*');
    expect(manifest.optional_host_permissions).toEqual(['http://*/*', 'https://*/*']);
    expect(manifest.options_ui?.page).toBe('options.html');
  });

  it('rewrites only the bridge path and asks Chrome for one exact origin', async () => {
    const moduleUrl = `${pathToFileURL(path.join(process.cwd(), 'extension', 'remote-bridge-config.js')).href}?test=${Date.now()}`;
    const config = (await import(moduleUrl)) as {
      rewriteBridgeUrl(localValue: string, remoteBase: string): URL;
      permissionPattern(remoteBase: string): string;
    };

    expect(
      config.rewriteBridgeUrl('http://127.0.0.1:8765/events?batch=1', 'https://bridge.example:9443/cos').href
    ).toBe('https://bridge.example:9443/cos/events?batch=1');
    expect(config.permissionPattern('https://bridge.example:9443/cos')).toBe('https://bridge.example:9443/*');
  });

  it('requests optional host access directly from the user gesture', async () => {
    const options = await fs.readFile(path.join(process.cwd(), 'extension', 'options.js'), 'utf8');
    expect(options).toContain('chrome.permissions.request({ origins: [pattern] })');
    expect(options).not.toContain('chrome.permissions.contains');
  });

  it('keeps the remote credential out of page and content-script code', async () => {
    const extension = path.join(process.cwd(), 'extension');
    const [manifestText, content, fiber] = await Promise.all([
      fs.readFile(path.join(extension, 'manifest.json'), 'utf8'),
      fs.readFile(path.join(extension, 'content.js'), 'utf8'),
      fs.readFile(path.join(extension, 'fiber.js'), 'utf8')
    ]);
    const manifest = JSON.parse(manifestText) as { content_scripts: Array<{ js: string[] }> };
    const pageFiles = new Set(manifest.content_scripts.flatMap((entry) => entry.js));

    expect(pageFiles.has('remote-bridge.js')).toBe(false);
    expect(pageFiles.has('remote-bridge-config.js')).toBe(false);
    expect(content).not.toContain('remoteBridgeSecret');
    expect(fiber).not.toContain('remoteBridgeSecret');
  });
});
