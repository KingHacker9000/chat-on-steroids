/**
 * Optional transport shim for a browser that is not running on the same machine as
 * Chat On Steroids.
 *
 * background.js deliberately knows only the original loopback bridge. Keeping that file
 * unchanged matters: it owns pairing, token rotation, the durable observation journal,
 * command acknowledgements and request/conversation evidence. This module runs first and
 * rewrites only those five fixed loopback bridge URLs when the user has explicitly saved a
 * remote endpoint in extension options.
 *
 * The second credential (`remoteBridgeSecret`) authenticates the network hop. The original
 * bearer token still authenticates the browser to bridge.ts after /pair, so remote mode does
 * not replace or weaken the existing identity chain.
 */

import {
  MIN_REMOTE_SECRET_CHARS,
  REMOTE_SECRET_HEADER,
  REMOTE_SECRET_KEY,
  REMOTE_URL_KEY,
  isLocalBridgeUrl,
  normalizeRemoteBase,
  rewriteBridgeUrl
} from './remote-bridge-config.js';

const nativeFetch = globalThis.fetch.bind(globalThis);
let cachedConfig = undefined;
let configLoad = null;

function invalidateConfig() {
  cachedConfig = undefined;
  configLoad = null;
}

async function readConfig() {
  if (cachedConfig !== undefined) return cachedConfig;
  if (!configLoad) {
    configLoad = chrome.storage.local
      .get([REMOTE_URL_KEY, REMOTE_SECRET_KEY])
      .then((stored) => {
        const remoteUrl = typeof stored[REMOTE_URL_KEY] === 'string' ? stored[REMOTE_URL_KEY].trim() : '';
        const secret = typeof stored[REMOTE_SECRET_KEY] === 'string' ? stored[REMOTE_SECRET_KEY].trim() : '';
        if (!remoteUrl) return null;
        try {
          const base = normalizeRemoteBase(remoteUrl);
          if (!base || secret.length < MIN_REMOTE_SECRET_CHARS) return null;
          return { base: base.href, secret };
        } catch {
          return null;
        }
      })
      .then((value) => {
        cachedConfig = value;
        return value;
      })
      .finally(() => {
        configLoad = null;
      });
  }
  return configLoad;
}

function headersWithRemoteSecret(source, secret) {
  const headers = new Headers(source);
  headers.set(REMOTE_SECRET_HEADER, secret);
  return headers;
}

/**
 * Retargets an existing Request without silently changing its effective request options.
 *
 * Chrome itself first combines the Request and any RequestInit overrides. We then read that
 * combined request and rebuild it with only the URL changed plus our network-hop credential.
 * Buffering the body is deliberate: it avoids relying on streaming-request `duplex` support,
 * and this shim is scoped to bridge traffic whose server-side body limit is already 2 MiB.
 */
async function retargetRequest(input, target, init, secret) {
  const combined = new Request(input.clone(), init);
  const method = combined.method.toUpperCase();
  const body = method === 'GET' || method === 'HEAD' ? undefined : await combined.arrayBuffer();

  return new Request(target, {
    method,
    headers: headersWithRemoteSecret(combined.headers, secret),
    body,
    cache: combined.cache,
    credentials: combined.credentials,
    integrity: combined.integrity,
    keepalive: combined.keepalive,
    mode: combined.mode,
    redirect: combined.redirect,
    referrer: combined.referrer,
    referrerPolicy: combined.referrerPolicy,
    signal: combined.signal
  });
}

async function remoteAwareFetch(input, init) {
  const rawUrl = input instanceof Request ? input.url : input instanceof URL ? input.href : String(input);
  if (!isLocalBridgeUrl(rawUrl)) return nativeFetch(input, init);

  const config = await readConfig();
  if (!config) return nativeFetch(input, init);

  const target = rewriteBridgeUrl(rawUrl, config.base);
  if (input instanceof Request) {
    return nativeFetch(await retargetRequest(input, target, init, config.secret));
  }

  return nativeFetch(target, {
    ...init,
    headers: headersWithRemoteSecret(init && init.headers, config.secret)
  });
}

// Keep the override scoped to the extension service worker. Content/page scripts never load
// this module and therefore never gain access to the remote credential or network endpoint.
globalThis.fetch = remoteAwareFetch;

try {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes[REMOTE_URL_KEY] || changes[REMOTE_SECRET_KEY]) invalidateConfig();
  });
} catch {
  // Narrow unit-test harnesses may provide storage.local without the change event.
}
