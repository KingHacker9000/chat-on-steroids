import {
  MIN_REMOTE_SECRET_CHARS,
  REMOTE_SECRET_HEADER,
  REMOTE_SECRET_KEY,
  REMOTE_URL_KEY,
  normalizeRemoteBase,
  permissionPattern
} from './remote-bridge-config.js';

const $ = (id) => document.getElementById(id);
const TEST_TIMEOUT_MS = 5_000;

function setStatus(text, state = '') {
  const status = $('status');
  status.textContent = text;
  status.className = `status ${state}`.trim();
}

function values() {
  const base = normalizeRemoteBase($('remoteUrl').value);
  const secret = $('remoteSecret').value.trim();
  if (!base) throw new Error('Enter a remote bridge URL');
  if (secret.length < MIN_REMOTE_SECRET_CHARS) {
    throw new Error(`Remote secret must be at least ${MIN_REMOTE_SECRET_CHARS} characters`);
  }
  return { base, secret, pattern: permissionPattern(base.href) };
}

/**
 * Chrome requires permissions.request() to run from a user gesture. Do not put an awaited
 * contains() call in front of it: the permission prompt may otherwise lose the click that
 * authorizes it. Requesting an already-granted origin is harmless and resolves true.
 */
function requestPermission(pattern) {
  return chrome.permissions.request({ origins: [pattern] });
}

async function load() {
  const stored = await chrome.storage.local.get([REMOTE_URL_KEY, REMOTE_SECRET_KEY]);
  $('remoteUrl').value = typeof stored[REMOTE_URL_KEY] === 'string' ? stored[REMOTE_URL_KEY] : '';
  $('remoteSecret').value = typeof stored[REMOTE_SECRET_KEY] === 'string' ? stored[REMOTE_SECRET_KEY] : '';
  setStatus(stored[REMOTE_URL_KEY] ? 'Remote bridge is configured.' : 'Using local bridge discovery.');
}

async function save(event) {
  event.preventDefault();
  try {
    // Parse synchronously and request permission immediately while the submit gesture is live.
    const { base, secret, pattern } = values();
    const granted = await requestPermission(pattern);
    if (!granted) throw new Error('Chrome did not grant access to that bridge origin');
    await chrome.storage.local.set({
      [REMOTE_URL_KEY]: base.href.replace(/\/$/, ''),
      [REMOTE_SECRET_KEY]: secret
    });
    setStatus('Remote bridge saved. The next bridge request will use it.', 'good');
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'bad');
  }
}

async function responseError(response) {
  try {
    const body = await response.clone().json();
    if (response.status === 403 && body && body.error === 'remote_auth_required') {
      return 'Remote secret was rejected';
    }
    if (body && typeof body.error === 'string') return `Remote bridge rejected the request (${body.error})`;
  } catch {
    // A proxy or TLS terminator may return a non-JSON error page. Fall back to the status.
  }
  return `Remote bridge returned HTTP ${response.status}`;
}

async function testConnection() {
  $('testBtn').disabled = true;
  setStatus('Testing remote bridge…');
  try {
    // Same rule as save(): permission acquisition is the first async operation from the click.
    const { base, secret, pattern } = values();
    const granted = await requestPermission(pattern);
    if (!granted) throw new Error('Chrome did not grant access to that bridge origin');

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TEST_TIMEOUT_MS);
    let response;
    try {
      response = await fetch(new URL('hello', base), {
        cache: 'no-store',
        signal: controller.signal,
        headers: { [REMOTE_SECRET_HEADER]: secret }
      });
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) throw new Error(await responseError(response));
    const body = await response.json();
    if (!body || body.app !== 'chat-on-steroids') throw new Error('That endpoint is not a Chat On Steroids bridge');
    setStatus(`Connected to Chat On Steroids${body.version ? ` v${body.version}` : ''}.`, 'good');
  } catch (error) {
    const message =
      error && error.name === 'AbortError'
        ? 'Remote bridge timed out'
        : error instanceof Error
          ? error.message
          : String(error);
    setStatus(message, 'bad');
  } finally {
    $('testBtn').disabled = false;
  }
}

async function clearRemote() {
  const stored = await chrome.storage.local.get([REMOTE_URL_KEY]);
  const oldUrl = typeof stored[REMOTE_URL_KEY] === 'string' ? stored[REMOTE_URL_KEY] : '';
  await chrome.storage.local.remove([REMOTE_URL_KEY, REMOTE_SECRET_KEY]);
  if (oldUrl) {
    try {
      await chrome.permissions.remove({ origins: [permissionPattern(oldUrl)] });
    } catch {
      // Permission cleanup is best-effort; removing the config already disables remote mode.
    }
  }
  $('remoteUrl').value = '';
  $('remoteSecret').value = '';
  setStatus('Remote mode disabled. Using local bridge discovery.', 'good');
}

$('remoteForm').addEventListener('submit', save);
$('testBtn').addEventListener('click', testConnection);
$('clearBtn').addEventListener('click', clearRemote);
load().catch((error) => setStatus(error instanceof Error ? error.message : String(error), 'bad'));
