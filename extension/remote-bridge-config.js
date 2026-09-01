export const REMOTE_URL_KEY = 'remoteBridgeUrl';
export const REMOTE_SECRET_KEY = 'remoteBridgeSecret';
export const REMOTE_SECRET_HEADER = 'x-cos-remote-secret';
export const MIN_REMOTE_SECRET_CHARS = 32;

const LOCAL_BRIDGE_PORTS = new Set(['8765', '8766', '8767', '8768', '8769']);

export function isLocalBridgeUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'http:' && url.hostname === '127.0.0.1' && LOCAL_BRIDGE_PORTS.has(url.port);
  } catch {
    return false;
  }
}

export function normalizeRemoteBase(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  const url = new URL(text);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Remote bridge URL must use http:// or https://');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Remote bridge URL must not contain credentials, a query, or a fragment');
  }
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/`;
  return url;
}

export function rewriteBridgeUrl(localValue, remoteBase) {
  const local = new URL(String(localValue));
  const base = normalizeRemoteBase(remoteBase);
  if (!base) return local;
  const relativePath = `${local.pathname.replace(/^\/+/, '')}${local.search}`;
  return new URL(relativePath, base);
}

/** The narrow origin permission Chrome is asked to grant after a user saves an endpoint. */
export function permissionPattern(remoteBase) {
  const url = normalizeRemoteBase(remoteBase);
  if (!url) throw new Error('Remote bridge URL is required');
  return `${url.protocol}//${url.host}/*`;
}
