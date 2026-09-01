# Remote browser bridge

Chat On Steroids normally assumes that the Chrome companion and the app are on the same machine. The model-facing MCP connection can already be remote, but the companion proves which ChatGPT conversation issued a tool call by sending browser evidence to a separate bridge that intentionally listens only on `127.0.0.1:8765-8769`.

Remote browser bridge mode carries **only that browser-evidence connection** to another machine. It does not expose the MCP server, add a command API, or relax conversation/terminal/workspace ownership.

## Architecture

```text
Browser machine                                  Chat On Steroids machine

ChatGPT page
    │
Chrome companion
    │  remote secret + normal bridge bearer
    │
    └──────────────► remote-browser-bridge :8770
                           │
                           │ loopback only
                           ▼
                     bridge.ts :8765-8769
                           │
                           └── recorder / request correlation / agents

ChatGPT model ───────── existing MCP/tunnel connection ─────────► MCP server
```

The two network paths stay separate on purpose. `bridge.ts` remains loopback-only and keeps its existing silent local `/pair` flow. The remote sidecar is an explicit adapter in front of it and requires another strong credential before forwarding anything.

## Security properties

Remote mode is opt-in. Nothing listens on a network interface until `bridge:remote` is started, and the shipped extension continues to use loopback discovery unless a remote endpoint is saved in its Options page.

The sidecar:

- requires a remote secret of at least 32 characters on every real request;
- compares that secret in constant time and strips it before forwarding;
- accepts browser origins only from `chrome-extension://` (or no Origin, which MV3 extension fetches may use);
- bounds requests and responses to 2 MiB and rate-limits traffic before it reaches `bridge.ts`;
- discovers only the existing loopback bridge by default;
- refuses to listen beyond loopback over HTTP unless `--allow-remote-http` is explicit.

The original app bearer token is still minted by `/pair` and checked by `bridge.ts`. The remote secret authenticates the **network hop**; it does not replace browser/app pairing or request-id-to-conversation proof.

The extension declares broad HTTP/HTTPS hosts only as **optional** host permissions. Chrome is asked to grant the exact origin entered in Options; those hosts are not part of the extension's always-on permissions.

## 1. Generate a secret on the Chat On Steroids machine

Prefer a file over a command-line argument so the secret is not visible in the process command line.

```bash
mkdir -p ~/.config/chat-on-steroids
chmod 700 ~/.config/chat-on-steroids
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex') + '\n')" > ~/.config/chat-on-steroids/remote-bridge.secret
chmod 600 ~/.config/chat-on-steroids/remote-bridge.secret
```

## 2. Start the sidecar

The local app/core must already be running so its normal browser bridge exists on one of ports 8765-8769.

### Tailscale / other encrypted private overlay

Find the machine's tailnet address:

```bash
tailscale ip -4
```

Then bind the sidecar to that address. Example:

```bash
COS_REMOTE_BRIDGE_SECRET_FILE="$HOME/.config/chat-on-steroids/remote-bridge.secret" \
  npm run bridge:remote -- \
  --host 100.64.0.12 \
  --port 8770 \
  --allow-remote-http
```

`--allow-remote-http` is intentionally noisy: HTTP has no application-layer encryption. It is appropriate here only because an overlay such as Tailscale encrypts the network path underneath it. Do not expose that listener directly to an untrusted LAN or the public internet.

### HTTPS reverse proxy

For a public/routable host, keep the sidecar on loopback:

```bash
COS_REMOTE_BRIDGE_SECRET_FILE="$HOME/.config/chat-on-steroids/remote-bridge.secret" \
  npm run bridge:remote -- --host 127.0.0.1 --port 8770
```

Put Caddy, nginx, Traefik, Tailscale Serve, or another TLS terminator in front of `http://127.0.0.1:8770`, and use its `https://...` URL in the extension. The sidecar secret is still required behind TLS.

## 3. Configure the Chrome companion

Open the extension's **Options** page and enter:

- **Bridge URL** — for example `http://100.64.0.12:8770` on a tailnet, or your HTTPS reverse-proxy URL;
- **Remote secret** — the exact value generated above.

Press **Test connection**, then **Save remote bridge**. Chrome will request access only to that endpoint's origin.

No change is required to the ChatGPT MCP connector. The model continues using the existing public/tunnel endpoint while the browser companion sends request/conversation evidence through the remote sidecar.

To return to the normal same-machine setup, choose **Use local bridge** in Options. The extension removes the remote settings and best-effort revokes the optional host permission.

## systemd example

On a Linux host that stays online, run the sidecar beside the existing Chat On Steroids core. The example below assumes a dedicated `cos` service account, a checkout in `/opt/chat-on-steroids`, a root-owned secret in `/etc/chat-on-steroids`, and `100.64.0.12` as an example private-overlay address. Replace those values for the target machine.

```ini
# /etc/systemd/system/chat-on-steroids-remote-bridge.service
[Unit]
Description=Chat On Steroids remote browser bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cos
WorkingDirectory=/opt/chat-on-steroids
Environment=COS_REMOTE_BRIDGE_SECRET_FILE=/etc/chat-on-steroids/remote-bridge.secret
ExecStart=/usr/bin/npm run bridge:remote -- --host 100.64.0.12 --port 8770 --allow-remote-http
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now chat-on-steroids-remote-bridge.service
sudo systemctl status chat-on-steroids-remote-bridge.service
```

## Command reference

```text
--host <host>              listen address (default 127.0.0.1)
--port <port>              listen port (default 8770; 0 asks the OS)
--target <url>             exact loopback bridge origin; otherwise scan 8765-8769
--secret <value>           remote secret (prefer env/file)
--secret-file <path>       read remote secret from a file
--allow-remote-http        permit non-loopback HTTP listening
--help                     show help
```

Environment alternatives:

- `COS_REMOTE_BRIDGE_SECRET`
- `COS_REMOTE_BRIDGE_SECRET_FILE`

`--target` exists mainly for diagnostics and tests. It accepts only a literal loopback HTTP origin. Normal operation should use discovery so the sidecar follows whichever one of the fixed local bridge ports the app acquired.

## Failure behavior

The two credentials fail independently. A bad or missing **remote secret** is rejected by the sidecar with `403` and never reaches the app. It does not invalidate the browser/app bearer token. If the sidecar successfully authenticates the network hop but `bridge.ts` rejects the existing app bearer with `401`, that response is forwarded unchanged; the existing extension worker then drops only that stale bearer and performs its normal one-shot `/pair` recovery.

If the remote sidecar is unavailable, browser observations remain in the extension's existing storage-backed journal and are retried by the existing worker. The remote adapter does not maintain another queue.
