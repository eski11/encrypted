# ENCPTD server on your Windows PC

This is a prepared server setup. It has not been started or tested with Docker yet. It uses Synapse, PostgreSQL and a Caddy gateway. Your PC owns the chat accounts/database; the existing Matrix.org service is not used for accounts or message delivery.

## Before starting

Install [Docker Desktop for Windows x86_64](https://docs.docker.com/desktop/setup/install/windows-install/) using its **WSL 2 / Linux containers** backend. Finish any Windows feature installation/restart it requests, then open Docker Desktop and wait for the engine. If Windows requires administrator approval for WSL, complete that yourself; these scripts do not change Windows features or reboot the PC.

## First internet test without a domain

From PowerShell in this repository:

```powershell
./server/Start-Server.ps1 -TemporaryInternetTest
./server/New-ChatUser.ps1 -Username ediz
```

The account command prompts privately for a password. Create a separate account for each person. The account ID in this setup is `@ediz:encptd.local`; the identity remains fixed when the tunnel URL changes. Public/guest registration and federation with other Matrix servers are disabled. New local rooms default to end-to-end encryption, and the app separately refuses sending message contents in unencrypted rooms.

The startup script generates random server/database secrets in ignored `server/.env` and preserves them on subsequent runs. PostgreSQL lives in a Docker named volume; Synapse signing keys, configuration and media live in ignored `server/state/`. Do not delete either, and do not run `docker compose down -v` unless you intend to destroy the database. Server backups and phone recovery keys are still needed before relying on it.

The optional Cloudflare Quick Tunnel gives a temporary public HTTPS address without a domain/account or router port forwarding. Cloudflare terminates HTTPS and can observe account/login traffic and protocol metadata; the Matrix client supplies the separate end-to-end encryption for message contents. This route does not meet a requirement for having no third-party network intermediary. Quick Tunnels have no uptime guarantee and change address on restart. They are for testing, not permanent hosting. Anyone with that address can reach the login API, but accounts remain controlled locally.

The Caddy gateway publishes only the client/media endpoints and discovery. Synapse's admin API, federation endpoints and PostgreSQL are not published. The gateway itself binds only to Windows loopback; the tunnel supplies external reachability. Do not expose ports 5432 or 8008 on your router.

When the public health check passes, startup writes `server/client.json` with only the public URL/server name/app name. Commit this **non-secret** file for Codemagic to build an app that goes straight to your server. Do not commit `.env`, server data, passwords or recovery keys. The app configuration script consumes `client.json`, disables other account providers and removes the public Create Account button. Accounts are created with the command above.

## Stopping and restarting

```powershell
cd server
docker compose --profile temporary-tunnel stop
```

To restart, run `Start-Server.ps1 -TemporaryInternetTest` again. Check whether the public address changed. If it did, the app's server configuration needs updating and a new IPA build; don't delete the app's local data when updating. A stable public hostname/tunnel is required to avoid this for regular use.

## Permanent access

A permanent deployment needs a stable public hostname and working HTTPS routing to this PC, either directly or through an explicitly configured persistent tunnel. That setup is not provisioned here. Keep the PC awake and connected; turning it off or losing internet stops this service. Push notifications and calls remain separate work; this build relies on opening the app to sync.

References: [Synapse installation](https://element-hq.github.io/synapse/latest/setup/installation.html), [Synapse settings](https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html), [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
