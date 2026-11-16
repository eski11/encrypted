# ENCPTD

An independent iPhone chat app and a server that runs directly on Windows. No Matrix account, Matrix server, Docker, WSL, or Virtual Machine Platform is used by the current application. The earlier prototype is preserved under `legacy/` and in Git history; it is not fetched or built by the current workflow.

**Status:** custom prototype. The Windows relay's integration tests pass locally. The custom iPhone build and encryption tests must pass on Codemagic's Mac, followed by a real exchange between two phones, before this replaces the installed prototype. Using libsignal is not a security audit of this application.

## Run on Windows

Extract the server ZIP to a private folder and double-click **Start-ENCPTD.cmd**. The packaged ZIP includes its Node.js 24 runtime, so Windows virtualization features and a separate Node installation are unnecessary. Keep the server window open. The owner console opens locally in your browser.

People can choose **Create account** on their phones, or the owner can create an account in the local console. Each person uses a separate username/password. The owner console is bound only to `127.0.0.1:9752`. The phone-facing API is separate on `127.0.0.1:9751`; forwarding it does not publish the owner console. Phone signup creates ordinary chat accounts, with a global limit of 12 attempts/hour and a 100-account server cap.

Use **Stop-ENCPTD.cmd** to stop the server. Close the internet connector window separately if it is open.

Server 0.6 adds a PC-only administrator account to the owner dashboard. Create or unlock it under **Administrator messages**, select any account whose phone keys are registered, and send encrypted messages. Phone app **0.4.2** verifies the signed administrator identity automatically and shows a **Server administrator** conversation: users stay in their own accounts and can reply without adding or pairing the administrator. Older phone builds need one update for automatic delivery. Ordinary private chats still require manual safety-number verification. The dashboard cannot read messages between other accounts. See [the admin instructions](INSTALL.md#admin-dashboard-and-administrator-messages).

For an initial internet test without a domain/router configuration, double-click **Connect-Internet-Test.cmd** while the server runs. It downloads a Windows Cloudflare connector from the official GitHub release, checks the published SHA-256 digest, and creates a temporary HTTPS address. The connector updates a signed public GitHub connection file automatically, including when the address changes. The phone app has no server address field. Version 0.3 adds a separate pinned HPKE channel for credentials, session tokens, API paths, routing fields and responses, inside Cloudflare's HTTPS connection. Cloudflare still sees IP addresses, timing and padded traffic sizes. Quick Tunnels are a testing service without an uptime guarantee. Your PC must stay awake and online.

For a new server, first run **Setup-Automatic-Connection.cmd** while signed in to Git for Windows with Gist permission. It creates a public GitHub Gist and saves an Ed25519 signing key under `desktop/state/`. Copy **only** `desktop/app-config.json` to `iphone/Resources/Server.json` before building that server's app. Keep the original state directory when upgrading an existing server; creating a new signing identity requires a new app build. The shipped source configuration identifies the project owner's server.

The phone verifies the exact signed payload with its bundled public key and instance ID. Records expire after 24 hours and refresh hourly while the connector runs. Older revisions are rejected after the phone has seen a newer one. Public GitHub changes alone cannot redirect the app to an unsigned address. GitHub can observe discovery requests and retains connection-address history. [GitHub's Gist API](https://docs.github.com/en/rest/gists/gists) is used only for public connection metadata.

The connector checks the public relay before publishing a new address and then every 15 seconds. Three consecutive failed checks trigger a fresh temporary connection and an automatic signed address update. A dead connector process is restarted while its launcher remains open. Cloudflare outages, loss of internet and a sleeping/switched-off PC can still interrupt service.

The packaged native server bundles its pinned `@hpke/core` dependency and needs no separate package install. For source development, install the locked dependencies from `pnpm-lock.yaml` before running Node.js 24 with `node desktop/start.mjs`; test with `node --test desktop/test/*.test.mjs`. All accounts, password verifiers, server transport/signing keys and queued encrypted envelopes stay in `desktop/state/`. Keep that directory and its owner token private. Server backups cannot recover lost phone encryption keys.

## Build the phone app

Before another phone install, run **Run-Local-Tests.cmd** in the source checkout for disposable Windows integration checks. These exercise the server and encrypted transport; native iOS interaction and Keychain checks run on the Mac simulator/phones. See [INSTALL.md](INSTALL.md#check-before-sideloading).

An optional manual **ENCPTD iPhone** GitHub Actions workflow also saves an `ENCPTD-iPhone` artifact containing the IPA and test results, if the account permits hosted Mac jobs. The server still runs directly on your PC; the hosted Mac is only a build machine.

Codemagic: refresh configuration on `main`, choose **ENCPTD — custom iPhone app** (`encptd-iphone`), then start a build. The workflow runs the Swift encryption/storage tests before building an unsigned IPA. Download **ENCPTD-unsigned.ipa**, sign it with Sideloadly and install it. See [INSTALL.md](INSTALL.md).

The phone app is custom SwiftUI code in `iphone/`. It uses the pinned **libsignal 0.107.0** Swift library and the matching checksum-verified binary framework for the Signal protocol. It does not use a Signal account, Signal phone-number registration or Signal's messaging servers. The library's authors do not support third-party applications; this project owns integration, updates and review. Source and binary versions are pinned together.

On the phone: unlock with Face ID/passcode, choose **Sign in** or **Create account**, add the other person's ENCPTD username, and compare the safety number on both phones through a trusted channel. Both sides must verify before messages open. Changed identity keys are not silently trusted.

## Included in this first version

- One-to-one text chat, with queued delivery when the other phone is offline.
- A separate local owner console, phone signup and automatic signed server discovery.
- PQXDH/prekey sessions and ratcheted encrypted messages through libsignal; private keys stay on each phone.
- Encrypted on-device storage, with its master key protected by device passcode/biometric user presence in the iOS Keychain; an update migrates the same original vault key.
- Durable encrypted outbox, server deduplication, and acknowledging inbox messages only after local encrypted storage succeeds.
- Phone lock on backgrounding, after 60 seconds of inactivity, during detected recording/mirroring and after screenshot notification. Decrypted state is released when locked; no plaintext notification previews or chat text-selection controls.
- New messages expire locally after 24 hours. Existing history without an expiry is preserved. Expired data is pruned while the app is open or on next unlock; modified recipients can retain copies.
- Pinned HPKE request encryption and authenticated encrypted responses, replay protection, fixed outer API path and 1 KiB padding buckets. Plaintext API fallback is disabled.
- Password changes over the encrypted channel revoke other sessions. New acknowledgement receipts omit the recipient field, queued ciphertext expires after seven days, and retry records expire after 30 days.
- Obfuscated/minified Windows release scripts, randomized Swift app type names and stripped release symbols. Reviewed source remains available in this AGPL repository.
- Multiple saved accounts on one phone, each with a separate encrypted vault and optional six-digit app passcode. Account passwords alone do not bypass a saved profile's enabled app passcode.
- Per-account optional deletion after three consecutive complete wrong passcodes, or a chosen 1–365 days without an online successful passcode event. Both switches default off and require explicit confirmation in Settings.

## Current limits

One phone installation per account; multiple accounts may be saved on that phone. No cross-phone key recovery/migration, attachments, group chat, push notifications or calls yet. Open the phone app to sync. Do not delete its data expecting the server to recover its keys/history. An account already paired with another installation is rejected rather than silently replacing its encryption keys.

Use **Account → Passcode and automatic deletion** to configure a separate six-digit app code and deletion rules for the selected account. Each complete wrong code counts persistently across app restarts; a correct code resets the consecutive count. Incomplete entries do not count, and retry delays limit guessing. Security changes require the account password and, for an already protected profile, its current app code. New settings are prepared on the PC, durably saved on the phone, then confirmed on the PC before its timer activates. A pending confirmation is shown explicitly.

Deletion removes the selected phone vault key and data, plus its account, sessions, public keys and queued messages on the PC. It cannot erase other people's copies or existing backups. If the phone is offline, server deletion is queued in the protected account index and retried while the app is open online. iOS cannot guarantee scheduled execution while closed: the phone checks deadlines before opening an account; the PC checks every minute and on startup. For inactivity deletion, an online unlock must reach the PC before its deadline. Offline code entry cannot postpone a server deadline that has already expired. The same accepted unlock event cannot be replayed as a keepalive.

The server must still know accounts and route pending messages. The encrypted transport reduces what Cloudflare can inspect; it does not provide anonymity or hide all sizes/timing. Recipients can read/save messages and a compromised endpoint can expose data. The server cannot prove that an arbitrary modified client encrypted its bytes. This custom integration has not had an independent security audit. See [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md).

## License

GNU Affero General Public License. See [LICENSE](LICENSE). Preserve corresponding source when sharing modified builds. Third-party runtime and cryptographic-library licenses/notices remain applicable. Protocol/library reference: [signalapp/libsignal](https://github.com/signalapp/libsignal/tree/v0.107.0), [Swift integration](https://github.com/signalapp/libsignal/blob/v0.107.0/swift/README.md).
