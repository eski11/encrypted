# ENCPTD

An independent iPhone chat app and a server that runs directly on Windows. No Matrix account, Matrix server, Docker, WSL, or Virtual Machine Platform is used by the current application. The earlier prototype is preserved under `legacy/` and in Git history; it is not fetched or built by the current workflow.

**Status:** custom prototype. The Windows relay's integration tests pass locally. The custom iPhone build and encryption tests must pass on Codemagic's Mac, followed by a real exchange between two phones, before this replaces the installed prototype. Using libsignal is not a security audit of this application.

## Run on Windows

Extract the server ZIP to a private folder and double-click **Start-ENCPTD.cmd**. The packaged ZIP includes its Node.js 24 runtime, so Windows virtualization features and a separate Node installation are unnecessary. Keep the server window open. The owner console opens locally in your browser.

The owner console creates accounts. Choose a separate username/password for each person. It is bound only to `127.0.0.1:9752`. The phone-facing API is separate on `127.0.0.1:9751`; forwarding the phone API does not publish the owner console. No remote account signup is provided.

Use **Stop-ENCPTD.cmd** to stop the server. Close the internet connector window separately if it is open.

For an initial internet test without a domain/router configuration, double-click **Connect-Internet-Test.cmd** while the server runs. It downloads a Windows Cloudflare connector from the official GitHub release, checks the published SHA-256 digest, and creates a temporary HTTPS address. Enter that address in the phone app. Its address can change on restart. Cloudflare can observe login traffic and metadata; phone message contents use separate end-to-end encryption. This is an optional testing connection, not permanent private hosting. A stable hostname and appropriate HTTPS routing are still needed for regular use. Your PC must stay awake and online.

The native server has no production package dependencies. From source, run Node.js 24 with `node desktop/start.mjs`; test with `node --test desktop/test/*.test.mjs`. All accounts, password verifiers and queued encrypted envelopes stay in `desktop/state/`. Keep that directory and its owner token private and backed up. Server backups cannot recover lost phone encryption keys.

## Build the phone app

GitHub Actions automatically tests/builds phone-source changes on a hosted Mac. Its **ENCPTD iPhone** run saves an `ENCPTD-iPhone` artifact containing the IPA and test results. The server still runs directly on your PC; the hosted Mac is only a build machine.

Codemagic: refresh configuration on `main`, choose **ENCPTD — custom iPhone app** (`encptd-iphone`), then start a build. The workflow runs the Swift encryption/storage tests before building an unsigned IPA. Download **ENCPTD-unsigned.ipa**, sign it with Sideloadly and install it. See [INSTALL.md](INSTALL.md).

The phone app is custom SwiftUI code in `iphone/`. It uses the pinned **libsignal 0.107.0** Swift library and the matching checksum-verified binary framework for the Signal protocol. It does not use a Signal account, Signal phone-number registration or Signal's messaging servers. The library's authors do not support third-party applications; this project owns integration, updates and review. Source and binary versions are pinned together.

On the phone: unlock with Face ID/passcode, enter your own server's HTTPS address and account, add the other person's ENCPTD username, and compare the safety number on both phones through a trusted channel. Both sides must verify before messages open. Changed identity keys are not silently trusted.

## Included in this first version

- One-to-one text chat, with queued delivery when the other phone is offline.
- A separate owner console and invite-only account creation.
- PQXDH/prekey sessions and ratcheted encrypted messages through libsignal; private keys stay on each phone.
- Encrypted on-device storage, with its master key stored as `WhenUnlockedThisDeviceOnly` in the iOS Keychain.
- Durable encrypted outbox, server deduplication, and acknowledging inbox messages only after local encrypted storage succeeds.
- Phone lock on backgrounding and no plaintext notification previews.

## Current limits

One phone installation per account. No phone-key recovery/migration, attachments, group chat, push notifications or calls yet. Open the phone app to sync. Do not delete its data expecting the server to recover its keys/history. An account already paired with another installation is rejected rather than silently replacing its encryption keys.

Message encryption does not hide usernames, who communicates with whom, ciphertext sizes, traffic timing or server metadata. Recipients can read/save messages; compromised devices remain a risk. The server enforces authentication, request limits and message-envelope types, but cannot prove that an arbitrary modified client encrypted its bytes. The shipped client supplies the actual cryptography. See [PRIVACY.md](PRIVACY.md).

## License

GNU Affero General Public License. See [LICENSE](LICENSE). Preserve corresponding source when sharing modified builds. Third-party runtime and cryptographic-library licenses/notices remain applicable. Protocol/library reference: [signalapp/libsignal](https://github.com/signalapp/libsignal/tree/v0.107.0), [Swift integration](https://github.com/signalapp/libsignal/blob/v0.107.0/swift/README.md).
