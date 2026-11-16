# ENCPTD security status

This is a custom prototype with an unaudited application integration. No claim of impossible interception, anonymity, screenshot prevention, forensic erasure or resistance to a compromised phone/PC is made. Library use, successful tests and obfuscation do not replace an independent security audit.

The 0.5 admin dashboard is local-only, authenticated with the owner token, protected by Host/Origin checks and a restrictive content security policy. Account responses omit credentials, password verifiers and message bodies. PC chat additionally requires its vault passphrase and a per-unlock session token; ordinary chat tokens cannot administer the server, and owner tokens cannot decrypt a locked PC vault. PC chat is its own libsignal endpoint, not an interception facility. Its keys/history use an AES-256-GCM encrypted file with a scrypt-derived key and atomic replacement. Explicit safety-number trust is required before sending/decrypting, changed keys are never auto-trusted, and outgoing ratchet state plus ciphertext are persisted before relay submission. Received ratchet state is persisted before acknowledgement. The unlocked Windows process/browser necessarily sees this endpoint's messages; memory erasure and a malicious/compromised host are outside the guarantee.

## Protected transport (0.3)

The phone pins the PC's P-256 public key in its build configuration. Requests use RFC 9180 HPKE base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. The server uses pinned `@hpke/core` 1.10.1; the phone uses Apple's CryptoKit HPKE. Each request creates a fresh encapsulation and a fresh reply key. The request carries its UUID, timestamp, method, inner path, optional bearer token, body and reply public key inside encryption.

Responses use HPKE authenticated mode with the PC's private key, the per-request reply public key and a context bound to the instance ID and request UUID. The phone authenticates them using the pinned PC public key. Responses and API errors are encrypted. Outer business responses always use HTTP 200. Transport errors disclose no account data. HTTP redirects and plaintext fallback are disabled.

Both sides authenticate the versioned transport context, prefix JSON with its big-endian byte length, and pad to 1 KiB blocks before sealing. The server accepts request timestamps within two minutes, persists replay IDs for four minutes, limits decryption concurrency, caps bodies and applies existing authentication/KDF/rate limits. Clocks need to be reasonably correct. Malicious intermediaries can still block traffic and perform size/timing analysis. A stolen transport key can expose recorded requests; this layer is not a claim of transport forward secrecy.

Phone-to-phone messages retain their separate libsignal encryption and manual safety-number verification. Do not bypass that comparison. The PC still knows accounts and routes ciphertext; hiding that metadata from the server would require a different architecture.

## Device and retention measures

The encrypted vault key requires passcode/biometric user presence and stays on the phone. Existing keys are migrated without changing the vault's encryption key. Backgrounding, loss of protected-data access, inactivity or detected recording/mirroring locks the app and releases decrypted state. A generation check discards network completions from before a lock. ARC/runtime copies and malicious code on a compromised endpoint remain outside those guarantees.

Screenshot notification is after-the-fact. Screen recording protection uses supported OS capture signals, not undocumented secure-text-field hacks. Someone can still photograph the display. New messages expire after 24 hours in compliant apps; old untimed history remains. The relay's seven-day queue and 30-day retry-record limits reduce retention. Existing copies, device backups and modified recipients can retain data.

## Per-account passcodes and opt-in deletion (0.4)

The account index and each account vault have independent keys. A saved account's six-digit app code wraps only its own master key using PBKDF2-HMAC-SHA256 (600,000 iterations, random 32-byte salt) and AES-GCM bound to its local UUID. The device Keychain adds passcode/biometric user-presence protection. Switching/signing into a saved account still requires its enabled app code; a new account gets fresh keys. The legacy vault is read back through its new protected account record before legacy key removal. Interrupted migration uses a stable journal ID, preventing duplicate legacy-key copies from repeated attempts.

Wrong complete codes increment a durable Keychain counter before returning. A correct code resets the consecutive count. If the explicit three-failure rule is enabled, a tombstone is saved, a narrowly scoped server-deletion job is durably queued, and that account key and file are removed. Failure to complete storage removal stays locked/tombstoned for retry. Other account keys remain independent. App-level counters and clocks cannot promise resistance to a compromised phone OS or external rollback, and deletion cannot guarantee forensic erasure of hardware/backups.

Inactivity is 1–365 days, chosen by the user. It is separate from the three-attempt switch; both default off. The PC records a signed, versioned nonce challenge and monotonically increasing successful-unlock counter. Replayed event counters do not move the deadline. The proof key is inside the account vault, not the public index. Password plus a short-lived saved-device proof are required to replace configured security policies. Ordinary message polling and password login are not PIN events. Preparation is non-destructive; server rules activate only after the phone commits its Keychain record and confirms using a one-time capability. Confirmation retries do not reset the deadline.

The phone cannot be guaranteed to execute while iOS has suspended/closed it, so it checks before vault decryption and during active use. The PC checks at startup and once per minute. Deletion triggered offline is queued for later online delivery. A server inactivity deadline requires online proof before expiry; local offline entries cannot renew it retroactively. Capability revocation and account UUID binding prevent old deletion requests affecting a replacement account with the same username. Users must explicitly accept permanent data loss before enabling these rules.

## Release obfuscation

Windows packaging obfuscates first-party JavaScript, bundles the locked HPKE implementation, minifies identifiers and ships no source maps. The owner-console script is obfuscated too. iPhone Release builds randomize app type names in a generated source copy and strip symbols/reflection names. Codable properties, wire names, selectors and cryptographic calls are preserved. Debug tests run against readable source; independent CryptoKit interoperability fixtures run before the release build. Real-device testing of the obfuscated app is still required.

Source is available under AGPL. Obfuscation is an inspection obstacle, not a confidentiality or cryptographic guarantee.

## Validation

Node integration tests exercise encrypted signup/login/password changes, response authentication, tampering, replay rejection, plaintext downgrade rejection, owner isolation, message deduplication and retention. The same suite can run against the obfuscated server using `ENCPTD_TEST_SERVER_MODULE`. Swift tests include Node-generated HPKE interoperability fixtures, local-vault tampering and libsignal round trips. Swift/device checks require Codemagic's Mac and actual phones; Windows checks do not establish their results.

References: [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), [CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke), [hpke-js](https://github.com/dajiaji/hpke-js), [Apple screen-capture notification](https://developer.apple.com/documentation/uikit/uiscreen/captureddidchangenotification).
