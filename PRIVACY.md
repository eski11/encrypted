# ENCPTD data handling

The current ENCPTD service is an independent custom server running on the owner's Windows PC. It does not use Matrix or Signal messaging services/accounts. Signal's libsignal library implements phone-to-phone encryption locally in the app.

The server stores usernames, salted scrypt password verifiers, hashed authentication tokens, public encryption-key bundles, routing metadata and queued ciphertext. It does not receive phone private keys or message text from the shipped client. Acknowledged messages are removed from the active queue; SQLite/WAL backups and storage media may retain historical ciphertext/metadata. Authentication/routing metadata remains visible to the server owner. Device and recipient compromise are outside message encryption's protection.

The owner console is separate from the phone API and binds only to this PC's loopback interface. Its private owner token is stored under `desktop/state/`; anyone with that token and local access can create accounts. Protect the Windows login and that directory. No credential, token, real database or message history belongs in GitHub/Codemagic.

The optional Cloudflare Quick Tunnel exposes the phone API over a temporary HTTPS address. Cloudflare terminates TLS and can observe login credentials, API traffic and metadata, while message contents have a separate layer of end-to-end encryption supplied by the phones. It has no production uptime guarantee. This option is not suitable if the requirement forbids any third-party network intermediary. A different stable HTTPS deployment is separate work.

Phone keys, session records and local message history are saved in an AES-GCM encrypted vault. Its master key uses the iOS Keychain's `WhenUnlockedThisDeviceOnly` setting and is not sent to the server. Phone-key recovery and multiple-phone use are not implemented in this first version.

GitHub and Codemagic process the source/build configuration, and Apple/Sideloadly handle personal app signing separately. They do not need real chat accounts, passwords or encryption keys for this build. The custom app has no analytics or automatic crash-upload service. It still needs successful cloud tests, real-device testing and independent review before security claims beyond the implemented design are justified.
