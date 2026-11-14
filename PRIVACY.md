# Data handling for the personal Encrypted build

Encrypted is a personal fork of Element X, not a separate hosted messaging service. The app connects to the Matrix provider you select. That provider receives your account/login activity, network address, room membership and protocol metadata. End-to-end encrypted message contents are handled by the upstream Matrix Rust SDK. Encryption does not conceal room state, profiles or traffic timing.

The personal configuration sets the app's PostHog, Sentry, bug-report upload and map-service credentials to nil. It does not provide a push gateway or upload app data to a service run by this project's author. Optional protocol features and links may contact services selected by your Matrix provider or the upstream client. Review those services separately before enabling them.

The app stores session secrets in the iOS Keychain. Message caches and encryption databases use the upstream client's local storage. Device access, operating-system compromise, unlocked screens and screenshots remain outside the protection supplied by message encryption.

GitHub and Codemagic receive the source and configuration needed for builds. No account passwords, chat recovery keys, real messages or Apple signing credentials belong in this repository or in the unsigned Codemagic workflow. Sideloadly is separate software with its own policies and handles the Apple Account used for personal signing.

Use the selected Matrix provider's privacy policy for its account and server processing. This prototype's authentication and data handling have not yet been independently reviewed or verified on a real device.
