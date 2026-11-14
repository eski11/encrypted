# Install on your iPhone from Windows

Only continue after the Codemagic build succeeds and creates `Encrypted-unsigned.ipa`. An unsigned IPA will not install directly on a normal iPhone.

1. Download Sideloadly from **https://sideloadly.io/**. Follow its current Windows prerequisites, including the versions of Apple's iTunes/iCloud it requests. Use official download links.
2. Connect your iPhone with USB, unlock it and choose **Trust** if prompted.
3. Open Sideloadly, choose your device and drag in `Encrypted-unsigned.ipa`.
4. Sign using your own Apple Account through Sideloadly. Keep credentials on your own computer; do not send them to this chat or add them to GitHub/Codemagic.
5. Complete any iPhone developer-trust/Developer Mode steps requested by iOS. These depend on the signing method and iOS version.
6. Open **Encrypted**, sign in to a supported Matrix provider, complete device verification/recovery and set the app PIN.

Free Apple signing normally lasts seven days. Refresh before expiry using Sideloadly. Keep the same Apple account and app bundle identifier when refreshing; avoid deleting the app because that can remove local message/cryptographic state. Keep an encrypted recovery backup/recovery key available through your provider and verify recovery before relying on it.

This build omits push notifications and sharing extensions. Opening the app is the reliable way to sync. It still needs real-device testing, including a message exchange between two verified accounts and a restart/re-signing check. Installing a successful build does not establish that every feature works or that the fork has been audited.

If Codemagic fails, open the failed step, download `xcodebuild.log` from artifacts and bring the error to the Codex chat. Do not share logs containing account identifiers publicly.
