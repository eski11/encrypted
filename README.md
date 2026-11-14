# Encrypted — personal iPhone build

A personal sideloading configuration of [Element X iOS](https://github.com/element-hq/element-x-ios), using its Matrix Rust SDK encryption and verification implementation. This is an initial fork/build setup, not a newly audited messenger or a completed security assessment.

The `App` submodule pins Element X release `26.11.0`, commit `975651ac92c16c346852f778da108dd249d991e5`. The upstream sources and licenses remain available through that exact source link. `scripts/configure.py` contains the modifications applied during the build. The private Enterprise submodule is not used or fetched.

## Build in Codemagic

1. On the Codemagic app settings page, select `main` and click **Check for configuration files**.
2. Select **Encrypted — iPhone IPA for Sideloadly** (`iphone-unsigned`).
3. Click **Start new build**. Use the macOS workflow; Xcode runs in the cloud.
4. When it succeeds, download `Encrypted-unsigned.ipa` from the build's artifacts.
5. Follow [INSTALL.md](INSTALL.md) to sign and install it from Windows.

No Apple login, signing certificate, App Store Connect key, or paid Apple membership is needed by this unsigned workflow. Codemagic build minutes/eligibility depend on your account. The first build downloads substantial SDK dependencies and can take a while.

## What this configuration changes

- App name `Encrypted` and bundle ID `com.eski11.encrypted`.
- Removes the push and share extensions and associated domain/App Group entitlements for personal sideloading.
- Stores secrets in the app's own Keychain with `whenUnlockedThisDeviceOnly` accessibility. Uses upstream's private-container fallback when App Groups are unavailable.
- Sets analytics, Sentry, automatic bug reporting and map API credentials to `nil`.
- Makes the existing app PIN setup mandatory with no background grace period.
- Refuses message, attachment and poll sends when the SDK reports that a room is unencrypted or encryption status is unknown. The UI also disables normal message composition in unencrypted rooms. Existing plaintext rooms/history can still be displayed.
- Disables reaction sends and live location publishing; these are outside this build's encrypted message scope.
- Uses an OAuth custom scheme callback, since the personal build cannot claim Element's associated domain.

## Account and first conversation

Use an existing **Matrix** account on a provider that supports Element X / Simplified Sliding Sync. You and the other person need Matrix accounts; you do not need a new custom server for this first version. They can use an official Matrix client.

Sign in, complete device verification (or encrypted recovery), set an app PIN, then start a new encrypted direct conversation. Verify the other person's identity through a trusted channel. Keep your recovery key somewhere safe; do not commit it to this repository.

Authentication compatibility, device signing, real encrypted sends, session restoration, media, app-lock behavior and re-signing still need verification on an iPhone. Some providers impose additional OAuth client-registration restrictions on custom app forks. OAuth app metadata points to this repository; providers that fetch the metadata may reject private repository URLs. In that case the project needs a public metadata/privacy page, without exposing any credentials. If login rejects the custom callback, a provider/domain configuration change is required; do not bypass verification or TLS to work around it.

## Limits of this first build

- No working remote push service: expect to open the app to reliably receive new messages. Do not depend on background delivery or calls yet.
- Location maps have no API key. Share extension is omitted.
- This preserves much of Element's existing UI/graphics and help content; it is not affiliated with Element and has not received an independent review of these changes.
- End-to-end encryption protects supported encrypted message contents, not account profiles, room names/state, membership, server-visible IPs/timestamps, compromised phones, or recipients' screenshots. Public/unencrypted history is not made private retroactively.
- The provider's policies apply to its service. See [PRIVACY.md](PRIVACY.md) for the build and data handling details.

## Source and license

This fork and the upstream source are available under the GNU Affero General Public License. See [LICENSE](LICENSE) and the notices in `App`. When sharing builds, provide recipients the corresponding source (the pinned upstream source, these modifications and build scripts) under that license. The repo can remain private for personal work; recipients must still be able to obtain the required source when you distribute it.

Fetch the public app submodule without recursing into the private Enterprise submodule:

```sh
git clone https://github.com/eski11/encrypted.git
cd encrypted
GIT_LFS_SKIP_SMUDGE=1 git submodule update --init App
git -C App lfs pull --include="Components/DevelopmentAssets/Media/**" --exclude=""
```

On macOS, install Xcode 27.2, XcodeGen and SwiftGen, install `requirements-build.txt` in a Python virtual environment, run `python scripts/configure.py App` on a clean pinned source checkout, then run `xcodegen generate` inside `App`. The Codemagic workflow contains the exact build command. Never commit passwords, `.p8`/`.p12` files, recovery keys or user message data.
