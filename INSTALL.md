# ENCPTD setup and updates

For the project owner's existing installation, keep using the original server folder and `desktop/state/`. Its accounts, owner token and discovery signing key must stay together. Update only application code. Do not replace the state folder with an empty ZIP installation.

1. Run **Start-ENCPTD.cmd** on the Windows PC.
2. Run **Connect-Internet-Test.cmd** and keep it open. The connector publishes the signed connection automatically. The local owner console shows when it is ready.
3. In Codemagic, build `main` using **ENCPTD — custom iPhone app**. Download the new **ENCPTD-unsigned.ipa** only after the build and tests pass.
4. Sign/install the IPA using [Sideloadly](https://sideloadly.io/) on Windows with the same Apple Account and bundle identifier used for the current app. Install the update over the existing app; deleting the app can lose phone keys/history. Refresh free signing before expiry.
5. Open ENCPTD, unlock with Face ID/passcode, then **Sign in** or **Create account**. There is no server address to enter. Existing phone installations keep using their original account.
6. Set an app passcode in **Account → Passcode and automatic deletion** on each phone (automatic deletion can stay off). Add the other person's username, then enter your app passcode to reveal the safety number. Compare the complete number in person or over a trusted call, then confirm and exchange test messages.

The old app with a server address field needs this update. A changed temporary address is then discovered automatically without rebuilding or re-entering an address. The PC and connector must remain awake and online.

Version 0.3 requires the updated app and server together. The server rejects older plaintext API clients. Existing account and phone encryption keys are preserved; sign in again after sessions are revoked during the security upgrade. In the updated app, use **Account → Change password** to replace a password previously sent through the older Cloudflare connection. New messages expire after 24 hours; existing untimed history remains. Recording/mirroring locks the screen and inactivity locks after 60 seconds.

Keep your phone passcode set. The protected vault key is tied to this device; removing its passcode deletes that Keychain key and can make chat history unrecoverable. See [Apple's Keychain documentation](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly).

Version 0.4 adds **Switch or add account** in the account menu and **Passcode and automatic deletion** in Account settings. Install over the existing app so the original identity/history can migrate into its own account vault. Each account can enable a separate six-digit app code, deletion after three consecutive wrong complete codes, and/or an inactivity period of 1–365 days. All deletion rules start off. Read and confirm the permanent-deletion warning before enabling them. There is no forgotten-app-code recovery for the encrypted vault.

With inactivity deletion enabled, connect the phone and PC before the deadline so a successful app-code event reaches the server. PC deletion is enforced while the server runs or at next startup. A closed iOS app wipes locally before its next unlock, not at a guaranteed background execution time. Offline wrong-code deletion wipes locally and queues the PC request until the app is open online. The rule applies only to the selected account, not other saved accounts on the phone.

For a completely new server, run **Setup-Automatic-Connection.cmd** once before step 2. Git for Windows must already be signed in to GitHub with Gist permission. Copy only the resulting `desktop/app-config.json` to `iphone/Resources/Server.json`, commit that public configuration to your build repository, then build your app. Never copy `desktop/state/` into GitHub or a distributable ZIP.

This version pairs one phone installation with each account. Phone-key recovery, multiple devices, push notifications, calls and attachments are not implemented. A successful build still needs a real exchange between two phones and independent security review.

The owner console remains local to the PC. Do not forward port 9752 or share its private owner link/token. The internet connector forwards only the phone API on port 9751.

## Check before sideloading

In the source checkout, double-click **Run-Local-Tests.cmd**. It requires Node.js 24 and the locked source dependencies (`pnpm install --frozen-lockfile --ignore-scripts`). It tests disposable accounts and temporary local servers/databases, including pinned encrypted transport, authentication, settings confirmation, replay rejection and deletion policies. It never targets your running chat server. This is data separation on the same Windows host, not a sandbox against hostile code.

Windows cannot run the iOS app or Apple's iOS simulator. Codemagic runs the Swift encryption/vault/polling tests on a Mac simulator before producing the IPA; download the test log first if you want to inspect results before signing. Native typing, screen locking and device Keychain behaviour still need checks on the phones. Update over the installed app with the same signing identity; do not uninstall as a troubleshooting step.

Version 0.4.1 keeps background polling independent of the foreground busy state, preserves security-form edits across reappearances, and reports a successful save only after server confirmation. Failed saves keep the entered fields for correction. Confirm that settings remain selected after leaving Settings and after locking/unlocking.

Safety numbers are now hidden behind the selected account's app passcode and concealed when leaving the screen or when the app becomes inactive. Wrong complete codes on this screen count toward an enabled three-attempt deletion rule. The screen checks this phone's identity against its published key and fetches the other account's current key; it never automatically trusts a changed key. Both accounts viewing each other must display the same complete 60-digit number. Refresh the lookup on both phones, check the displayed usernames, and compare every group. If they still differ, leave the contact unverified and investigate; do not approve the mismatch, delete the app or reset phone keys to force a match.

## Admin dashboard and administrator messages

Open **Start-ENCPTD.cmd** in your existing server folder. The panel lists usernames, whether the phone has registered its encryption keys, and queued encrypted envelopes. Search, create phone accounts, or use **Sign out** to revoke an account's sessions without deleting it. An account marked **Open phone app once** has no published recipient key yet and cannot receive encrypted messages until it signs into the app.

1. Under **Administrator messages**, create a new username (for example `encptd_pc`) and a unique 12+ character passphrase, or unlock your existing PC account. This account belongs only to the panel. **Do not sign into it on a phone.** Version 0.6 explicitly blocks its login through the phone API.
2. Select any account marked **App ready**, type a message and click **Send encrypted message**. Administrator messaging uses the device key registered with this server; a previously pinned key that changes is blocked for inspection. Safety-number inspection remains optional for the administrator.
3. With **phone app 0.4.2**, each phone stays signed into its own account, verifies the administrator certificate against the server signing key already pinned in the app, and adds the **Server administrator** conversation automatically. Users can read and reply without adding a contact, comparing an admin safety number, or pairing the administrator account to a phone. Ordinary conversations retain manual safety-number verification.
4. **Older installed phone builds need one update for automatic delivery.** In Codemagic build `main` with **ENCPTD - custom iPhone app**, let its tests pass, then install the 0.4.2 IPA over the existing app using the same signing identity. An old build cannot be made to accept an unknown sender remotely. Do not uninstall or reset phone keys.
5. **Lock chat** hides the panel's conversations. Administrator messaging also locks after five minutes without a user action and when this page closes. Reload requires the same passphrase; the account list stays available to the owner. Background polling does not extend the timer.

The encrypted PC vault remains `desktop/state/pc-chat.vault.json`. Its private keys, sessions, messages and outgoing queue use scrypt (N=32768,r=8,p=1), AES-256-GCM and atomic file replacement. Keep this file and passphrase across updates; there is no key recovery. If you already created the PC account on 0.5, unlock that same account after upgrading to designate it as the administrator. Do not create a replacement or log into it on a phone.

Administrator certificates contain only the designated account ID, username, public Signal key, revision, server instance and validity times. They are domain-separated Ed25519 signatures, expire after one hour, and reject previously seen revision rollback. A username alone never grants a role. A signed role revocation removes automatic trust and its old Signal session. This PC remains the administrator conversation endpoint and can see messages addressed to it while unlocked; it cannot decrypt private conversations between other accounts.

The Windows x64 package includes pinned native libsignal 0.107.0 without a VM or additional build tools. Administrator and normal messages use the same Signal ciphertext format. Automated tests and a browser exchange are not an independent security audit; the new Swift certificate and Node-to-Swift decryption tests must also pass on Codemagic and be checked on the phones.
