# ENCPTD setup and updates

For the project owner's existing installation, keep using the original server folder and `desktop/state/`. Its accounts, owner token and discovery signing key must stay together. Update only application code. Do not replace the state folder with an empty ZIP installation.

1. Run **Start-ENCPTD.cmd** on the Windows PC.
2. Run **Connect-Internet-Test.cmd** and keep it open. The connector publishes the signed connection automatically. The local owner console shows when it is ready.
3. In Codemagic, build `main` using **ENCPTD — custom iPhone app**. Download the new **ENCPTD-unsigned.ipa** only after the build and tests pass.
4. Sign/install the IPA using [Sideloadly](https://sideloadly.io/) on Windows with the same Apple Account and bundle identifier used for the current app. Install the update over the existing app; deleting the app can lose phone keys/history. Refresh free signing before expiry.
5. Open ENCPTD, unlock with Face ID/passcode, then **Sign in** or **Create account**. There is no server address to enter. Existing phone installations keep using their original account.
6. On both phones, add the other person's username. Compare every safety-number digit in person or over a trusted call, then confirm and exchange test messages.

The old app with a server address field needs this update. A changed temporary address is then discovered automatically without rebuilding or re-entering an address. The PC and connector must remain awake and online.

Version 0.3 requires the updated app and server together. The server rejects older plaintext API clients. Existing account and phone encryption keys are preserved; sign in again after sessions are revoked during the security upgrade. In the updated app, use **Account → Change password** to replace a password previously sent through the older Cloudflare connection. New messages expire after 24 hours; existing untimed history remains. Recording/mirroring locks the screen and inactivity locks after 60 seconds.

Keep your phone passcode set. The protected vault key is tied to this device; removing its passcode deletes that Keychain key and can make chat history unrecoverable. See [Apple's Keychain documentation](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly).

For a completely new server, run **Setup-Automatic-Connection.cmd** once before step 2. Git for Windows must already be signed in to GitHub with Gist permission. Copy only the resulting `desktop/app-config.json` to `iphone/Resources/Server.json`, commit that public configuration to your build repository, then build your app. Never copy `desktop/state/` into GitHub or a distributable ZIP.

This version pairs one phone installation with each account. Phone-key recovery, multiple devices, push notifications, calls and attachments are not implemented. A successful build still needs a real exchange between two phones and independent security review.

The owner console remains local to the PC. Do not forward port 9752 or share its private owner link/token. The internet connector forwards only the phone API on port 9751.
