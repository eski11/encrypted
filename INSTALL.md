# ENCPTD first setup

1. Run **Start-ENCPTD.cmd** on the Windows PC. The owner console opens in the browser. Create an account for each person, with a separate password.
2. For a temporary internet connection, run **Connect-Internet-Test.cmd**. Keep it open and note its HTTPS address. The owner console shows it after refreshing through the launcher. This connector is optional and contacts Cloudflare; see the privacy notes.
3. Run the **ENCPTD — custom iPhone app** workflow in Codemagic. It must pass its tests and create **ENCPTD-unsigned.ipa**. The old `Encrypted-unsigned.ipa` is the earlier prototype and does not connect to this custom server.
4. Sign/install the new IPA using [Sideloadly](https://sideloadly.io/) on Windows with your own Apple Account. Refresh free signing before its usual seven-day expiry. Keep the same signing account and bundle identifier for updates.
5. Open ENCPTD, unlock with Face ID/passcode, and enter the server address and your ENCPTD username/password. Accounts are made in the PC owner console; no third-party chat account is involved.
6. On both phones, add the other person's username. Compare the entire safety number through a trusted channel. Confirm only if every digit matches. Then exchange test messages and test closing/reopening the apps.

This first version has one phone installation per account and no key-recovery flow. Do not delete app data to troubleshoot without understanding that the phone's encryption keys can be lost. A successful build is not a completed real-device or security review.

If the temporary server URL changes, use **Server connection** inside ENCPTD and sign in again at the new address. Existing encryption state is kept only for the same account ID. The custom app handles a changed connection address without needing a fresh build.

The server owner's browser page is local only. Do not forward port 9752 or share its private owner link/token. The internet connector forwards only the phone API on port 9751.
