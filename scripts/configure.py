"""Configure the pinned Element X source for a standalone, locally signed IPA.

This script intentionally fails if an upstream source anchor changes. Run on a
clean checkout; it never silently skips a privacy or signing modification.
"""

import re
import subprocess
import sys
from pathlib import Path

import yaml

REVISION = "975651ac92c16c346852f778da108dd249d991e5"
ROOT = Path(sys.argv[1]).resolve()


def replace(path, old, new, count=1):
    file = ROOT / path
    text = file.read_text(encoding="utf-8")
    if text.count(old) != count:
        raise RuntimeError(f"Upstream changed: {path}: expected {count} anchors")
    file.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def configure():
    revision = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != REVISION:
        raise RuntimeError("App source does not match the reviewed pinned revision")

    app_path = ROOT / "app.yml"
    app = yaml.safe_load(app_path.read_text(encoding="utf-8"))
    app["settings"].update(
        APP_DISPLAY_NAME="Encrypted",
        PRODUCTION_APP_NAME="Encrypted",
        BASE_BUNDLE_IDENTIFIER="com.eski11.encrypted",
        APP_GROUP_IDENTIFIER="group.com.eski11.encrypted",
        DEVELOPMENT_TEAM="",
        CLASSIC_APP_GROUP_IDENTIFIER="",
        CLASSIC_APP_KEYCHAIN_SERVICE_IDENTIFIER="",
        CLASSIC_APP_KEYCHAIN_ACCESS_GROUP_IDENTIFIER="",
        CLASSIC_APP_DEEP_LINK_URL="",
    )
    app_path.write_text(yaml.safe_dump(app, sort_keys=False), encoding="utf-8")

    target_path = ROOT / "ElementX/SupportingFiles/target.yml"
    target = yaml.safe_load(target_path.read_text(encoding="utf-8"))
    main = target["targets"]["ElementX"]
    # Personal signing has no shared App Groups, push service, or owned web domain.
    main["dependencies"] = [
        item for item in main["dependencies"]
        if item.get("target") not in ("NSE", "ShareExtension")
    ]
    main["entitlements"]["properties"] = {}
    for name in ("classicAppGroupIdentifier", "classicAppKeychainServiceIdentifier",
                 "classicAppKeychainAccessGroupIdentifier", "classicAppDeepLinkURL"):
        main["info"]["properties"].pop(name, None)
    # Retain checked-in generated mocks/previews. Only resource generation is needed.
    main["preBuildScripts"] = [main["preBuildScripts"][0]]
    main["postBuildScripts"] = []
    target_path.write_text(yaml.safe_dump(target, sort_keys=False), encoding="utf-8")

    secrets = ROOT / "Components/Secrets/Secrets.swift"
    secrets.write_text(
        "nonisolated enum Secrets {\n"
        + "".join(f"    static let {name}: String? = nil\n" for name in (
            "sentryDSN", "sentryRustDSN", "postHogHost", "postHogAPIKey",
            "rageshakeURL", "mapLibreAPIKey"))
        + "}\n", encoding="utf-8"
    )

    settings = "ElementX/Sources/Application/Settings/AppSettings.swift"
    replace(settings, "let appLockIsMandatory = false", "let appLockIsMandatory = true")
    replace(settings,
            "@UserPreference(defaultValue: false)\n    var hasRunNotificationPermissionsOnboarding",
            "@UserPreference(defaultValue: true)\n    var hasRunNotificationPermissionsOnboarding")
    # Custom-scheme callbacks work without Associated Domains entitlements.
    replace(settings,
            'URL(string: "https://element.io/oauth/ios/\\(InfoPlistReader.main.bundleIdentifier)")',
            'URL(string: "com.eski11.encrypted:/oauth/callback")')
    for name, old, new in (
        ("websiteURL", "https://element.io", "https://github.com/eski11/encrypted"),
        ("logoURL", "https://element.io/mobile-icon.png", "https://github.com/eski11/encrypted/raw/refs/heads/main/docs/icon.svg"),
        ("copyrightURL", "https://element.io/copyright", "https://github.com/eski11/encrypted/blob/main/LICENSE"),
        ("acceptableUseURL", "https://element.io/acceptable-use-policy-terms", "https://github.com/eski11/encrypted/blob/main/README.md"),
        ("privacyURL", "https://element.io/privacy", "https://github.com/eski11/encrypted/blob/main/PRIVACY.md"),
    ):
        replace(settings, f'var {name}: URL = "{old}"', f'var {name}: URL = "{new}"')
    replace(settings, 'var oAuthClientURIPath: String? = "apps/ios"', 'var oAuthClientURIPath: String? = nil')

    strings = ROOT / "ElementX/Resources/Localizations/en.lproj/Untranslated.strings"
    with strings.open("a", encoding="utf-8") as file:
        file.write('\n"error_encrypted_room_required" = "Sending requires an end-to-end encrypted room.";\n'
                   '"error_personal_build_feature_unavailable" = "This feature is unavailable in this personal build.";\n')

    keychain = "ElementX/Sources/Services/Keychain/KeychainController.swift"
    for name in ("restorationTokenID", "mainID"):
        replace(keychain,
                f"Keychain(service: service.{name}, accessGroup: accessGroup)",
                f"Keychain(service: service.{name}).accessibility(.whenUnlockedThisDeviceOnly)")

    # The upstream SDK remains responsible for actual encryption. Refuse outgoing
    # content before the SDK send/upload operation if room encryption is unknown/off.
    timeline = "ElementX/Sources/Services/Timeline/TimelineProxy.swift"
    replace(timeline, "private let timeline: Timeline",
            "private let timeline: Timeline\n    private let encryptionAllowed: () -> Bool")
    replace(timeline, "init(timeline: Timeline, kind: TimelineKind) {",
            "init(timeline: Timeline, kind: TimelineKind, encryptionAllowed: @escaping () -> Bool = { false }) {\n"
            "        self.encryptionAllowed = encryptionAllowed")
    path = ROOT / timeline
    text = path.read_text(encoding="utf-8")
    methods = ("edit", "sendAudio", "sendFile", "sendImage", "sendLocation", "sendVideo",
               "sendGallery", "sendVoiceMessage", "sendMessage", "sendMessageEventContent",
               "createPoll", "editPoll", "endPoll", "sendPollResponse")
    for method in methods:
        pattern = rf"(    func {method}\(.*?\) async -> Result<Void, TimelineProxyError> \{{)"
        text, count = re.subn(pattern, lambda m: m[1] +
            "\n        guard encryptionAllowed() else {\n"
            "            return .failure(.sdkError(EncryptedRoomRequired()))\n        }\n",
            text, count=1, flags=re.S)
        if count != 1:
            raise RuntimeError(f"Missing send guard anchor: {method}")
    # Matrix reactions are not guaranteed to be encrypted by the protocol/client.
    pattern = r"(    func toggleReaction\(.*?\) async -> Result<Void, TimelineProxyError> \{).*?(?=\n    func )"
    text, count = re.subn(pattern, lambda m: m[1] +
        '\n        return .failure(.sdkError(NSError(domain: "Encrypted", code: 1, userInfo: '
        '[NSLocalizedDescriptionKey: UntranslatedL10n.errorPersonalBuildFeatureUnavailable])))\n    }\n    ',
        text, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError("Missing reaction anchor")
    text += ("\nprivate nonisolated struct EncryptedRoomRequired: LocalizedError {\n"
             '    var errorDescription: String? { UntranslatedL10n.errorEncryptedRoomRequired }\n}\n')
    path.write_text(text, encoding="utf-8", newline="\n")

    joined = "ElementX/Sources/Services/Room/JoinedRoomProxy.swift"
    replace(joined, "kind: .live)",
            "kind: .live, encryptionAllowed: { room.encryptionState() == .encrypted })")
    for kind in (".detached", ".thread(rootEventID: eventID)", ".media(presentation)", ".pinned"):
        replace(joined, f"kind: {kind})",
                f"kind: {kind}, encryptionAllowed: {{ [room] in room.encryptionState() == .encrypted }})")
    # Disable live location sharing in this personal build: its room state/updates
    # are unsuitable for the encrypted-message-only scope.
    file = ROOT / joined
    text = file.read_text(encoding="utf-8")
    for method in ("startLiveLocationShare", "sendLiveLocation", "stopLiveLocationShare"):
        pattern = rf"(    func {method}\(.*?\) async -> Result<.*?, RoomProxyError> \{{)(.*?)(?=\n    func |\n    // MARK:)"
        text, count = re.subn(pattern, lambda m: m[1] +
            '\n        return .failure(.sdkError(NSError(domain: "Encrypted", code: 1, userInfo: '
            '[NSLocalizedDescriptionKey: UntranslatedL10n.errorPersonalBuildFeatureUnavailable])))\n    }\n    ',
            text, count=1, flags=re.S)
        if count != 1:
            raise RuntimeError(f"Missing live location anchor: {method}")
    file.write_text(text, encoding="utf-8", newline="\n")
    replace("ElementX/Sources/Services/Room/RoomPowerLevelProxyProtocol.swift",
            "canOwnUser(sendMessage: isEncrypted ? .roomEncrypted : .roomMessage)",
            "isEncrypted && canOwnUser(sendMessage: .roomEncrypted)")
    print("Configured Encrypted personal build; upstream encryption implementation retained.")


if __name__ == "__main__":
    configure()
