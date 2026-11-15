// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit
import Security
import LocalAuthentication

final class Vault {
    let file: URL
    private let key: SymmetricKey
    private static let associatedData = Data("ENCPTD-vault-v1".utf8)

    init(file: URL, key: SymmetricKey) { self.file = file; self.key = key }
    static func applicationDirectory() throws -> URL {
        let directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("ENCPTD", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var backupURL = directory; try backupURL.setResourceValues(values)
        return directory
    }
    static func onDevice(authenticationContext: LAContext) throws -> Vault {
        let directory = try applicationDirectory()
        let file = directory.appendingPathComponent("vault.bin")
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.eski11.encptd.vault", kSecAttrAccount as String: "master-v2"]
        var legacy = query; legacy[kSecAttrAccount as String] = "master"
        var read = query; read[kSecReturnData as String] = true; read[kSecMatchLimit as String] = kSecMatchLimitOne
        read[kSecUseAuthenticationContext as String] = authenticationContext
        var result: CFTypeRef?
        let status = SecItemCopyMatching(read as CFDictionary, &result)
        let keyData: Data
        if status == errSecSuccess, let bytes = result as? Data, bytes.count == 32 { keyData = bytes }
        else if status == errSecItemNotFound {
            var oldQuery = legacy; oldQuery[kSecReturnData as String] = true
            var old: CFTypeRef?
            let oldStatus = SecItemCopyMatching(oldQuery as CFDictionary, &old)
            if oldStatus == errSecSuccess, let bytes = old as? Data, bytes.count == 32 { keyData = bytes }
            else if oldStatus == errSecItemNotFound, !FileManager.default.fileExists(atPath: file.path) {
                keyData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
            } else { throw ChatFailure(message: "The vault key is unavailable. Your existing data has not been changed.") }
            if FileManager.default.fileExists(atPath: file.path) {
                _ = try AES.GCM.open(AES.GCM.SealedBox(combined: Data(contentsOf: file)), using: SymmetricKey(data: keyData), authenticating: associatedData)
            }
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &accessError) else {
                throw ChatFailure(message: "Set a phone passcode to protect your chat encryption key.")
            }
            var insert = query; insert[kSecValueData as String] = keyData; insert[kSecAttrAccessControl as String] = access
            guard SecItemAdd(insert as CFDictionary, nil) == errSecSuccess else { throw ChatFailure(message: "Could not save your phone's encryption key.") }
            var confirmed: CFTypeRef?
            guard SecItemCopyMatching(read as CFDictionary, &confirmed) == errSecSuccess, confirmed as? Data == keyData else {
                throw ChatFailure(message: "Unlock again to confirm the protected encryption key. Existing data was preserved.")
            }
        } else { throw ChatFailure(message: "Unlock the phone to access your encrypted chats.") }
        // Remove the weaker legacy copy only after the protected key was read.
        var legacyRead = legacy; legacyRead[kSecReturnData as String] = true
        var old: CFTypeRef?
        let oldStatus = SecItemCopyMatching(legacyRead as CFDictionary, &old)
        if oldStatus == errSecSuccess {
            guard old as? Data == keyData, SecItemDelete(legacy as CFDictionary) == errSecSuccess else {
                throw ChatFailure(message: "Could not finish protecting the existing vault key. Your data was preserved.")
            }
        } else if oldStatus != errSecItemNotFound { throw ChatFailure(message: "Could not verify the old vault key.") }
        return Vault(file: file, key: SymmetricKey(data: keyData))
    }
    func migrationKey() -> Data { key.withUnsafeBytes { Data($0) } }
    static func retireLegacy(authenticationContext: LAContext) throws {
        for name in ["master", "master-v2"] {
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.eski11.encptd.vault", kSecAttrAccount as String: name, kSecUseAuthenticationContext as String: authenticationContext]
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw ChatFailure(message: "Could not finish migrating the old vault key. Existing data was preserved.") }
        }
        let file = try applicationDirectory().appendingPathComponent("vault.bin")
        if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
    }
    func load() throws -> VaultState {
        guard FileManager.default.fileExists(atPath: file.path) else { return VaultState() }
        let sealed = try AES.GCM.SealedBox(combined: Data(contentsOf: file))
        let clear = try AES.GCM.open(sealed, using: key, authenticating: Self.associatedData)
        return try JSONDecoder().decode(VaultState.self, from: clear)
    }
    func save(_ state: VaultState) throws {
        let clear = try JSONEncoder().encode(state)
        let sealed = try AES.GCM.seal(clear, using: key, authenticating: Self.associatedData)
        guard let data = sealed.combined else { throw ChatFailure(message: "Could not encrypt local storage.") }
        try data.write(to: file, options: [.atomic, .completeFileProtection])
    }
}
