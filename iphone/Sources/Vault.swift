// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit
import Security

final class Vault {
    let file: URL
    private let key: SymmetricKey
    private static let associatedData = Data("ENCPTD-vault-v1".utf8)

    init(file: URL, key: SymmetricKey) { self.file = file; self.key = key }
    static func onDevice() throws -> Vault {
        let directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("ENCPTD", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var backupURL = directory; try backupURL.setResourceValues(values)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.eski11.encptd.vault", kSecAttrAccount as String: "master"]
        var read = query; read[kSecReturnData as String] = true; read[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(read as CFDictionary, &result)
        let keyData: Data
        if status == errSecSuccess, let bytes = result as? Data, bytes.count == 32 { keyData = bytes }
        else if status == errSecItemNotFound {
            guard !FileManager.default.fileExists(atPath: directory.appendingPathComponent("vault.bin").path) else { throw ChatFailure(message: "The vault key is unavailable. Your existing data has not been changed.") }
            keyData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
            var insert = query; insert[kSecValueData as String] = keyData; insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            guard SecItemAdd(insert as CFDictionary, nil) == errSecSuccess else { throw ChatFailure(message: "Could not save your phone's encryption key.") }
        } else { throw ChatFailure(message: "Unlock the phone to access your encrypted chats.") }
        return Vault(file: directory.appendingPathComponent("vault.bin"), key: SymmetricKey(data: keyData))
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
