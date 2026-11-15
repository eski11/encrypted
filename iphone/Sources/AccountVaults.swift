// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit
import CommonCrypto
import Security
import LocalAuthentication

struct LocalAccount: Codable, Identifiable, Equatable {
    var id: String; var accountID: String?; var username: String
}
struct AccountProtection: Codable, Equatable {
    var requirePasscode = false
    var wipeAfterThree = false
    var inactivityDays: Int?
}
struct RemoteProtection: Codable {
    var version: Int; var preparedAt: Double; var commitToken: String; var unlockToken: String; var deleteToken: String?
    var needsConfirmation: Bool? = true
    var unlockCounter: Int64? = 0
}
struct AccountDeletionJob: Codable, Identifiable {
    var accountID: String; var deleteToken: String
    var id: String { accountID }
}
struct AccountIndex: Codable {
    var version = 1
    var profiles: [LocalAccount] = []
    var activeID: String?
    var connection: VerifiedConnection?
    var discoveryRevision: Int64 = 0
    var pendingDeletes: [AccountDeletionJob] = []
    var pendingWipes: [String] = []
    var legacyImported = false
    var legacyCleanupPending = false
}
struct AccountSecret: Codable {
    var version = 1
    var rawKey: Data?
    var wrappedKey: Data?
    var salt: Data?
    var protection = AccountProtection()
    var failures = 0
    var lastSuccess: Date
    var observedTime: Date
    var retryAfter: Date?
    var remote: RemoteProtection?
    var tombstoned = false
}
enum AccountAccessError: LocalizedError {
    case needsPasscode, wrongPasscode(Int?), cooldown(Int), deleted, deletionPending
    var errorDescription: String? {
        switch self {
        case .needsPasscode: return "Enter this account's app passcode."
        case .wrongPasscode(let remaining): return remaining.map { "Wrong passcode. \($0) attempt(s) remain before permanent deletion." } ?? "Wrong passcode. Try again."
        case .cooldown(let seconds): return "Wait \(seconds) seconds before trying again."
        case .deleted: return "This account was deleted from this phone. Server deletion is queued until a connection is available."
        case .deletionPending: return "This account is locked for deletion. Removal could not finish and will be retried before it can unlock."
        }
    }
}
protocol AccountSecretStorage: AnyObject {
    func read(_ name: String) throws -> Data?
    func write(_ name: String, data: Data) throws
    func delete(_ name: String) throws
}
final class KeychainAccountSecrets: AccountSecretStorage {
    private let context: LAContext
    init(context: LAContext) { self.context = context }
    private func query(_ name: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.eski11.encptd.accounts", kSecAttrAccount as String: name]
    }
    func read(_ name: String) throws -> Data? {
        var request = query(name)
        request[kSecReturnData as String] = true; request[kSecMatchLimit as String] = kSecMatchLimitOne
        request[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let value = result as? Data else { throw ChatFailure(message: "Could not read the protected account settings. Unlock the phone and try again.") }
        return value
    }
    func write(_ name: String, data: Data) throws {
        var request = query(name); request[kSecUseAuthenticationContext as String] = context
        let status = SecItemUpdate(request as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw ChatFailure(message: "Could not save protected account settings.") }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &error) else { throw ChatFailure(message: "Keep a phone passcode enabled to protect your accounts.") }
        var insert = query(name); insert[kSecValueData as String] = data; insert[kSecAttrAccessControl as String] = control
        guard SecItemAdd(insert as CFDictionary, nil) == errSecSuccess else { throw ChatFailure(message: "Could not create protected account settings.") }
    }
    func delete(_ name: String) throws {
        var request = query(name); request[kSecUseAuthenticationContext as String] = context
        let status = SecItemDelete(request as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ChatFailure(message: "Could not finish removing this account's encryption key.") }
    }
}
enum AppPasscodeCrypto {
    static func valid(_ code: String) -> Bool { code.range(of: "^[0-9]{6}$", options: .regularExpression) != nil }
    static func derive(_ code: String, salt: Data) throws -> SymmetricKey {
        guard valid(code), salt.count == 32 else { throw ChatFailure(message: "Use exactly six digits for the app passcode.") }
        var output = Data(count: 32)
        let status = output.withUnsafeMutableBytes { target in
            salt.withUnsafeBytes { bytes in
                code.withCString { password in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, code.utf8.count,
                        bytes.bindMemory(to: UInt8.self).baseAddress!, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        600_000, target.bindMemory(to: UInt8.self).baseAddress!, 32)
                }
            }
        }
        guard status == kCCSuccess else { throw ChatFailure(message: "Could not protect the app passcode.") }
        return SymmetricKey(data: output)
    }
    static func randomKey() throws -> Data {
        var data = Data(count: 32)
        let result = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard result == errSecSuccess else { throw ChatFailure(message: "Could not generate an encryption key.") }
        return data
    }
    static func aad(_ id: String) -> Data { Data("ENCPTD-account-key-v1|\(id)".utf8) }
}

final class AccountVaults {
    let directory: URL
    private let secrets: AccountSecretStorage
    private let indexKey: SymmetricKey
    private let clock: () -> Date
    private(set) var index: AccountIndex
    private(set) var expiredRemovals = 0
    private var indexFile: URL { directory.appendingPathComponent("accounts-index.bin") }
    private static let indexAAD = Data("ENCPTD-account-index-v1".utf8)

    init(directory: URL, secrets: AccountSecretStorage, now: @escaping () -> Date = Date.init) throws {
        self.directory = directory; self.secrets = secrets; self.clock = now
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        let file = directory.appendingPathComponent("accounts-index.bin")
        let bytes: Data
        if let saved = try secrets.read("registry-key"), saved.count == 32 { bytes = saved }
        else {
            guard !FileManager.default.fileExists(atPath: file.path) else { throw ChatFailure(message: "The saved account index key is missing. Existing files were preserved.") }
            bytes = try AppPasscodeCrypto.randomKey(); try secrets.write("registry-key", data: bytes)
            guard try secrets.read("registry-key") == bytes else { throw ChatFailure(message: "Could not verify the saved account-index key.") }
        }
        indexKey = SymmetricKey(data: bytes)
        if FileManager.default.fileExists(atPath: file.path) {
            index = try JSONDecoder().decode(AccountIndex.self, from: AES.GCM.open(AES.GCM.SealedBox(combined: Data(contentsOf: file)), using: indexKey, authenticating: Self.indexAAD))
            guard index.version == 1 else { throw ChatFailure(message: "Unsupported saved account format.") }
        } else { index = AccountIndex() }
        try finishPendingWipes()
    }
    static func onDevice(context: LAContext) throws -> AccountVaults {
        let root = try Vault.applicationDirectory()
        let value = try AccountVaults(directory: root, secrets: KeychainAccountSecrets(context: context))
        if !value.index.legacyImported && FileManager.default.fileExists(atPath: root.appendingPathComponent("vault.bin").path) {
            guard value.index.profiles.isEmpty else { throw ChatFailure(message: "An older vault exists alongside saved accounts. Its data was preserved.") }
            try value.importLegacy(Vault.onDevice(authenticationContext: context))
        }
        if value.index.legacyCleanupPending {
            try Vault.retireLegacy(authenticationContext: context)
            try value.secrets.delete("legacy-import-id")
            value.index.legacyCleanupPending = false; try value.saveIndex()
        }
        try value.sweepExpired()
        return value
    }
    private func path(_ id: String) throws -> URL {
        guard UUID(uuidString: id) != nil else { throw ChatFailure(message: "Invalid saved account identifier.") }
        return directory.appendingPathComponent("account-\(id).bin")
    }
    private func name(_ id: String) -> String { "account-\(id)" }
    func saveIndex() throws {
        let data = try AES.GCM.seal(JSONEncoder().encode(index), using: indexKey, authenticating: Self.indexAAD)
        guard let bytes = data.combined else { throw ChatFailure(message: "Could not encrypt the account index.") }
        try bytes.write(to: indexFile, options: [.atomic, .completeFileProtection])
    }
    func secret(_ id: String) throws -> AccountSecret {
        _ = try path(id)
        guard let data = try secrets.read(name(id)) else { throw ChatFailure(message: "This account's protected key is missing. Its data was preserved.") }
        let value = try JSONDecoder().decode(AccountSecret.self, from: data)
        guard value.version == 1, value.failures >= 0, value.failures <= 1000000,
              (0...9_007_199_254_740_991).contains(value.remote?.unlockCounter ?? 0),
              value.protection.inactivityDays == nil || (1...365).contains(value.protection.inactivityDays!),
              value.protection.requirePasscode ? (value.rawKey == nil && value.wrappedKey?.count == 60 && value.salt?.count == 32) : (value.rawKey?.count == 32 && value.wrappedKey == nil) else { throw ChatFailure(message: "Invalid protected account settings.") }
        return value
    }
    private func write(_ id: String, _ value: AccountSecret) throws { try secrets.write(name(id), data: JSONEncoder().encode(value)) }
    func createDraft() throws -> LocalAccount {
        let id = UUID().uuidString.lowercased(), bytes = try AppPasscodeCrypto.randomKey(), now = clock()
        let profile = LocalAccount(id: id, accountID: nil, username: "New account")
        try write(id, AccountSecret(rawKey: bytes, lastSuccess: now, observedTime: now))
        let vault = Vault(file: try path(id), key: SymmetricKey(data: bytes))
        try vault.save(VaultState())
        index.profiles.append(profile); index.activeID = id; try saveIndex()
        return profile
    }
    func importLegacy(_ vault: Vault) throws {
        let state = try vault.load(), now = clock()
        let id: String
        if let data = try secrets.read("legacy-import-id"), let saved = String(data: data, encoding: .utf8), UUID(uuidString: saved) != nil { id = saved }
        else { id = UUID().uuidString.lowercased(); try secrets.write("legacy-import-id", data: Data(id.utf8)) }
        let bytes = vault.migrationKey()
        let copy = Vault(file: try path(id), key: SymmetricKey(data: bytes))
        try copy.save(state)
        guard try copy.load().identity == state.identity else { throw ChatFailure(message: "Could not verify the migrated account.") }
        try write(id, AccountSecret(rawKey: bytes, lastSuccess: now, observedTime: now))
        guard try secret(id).rawKey == bytes, try open(id).load().identity == state.identity else { throw ChatFailure(message: "Could not read back the protected migrated account key.") }
        index.profiles.append(LocalAccount(id: id, accountID: state.ownerID, username: state.login?.username ?? "Saved account"))
        index.activeID = id; index.connection = state.connection; index.discoveryRevision = state.discoveryRevision ?? 0
        index.legacyImported = true; index.legacyCleanupPending = true; try saveIndex()
    }
    func select(_ id: String) throws {
        guard index.profiles.contains(where: { $0.id == id }) else { throw ChatFailure(message: "Saved account not found.") }
        index.activeID = id; try saveIndex()
    }
    func bind(_ id: String, accountID: String, username: String) throws {
        guard let position = index.profiles.firstIndex(where: { $0.id == id }) else { throw ChatFailure(message: "Saved account not found.") }
        guard !index.profiles.contains(where: { $0.id != id && $0.accountID == accountID }) else { throw ChatFailure(message: "This account is already saved on this phone. Switch to its saved profile.") }
        index.profiles[position].accountID = accountID; index.profiles[position].username = username; try saveIndex()
    }
    func saveConnection(_ connection: VerifiedConnection) throws {
        index.connection = connection; index.discoveryRevision = max(index.discoveryRevision, connection.revision); try saveIndex()
    }
    private func overdue(_ secret: AccountSecret, now: Date) -> Bool {
        secret.protection.inactivityDays.map { now.timeIntervalSince(secret.lastSuccess) >= Double($0) * 86400 } ?? false
    }
    func sweepExpired() throws {
        for profile in index.profiles {
            var record = try secret(profile.id)
            let now = max(clock(), record.observedTime)
            if record.tombstoned || overdue(record, now: now) { try destroy(profile.id); expiredRemovals += 1; continue }
            record.observedTime = now; try write(profile.id, record)
        }
    }
    func open(_ id: String, passcode: String? = nil) throws -> Vault {
        var record = try secret(id)
        let now = max(clock(), record.observedTime)
        if record.tombstoned || overdue(record, now: now) {
            do { try destroy(id) } catch { throw AccountAccessError.deletionPending }
            throw AccountAccessError.deleted
        }
        record.observedTime = now
        let key: Data
        if record.protection.requirePasscode {
            guard let passcode else { throw AccountAccessError.needsPasscode }
            guard AppPasscodeCrypto.valid(passcode) else { throw ChatFailure(message: "Enter all six digits. An incomplete code does not count as an attempt.") }
            if let until = record.retryAfter, until > now { throw AccountAccessError.cooldown(Int(ceil(until.timeIntervalSince(now)))) }
            let box = try AES.GCM.SealedBox(combined: record.wrappedKey!)
            let pinKey = try AppPasscodeCrypto.derive(passcode, salt: record.salt!)
            do { key = try AES.GCM.open(box, using: pinKey, authenticating: AppPasscodeCrypto.aad(id)) }
            catch CryptoKitError.authenticationFailure {
                record.failures = min(record.failures + 1, 1000000)
                record.retryAfter = now.addingTimeInterval(min(300, pow(2, Double(min(record.failures, 8)))))
                if record.protection.wipeAfterThree && record.failures >= 3 { record.tombstoned = true }
                try write(id, record) // Count the complete wrong attempt before returning.
                if record.tombstoned {
                    do { try destroy(id) } catch { throw AccountAccessError.deletionPending }
                    throw AccountAccessError.deleted
                }
                throw AccountAccessError.wrongPasscode(record.protection.wipeAfterThree ? 3 - record.failures : nil)
            }
            record.failures = 0; record.retryAfter = nil; record.lastSuccess = now
            if record.remote != nil {
                let counter = record.remote?.unlockCounter ?? 0
                guard counter < 9_007_199_254_740_991 else { throw ChatFailure(message: "Unlock counter limit reached. Update the account security settings.") }
                record.remote?.unlockCounter = counter + 1
            }
        } else { key = record.rawKey! }
        guard key.count == 32 else { throw ChatFailure(message: "Invalid account encryption key.") }
        try write(id, record)
        return Vault(file: try path(id), key: SymmetricKey(data: key))
    }
    func configure(_ id: String, vault: Vault, protection: AccountProtection, passcode: String?, remote: RemoteProtection) throws {
        guard vault.file.standardizedFileURL == (try path(id)).standardizedFileURL else { throw ChatFailure(message: "The encryption vault does not belong to this saved account.") }
        guard protection.requirePasscode || (!protection.wipeAfterThree && protection.inactivityDays == nil) else { throw ChatFailure(message: "Enable an app passcode before enabling automatic deletion.") }
        var record = try secret(id)
        let now = max(clock(), record.observedTime), key = vault.migrationKey()
        if protection.requirePasscode {
            guard let passcode, AppPasscodeCrypto.valid(passcode) else { throw ChatFailure(message: "Choose a six-digit app passcode.") }
            let salt = try AppPasscodeCrypto.randomKey()
            let wrapped = try AES.GCM.seal(key, using: AppPasscodeCrypto.derive(passcode, salt: salt), authenticating: AppPasscodeCrypto.aad(id))
            record.rawKey = nil; record.salt = salt; record.wrappedKey = wrapped.combined
        } else { record.rawKey = key; record.wrappedKey = nil; record.salt = nil }
        record.protection = protection; record.remote = remote; record.failures = 0; record.retryAfter = nil
        record.lastSuccess = now; record.observedTime = now
        try write(id, record)
    }
    func markConfirmed(_ id: String) throws {
        var record = try secret(id); record.remote?.needsConfirmation = false; try write(id, record)
    }
    func settingsUnlockEvent(_ id: String) throws -> Int64? {
        var record = try secret(id)
        guard record.remote != nil else { return nil }
        let value = (record.remote?.unlockCounter ?? 0) + 1
        guard value <= 9_007_199_254_740_991 else { throw ChatFailure(message: "Unlock counter limit reached.") }
        record.remote?.unlockCounter = value; try write(id, record)
        return value
    }
    func destroy(_ id: String) throws {
        var record = try secret(id)
        record.tombstoned = true; try write(id, record)
        if let account = index.profiles.first(where: { $0.id == id }), let accountID = account.accountID,
           let deletionToken = record.remote?.deleteToken, !index.pendingDeletes.contains(where: { $0.accountID == accountID }) {
            index.pendingDeletes.append(AccountDeletionJob(accountID: accountID, deleteToken: deletionToken))
        }
        if !index.pendingWipes.contains(id) { index.pendingWipes.append(id) }
        index.profiles.removeAll { $0.id == id }
        if index.activeID == id { index.activeID = nil }
        try saveIndex()
        try finishPendingWipes()
    }
    private func finishPendingWipes() throws {
        for id in index.pendingWipes {
            try secrets.delete(name(id))
            let file = try path(id)
            if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
            index.pendingWipes.removeAll { $0 == id }; try saveIndex()
        }
    }
    func acknowledgeDeletion(_ accountID: String) throws {
        index.pendingDeletes.removeAll { $0.accountID == accountID }; try saveIndex()
    }
}
