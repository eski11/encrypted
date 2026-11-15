import XCTest
import CryptoKit
@testable import ENCPTD

private final class MemoryAccountSecrets: AccountSecretStorage {
    var data: [String: Data] = [:]
    var failDeletion = false
    var failWrites = false
    func read(_ name: String) throws -> Data? { data[name] }
    func write(_ name: String, data value: Data) throws {
        if failWrites { throw ChatFailure(message: "simulated Keychain write failure") }
        data[name] = value
    }
    func delete(_ name: String) throws {
        if failDeletion { throw ChatFailure(message: "simulated Keychain deletion failure") }
        data.removeValue(forKey: name)
    }
}
private final class AccountTestClock { var now = Date(timeIntervalSince1970: 1_900_000_000) }

final class AccountVaultTests: XCTestCase {
    func testPasscodeDerivationMatchesIndependentPBKDF2Vector() throws {
        let key = try AppPasscodeCrypto.derive("123456", salt: Data((0..<32).map { UInt8($0) }))
        let bytes = key.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes, Data(base64Encoded: "Og2XL/MacyJKrVys5TAPo4kpZX/Go2ZCsW8wqejDqt0="))
    }
    private func temporary() throws -> URL {
        let value = FileManager.default.temporaryDirectory.appendingPathComponent("encptd-accounts-\(UUID().uuidString)", isDirectory: true)
        XCTAssertTrue(value.standardizedFileURL.path.hasPrefix(FileManager.default.temporaryDirectory.standardizedFileURL.path))
        try FileManager.default.createDirectory(at: value, withIntermediateDirectories: true)
        return value
    }
    private func remote(_ clock: AccountTestClock) -> RemoteProtection {
        RemoteProtection(version: 1, preparedAt: clock.now.timeIntervalSince1970 * 1000, commitToken: String(repeating: "c", count: 43), unlockToken: String(repeating: "u", count: 43), deleteToken: String(repeating: "d", count: 43))
    }
    private func named(_ registry: AccountVaults, _ username: String) throws -> (LocalAccount, Vault, Data) {
        let draft = try registry.createDraft(), vault = try registry.open(draft.id)
        var state = try vault.load(); let id = UUID().uuidString.lowercased()
        state.ownerID = id; state.login = LoginSession(id: id, username: username, token: String(repeating: "t", count: 43), serverURL: "https://example.trycloudflare.com")
        try vault.save(state); try registry.bind(draft.id, accountID: id, username: username)
        return (try XCTUnwrap(registry.index.profiles.first { $0.id == draft.id }), vault, state.identity)
    }

    func testSeparateVaultsAndPasscodeDoNotUnlockAnotherAccount() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemoryAccountSecrets(), clock = AccountTestClock()
        let registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        let (a, aVault, identityA) = try named(registry, "private_account_alpha_821")
        let (b, bVault, identityB) = try named(registry, "private_account_beta_457")
        try registry.configure(a.id, vault: aVault, protection: AccountProtection(requirePasscode: true), passcode: "123456", remote: remote(clock))
        XCTAssertNil(try registry.secret(a.id).rawKey, "A protected account must not keep a raw master-key copy")
        XCTAssertThrowsError(try registry.open(a.id))
        XCTAssertEqual(try registry.open(a.id, passcode: "123456").load().identity, identityA)
        XCTAssertEqual(try registry.open(b.id).load().identity, identityB)
        XCTAssertThrowsError(try Vault(file: aVault.file, key: SymmetricKey(data: bVault.migrationKey())).load())
        XCTAssertThrowsError(try registry.configure(a.id, vault: bVault, protection: AccountProtection(), passcode: nil, remote: remote(clock)))
        XCTAssertNil(try Data(contentsOf: root.appendingPathComponent("accounts-index.bin")).range(of: Data("private_account_alpha_821".utf8)))
    }

    func testThirdConsecutiveWrongCodeSurvivesRestartAndDeletesOnlyItsAccount() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemoryAccountSecrets(), clock = AccountTestClock()
        var registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        let (a, vault, _) = try named(registry, "alpha"), (b, _, identityB) = try named(registry, "beta")
        try registry.configure(a.id, vault: vault, protection: AccountProtection(requirePasscode: true, wipeAfterThree: true), passcode: "123456", remote: remote(clock))
        XCTAssertThrowsError(try registry.open(a.id, passcode: "123"))
        XCTAssertEqual(try registry.secret(a.id).failures, 0, "incomplete codes do not count")
        for expected in 1...2 {
            clock.now.addTimeInterval(10)
            XCTAssertThrowsError(try registry.open(a.id, passcode: "000000"))
            registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
            XCTAssertEqual(try registry.secret(a.id).failures, expected)
            XCTAssertTrue(registry.index.profiles.contains { $0.id == a.id })
        }
        clock.now.addTimeInterval(10)
        XCTAssertThrowsError(try registry.open(a.id, passcode: "000000")) { error in
            guard let failure = error as? AccountAccessError, case .deleted = failure else { return XCTFail("Expected account deletion, got \(error)") }
        }
        XCTAssertFalse(registry.index.profiles.contains { $0.id == a.id })
        XCTAssertNil(secrets.data["account-\(a.id)"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: vault.file.path))
        XCTAssertEqual(registry.index.pendingDeletes.first?.accountID, a.accountID)
        XCTAssertEqual(try registry.open(b.id).load().identity, identityB)
        registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        XCTAssertEqual(registry.index.pendingDeletes.count, 1, "offline server deletion remains durable")
    }

    func testCorrectCodeResetsConsecutiveFailuresAndDisabledWipeNeverTriggers() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemoryAccountSecrets(), clock = AccountTestClock()
        let registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        let (profile, vault, identity) = try named(registry, "account")
        try registry.configure(profile.id, vault: vault, protection: AccountProtection(requirePasscode: true, wipeAfterThree: true), passcode: "123456", remote: remote(clock))
        for _ in 0..<2 { clock.now.addTimeInterval(10); XCTAssertThrowsError(try registry.open(profile.id, passcode: "000000")) }
        clock.now.addTimeInterval(10)
        _ = try registry.open(profile.id, passcode: "123456")
        XCTAssertEqual(try registry.secret(profile.id).failures, 0)
        clock.now.addTimeInterval(10); XCTAssertThrowsError(try registry.open(profile.id, passcode: "000000"))
        XCTAssertEqual(try registry.secret(profile.id).failures, 1)
        try registry.configure(profile.id, vault: vault, protection: AccountProtection(requirePasscode: true), passcode: "123456", remote: remote(clock))
        for _ in 0..<4 { clock.now.addTimeInterval(400); XCTAssertThrowsError(try registry.open(profile.id, passcode: "000000")) }
        clock.now.addTimeInterval(400 * 86400)
        XCTAssertEqual(try registry.open(profile.id, passcode: "123456").load().identity, identity)
    }

    func testInactivityWipesBeforeDecryptionAndWrongCodesDoNotExtendIt() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemoryAccountSecrets(), clock = AccountTestClock()
        var registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        let (a, vault, _) = try named(registry, "timed"), (b, _, identityB) = try named(registry, "untimed")
        try registry.configure(a.id, vault: vault, protection: AccountProtection(requirePasscode: true, inactivityDays: 3), passcode: "123456", remote: remote(clock))
        clock.now.addTimeInterval(2 * 86400)
        XCTAssertThrowsError(try registry.open(a.id, passcode: "000000"))
        clock.now.addTimeInterval(86400)
        registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        XCTAssertThrowsError(try registry.open(a.id, passcode: "123456")) { error in
            guard let failure = error as? AccountAccessError, case .deleted = failure else { return XCTFail("An overdue account must not open") }
        }
        XCTAssertEqual(try registry.open(b.id).load().identity, identityB)
    }

    func testLegacyMigrationKeepsKeysAndIsRetryableWithoutDuplicateProfiles() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemoryAccountSecrets(), clock = AccountTestClock()
        let legacy = Vault(file: root.appendingPathComponent("vault.bin"), key: SymmetricKey(size: .bits256))
        var old = VaultState(); old.ownerID = UUID().uuidString.lowercased()
        old.login = LoginSession(id: old.ownerID!, username: "original", token: String(repeating: "t", count: 43), serverURL: "https://example.trycloudflare.com")
        try legacy.save(old)
        let registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        try registry.importLegacy(legacy)
        let profile = try XCTUnwrap(registry.index.profiles.first)
        XCTAssertEqual(try registry.open(profile.id).load().identity, old.identity)
        XCTAssertEqual(try registry.open(profile.id).load().ownerID, old.ownerID)
        XCTAssertNotEqual(secrets.data["registry-key"], legacy.migrationKey())
        XCTAssertTrue(FileManager.default.fileExists(atPath: legacy.file.path), "legacy data is retained until protected migration is confirmed")
    }

    func testInterruptedKeyRemovalStaysTombstonedAndRetries() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemoryAccountSecrets(), clock = AccountTestClock()
        let registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        let (profile, vault, _) = try named(registry, "account")
        try registry.configure(profile.id, vault: vault, protection: AccountProtection(requirePasscode: true, wipeAfterThree: true), passcode: "123456", remote: remote(clock))
        secrets.failDeletion = true
        for _ in 0..<3 { clock.now.addTimeInterval(10); XCTAssertThrowsError(try registry.open(profile.id, passcode: "000000")) }
        XCTAssertTrue(try registry.secret(profile.id).tombstoned)
        XCTAssertThrowsError(try registry.open(profile.id, passcode: "123456"))
        secrets.failDeletion = false
        let recovered = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        XCTAssertNil(secrets.data["account-\(profile.id)"])
        XCTAssertFalse(recovered.index.profiles.contains { $0.id == profile.id })
        XCTAssertEqual(recovered.index.pendingDeletes.count, 1)
    }

    func testSettingsWriteFailureLeavesThePreviousKeyAndPolicyIntact() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemoryAccountSecrets(), clock = AccountTestClock()
        let registry = try AccountVaults(directory: root, secrets: secrets, now: { clock.now })
        let (profile, vault, identity) = try named(registry, "account")
        secrets.failWrites = true
        XCTAssertThrowsError(try registry.configure(profile.id, vault: vault, protection: AccountProtection(requirePasscode: true, wipeAfterThree: true), passcode: "123456", remote: remote(clock)))
        secrets.failWrites = false
        XCTAssertFalse(try registry.secret(profile.id).protection.requirePasscode)
        XCTAssertFalse(try registry.secret(profile.id).protection.wipeAfterThree)
        XCTAssertEqual(try registry.open(profile.id).load().identity, identity)
    }
}
