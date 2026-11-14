import XCTest
import SignalBridge
import CryptoKit
@testable import ENCPTD

final class EncryptionTests: XCTestCase {
    func testVerifiedSignalRoundTripAndPersistentState() throws {
        XCTAssertEqual(CiphertextMessage.MessageType.whisper.rawValue, 2)
        XCTAssertEqual(CiphertextMessage.MessageType.preKey.rawValue, 3)
        let alice = SignalStore(), bob = SignalStore()
        try alice.prepareKeys(count: 2); try bob.prepareKeys(count: 2)
        let aliceID = UUID().uuidString.lowercased(), bobID = UUID().uuidString.lowercased()
        let a = try ProtocolAddress(name: aliceID, deviceId: 1), b = try ProtocolAddress(name: bobID, deviceId: 1)
        alice.state.trusted[bobID] = try bob.identityKeyPair(context: NullContext()).publicKey.serialize()
        bob.state.trusted[aliceID] = try alice.identityKeyPair(context: NullContext()).publicKey.serialize()
        let keys = try bob.publication()
        let bundle = RemoteBundle(identityKey: keys.identityKey, registrationId: keys.registrationId, signedPreKey: keys.signedPreKey, preKey: try XCTUnwrap(keys.preKeys.first), kyberPreKey: try XCTUnwrap(keys.kyberPreKeys.first))
        try processPreKeyBundle(bundle.signalBundle(), for: b, ourAddress: a, sessionStore: alice, identityStore: alice, context: NullContext())
        let original = Data("a secret that must never reach the relay".utf8)
        let cipher = try signalEncrypt(message: original, for: b, localAddress: a, sessionStore: alice, identityStore: alice, context: NullContext())
        XCTAssertNil(cipher.serialize().range(of: original))
        let tamperStore = SignalStore(state: bob.state)
        var tampered = cipher.serialize(); tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try signalDecryptPreKey(message: PreKeySignalMessage(bytes: tampered), from: a, localAddress: b, sessionStore: tamperStore, identityStore: tamperStore, preKeyStore: tamperStore, signedPreKeyStore: tamperStore, kyberPreKeyStore: tamperStore, context: NullContext()))
        let decoded = try signalDecryptPreKey(message: PreKeySignalMessage(bytes: cipher.serialize()), from: a, localAddress: b, sessionStore: bob, identityStore: bob, preKeyStore: bob, signedPreKeyStore: bob, kyberPreKeyStore: bob, context: NullContext())
        XCTAssertEqual(decoded, original)
        let restoredBob = SignalStore(state: try JSONDecoder().decode(VaultState.self, from: JSONEncoder().encode(bob.state)))
        let reply = try signalEncrypt(message: Data("reply".utf8), for: a, localAddress: b, sessionStore: restoredBob, identityStore: restoredBob, context: NullContext())
        let replyClear = try signalDecrypt(message: SignalMessage(bytes: reply.serialize()), from: b, to: a, sessionStore: alice, identityStore: alice, context: NullContext())
        XCTAssertEqual(replyClear, Data("reply".utf8))
        let generator = NumericFingerprintGenerator(iterations: 5200)
        let aSafety = try generator.create(version: 2, localIdentifier: Data(aliceID.utf8), localKey: alice.identityKeyPair(context: NullContext()).publicKey, remoteIdentifier: Data(bobID.utf8), remoteKey: bob.identityKeyPair(context: NullContext()).publicKey)
        let bSafety = try generator.create(version: 2, localIdentifier: Data(bobID.utf8), localKey: bob.identityKeyPair(context: NullContext()).publicKey, remoteIdentifier: Data(aliceID.utf8), remoteKey: alice.identityKeyPair(context: NullContext()).publicKey)
        XCTAssertEqual(aSafety.displayable.formatted, bSafety.displayable.formatted)
        XCTAssertThrowsError(try signalDecryptPreKey(message: PreKeySignalMessage(bytes: cipher.serialize()), from: a, localAddress: b, sessionStore: restoredBob, identityStore: restoredBob, preKeyStore: restoredBob, signedPreKeyStore: restoredBob, kyberPreKeyStore: restoredBob, context: NullContext()))
    }

    func testUnverifiedAndChangedIdentityCannotCreateSession() throws {
        let alice = SignalStore(), bob = SignalStore(); try bob.prepareKeys(count: 1)
        let a = try ProtocolAddress(name: UUID().uuidString.lowercased(), deviceId: 1), b = try ProtocolAddress(name: UUID().uuidString.lowercased(), deviceId: 1)
        let keys = try bob.publication()
        let bundle = RemoteBundle(identityKey: keys.identityKey, registrationId: keys.registrationId, signedPreKey: keys.signedPreKey, preKey: try XCTUnwrap(keys.preKeys.first), kyberPreKey: try XCTUnwrap(keys.kyberPreKeys.first))
        XCTAssertThrowsError(try processPreKeyBundle(bundle.signalBundle(), for: b, ourAddress: a, sessionStore: alice, identityStore: alice, context: NullContext()))
        alice.state.trusted[b.name] = IdentityKeyPair.generate().publicKey.serialize()
        XCTAssertThrowsError(try processPreKeyBundle(bundle.signalBundle(), for: b, ourAddress: a, sessionStore: alice, identityStore: alice, context: NullContext()))
    }

    func testVaultEncryptsAndRejectsTampering() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("vault.bin")
        let vault = Vault(file: file, key: SymmetricKey(size: .bits256))
        var state = VaultState(); state.messages = [ChatMessage(id: "1", contactID: "2", text: "private local message", outgoing: true, date: Date(), pending: false)]
        try vault.save(state)
        XCTAssertNil(try Data(contentsOf: file).range(of: Data("private local message".utf8)))
        XCTAssertEqual(try vault.load().messages.first?.text, "private local message")
        var damaged = try Data(contentsOf: file); damaged[damaged.count - 1] ^= 1; try damaged.write(to: file)
        XCTAssertThrowsError(try vault.load())
    }
}
