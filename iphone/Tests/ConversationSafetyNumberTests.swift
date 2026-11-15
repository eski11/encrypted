import XCTest
import SignalBridge
@testable import ENCPTD

final class ConversationSafetyNumberTests: XCTestCase {
    func testBothPhonesDisplayIdenticalCompleteNumberAfterVaultReload() throws {
        var alice = VaultState(), bob = VaultState()
        alice.ownerID = UUID().uuidString.lowercased(); bob.ownerID = UUID().uuidString.lowercased()
        let restored = try JSONDecoder().decode(VaultState.self, from: JSONEncoder().encode(bob))
        let a = try IdentityKeyPair(bytes: alice.identity), b = try IdentityKeyPair(bytes: restored.identity)
        let bobContact = Contact(id: bob.ownerID!, username: "bob", identityKey: b.publicKey.serialize())
        let aliceContact = Contact(id: alice.ownerID!, username: "alice", identityKey: a.publicKey.serialize())
        let left = try ConversationSafetyNumber.make(ownerID: alice.ownerID!, identity: a, contact: bobContact)
        let right = try ConversationSafetyNumber.make(ownerID: bob.ownerID!, identity: b, contact: aliceContact)
        XCTAssertEqual(left, right)
        XCTAssertEqual(left.filter(\.isNumber).count, 60)
        XCTAssertEqual(left.components(separatedBy: "\n").count, 3)
        var renamed = bobContact; renamed.username = "new_display_name"
        XCTAssertEqual(left, try ConversationSafetyNumber.make(ownerID: alice.ownerID!, identity: a, contact: renamed))
        var changed = bobContact; changed.identityKey = IdentityKeyPair.generate().publicKey.serialize()
        XCTAssertNotEqual(left, try ConversationSafetyNumber.make(ownerID: alice.ownerID!, identity: a, contact: changed))
    }

    @MainActor func testSafetyNumberCannotBeReadWithInventedAuthorization() throws {
        let model = ChatModel()
        let contact = Contact(id: UUID().uuidString.lowercased(), username: "bob", identityKey: IdentityKeyPair.generate().publicKey.serialize())
        XCTAssertThrowsError(try model.safetyNumber(contact, authorization: UUID()))
        model.verify(contact, authorization: UUID())
        XCTAssertTrue(model.contacts.isEmpty)
    }
}
