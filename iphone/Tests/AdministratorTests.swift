import XCTest
import CryptoKit
import SignalBridge
@testable import ENCPTD

final class AdministratorTests: XCTestCase {
    private let now = 1900000000.0
    private let instance = "437ca923-85a7-4c96-a974-ef7925f38266"
    private func configuration(_ key: Curve25519.Signing.PrivateKey) -> ServerConfiguration {
        ServerConfiguration(version: 1, instanceID: instance, publicKey: key.publicKey.rawRepresentation,
            discoveryURL: URL(string: "https://gist.githubusercontent.com/test-owner/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/raw/connection.json")!)
    }
    private func record() -> AdministratorRecord {
        AdministratorRecord(version: 1, service: "ENCPTD-administrator", instanceID: instance, revision: 1,
            issuedAt: now, expiresAt: now + 3600,
            administrator: AdministratorIdentity(id: UUID().uuidString.lowercased(), username: "pc_admin", identityKey: IdentityKeyPair.generate().publicKey.serialize()))
    }
    private func signed(_ record: AdministratorRecord, _ key: Curve25519.Signing.PrivateKey, withDomain: Bool = true) throws -> Data {
        let payload = try JSONEncoder().encode(record)
        let signature = try key.signature(for: (withDomain ? AdministratorVerification.domain : Data()) + payload)
        return try JSONEncoder().encode(ConnectionEnvelope(payload: payload, signature: signature))
    }
    func testValidCertificateAddsOnlyTheDesignatedAdministratorWithoutManualPairing() throws {
        let key = Curve25519.Signing.PrivateKey(), value = record()
        let checked = try AdministratorVerification.verify(signed(value, key), configuration: configuration(key), now: now)
        var state = VaultState(); state.ownerID = UUID().uuidString.lowercased()
        let imposter = Contact(id: UUID().uuidString.lowercased(), username: "administrator", identityKey: IdentityKeyPair.generate().publicKey.serialize())
        state.contacts = [imposter]
        try AdministratorVerification.apply(checked, to: &state)
        XCTAssertNil(state.trusted[imposter.id])
        XCTAssertFalse(state.contacts[0].verified)
        let admin = try XCTUnwrap(value.administrator)
        XCTAssertEqual(state.trusted[admin.id], admin.identityKey)
        XCTAssertEqual(state.contacts.first { $0.id == admin.id }?.administrator, true)
        XCTAssertEqual(state.administratorRevision, 1)
    }
    func testWrongSignerScopeExpiredRecordAndRollbackAreRejected() throws {
        let key = Curve25519.Signing.PrivateKey(), config = configuration(key), value = record()
        XCTAssertThrowsError(try AdministratorVerification.verify(signed(value, Curve25519.Signing.PrivateKey()), configuration: config, now: now))
        XCTAssertThrowsError(try AdministratorVerification.verify(signed(value, key, withDomain: false), configuration: config, now: now))
        XCTAssertThrowsError(try AdministratorVerification.verify(signed(value, key), configuration: config, minimumRevision: 2, now: now))
        var wrongInstance = value; wrongInstance.instanceID = UUID().uuidString.lowercased()
        XCTAssertThrowsError(try AdministratorVerification.verify(signed(wrongInstance, key), configuration: config, now: now))
        var expired = value; expired.issuedAt = now - 3601; expired.expiresAt = now - 1
        XCTAssertThrowsError(try AdministratorVerification.verify(signed(expired, key), configuration: config, now: now))
        var future = value; future.issuedAt = now + 301; future.expiresAt = now + 3901
        XCTAssertThrowsError(try AdministratorVerification.verify(signed(future, key), configuration: config, now: now))
        var service = value; service.service = "ENCPTD"
        XCTAssertThrowsError(try AdministratorVerification.verify(signed(service, key), configuration: config, now: now))
        var envelope = try JSONDecoder().decode(ConnectionEnvelope.self, from: signed(value, key))
        envelope.payload[0] ^= 1
        XCTAssertThrowsError(try AdministratorVerification.verify(JSONEncoder().encode(envelope), configuration: config, now: now))
    }
    func testRevocationRemovesAutomaticTrustAndSessionButKeepsOtherContacts() throws {
        let key = Curve25519.Signing.PrivateKey(), initial = record()
        var state = VaultState(); state.ownerID = UUID().uuidString.lowercased()
        let admin = try XCTUnwrap(initial.administrator), otherID = UUID().uuidString.lowercased()
        state.trusted[otherID] = IdentityKeyPair.generate().publicKey.serialize()
        try AdministratorVerification.apply(initial, to: &state)
        state.sessions[admin.id] = Data([1,2,3])
        var revoked = initial; revoked.revision = 2; revoked.administrator = nil
        let checked = try AdministratorVerification.verify(signed(revoked, key), configuration: configuration(key), minimumRevision: 1, now: now)
        try AdministratorVerification.apply(checked, to: &state)
        XCTAssertNil(state.trusted[admin.id]); XCTAssertNil(state.sessions[admin.id])
        XCTAssertNotNil(state.trusted[otherID])
        XCTAssertFalse(try XCTUnwrap(state.contacts.first { $0.id == admin.id }).verified)
        XCTAssertThrowsError(try AdministratorVerification.apply(initial, to: &state))
    }
    func testSignedAdministratorCannotReplaceAnIndependentlyVerifiedPrivateKey() throws {
        var state = VaultState(); state.ownerID = UUID().uuidString.lowercased()
        let person = Contact(id: UUID().uuidString.lowercased(), username: "private_friend", identityKey: IdentityKeyPair.generate().publicKey.serialize(), verified: true)
        state.contacts = [person]; state.trusted[person.id] = person.identityKey; state.sessions[person.id] = Data([7,8,9])
        var value = record()
        value.administrator = AdministratorIdentity(id: person.id, username: person.username, identityKey: IdentityKeyPair.generate().publicKey.serialize())
        let key = Curve25519.Signing.PrivateKey()
        let checked = try AdministratorVerification.verify(signed(value, key), configuration: configuration(key), now: now)
        XCTAssertThrowsError(try AdministratorVerification.apply(checked, to: &state))
        XCTAssertEqual(state.trusted[person.id], person.identityKey)
        XCTAssertEqual(state.sessions[person.id], Data([7,8,9]))
        XCTAssertNil(state.contacts[0].administrator)
        value.administrator?.identityKey = person.identityKey
        try AdministratorVerification.apply(value, to: &state)
        XCTAssertEqual(state.contacts[0].independentlyVerified, true)
        var revoked = value; revoked.revision = 2; revoked.administrator = nil
        try AdministratorVerification.apply(revoked, to: &state)
        XCTAssertEqual(state.trusted[person.id], person.identityKey, "Role revocation cannot erase an independent private comparison")
        XCTAssertEqual(state.sessions[person.id], Data([7,8,9]))
        XCTAssertTrue(state.contacts[0].verified)
        XCTAssertEqual(state.contacts[0].administrator, false)
    }
}
