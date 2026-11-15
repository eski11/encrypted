import XCTest
import CryptoKit
@testable import ENCPTD

final class DiscoveryTests: XCTestCase {
    func testSignedConnectionRejectsTamperingExpiryRollbackAndWrongServer() throws {
        let key = Curve25519.Signing.PrivateKey()
        let config = ServerConfiguration(version: 1, instanceID: UUID().uuidString.lowercased(), publicKey: key.publicKey.rawRepresentation,
            discoveryURL: URL(string: "https://gist.githubusercontent.com/test-owner/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/raw/connection.json")!)
        let now = 1_900_000_000.0
        var payload = ConnectionPayload(version: 1, service: "ENCPTD", instanceID: config.instanceID, revision: 10, issuedAt: now, expiresAt: now + 3600, url: "https://example.trycloudflare.com")
        func envelope(_ value: ConnectionPayload) throws -> Data {
            let bytes = try JSONEncoder().encode(value)
            return try JSONEncoder().encode(ConnectionEnvelope(payload: bytes, signature: key.signature(for: bytes)))
        }
        let valid = try envelope(payload)
        XCTAssertEqual(try ConnectionVerification.verify(valid, configuration: config, minimumRevision: 10, now: now).url, payload.url)
        XCTAssertThrowsError(try ConnectionVerification.verify(valid, configuration: config, minimumRevision: 11, now: now))
        XCTAssertThrowsError(try ConnectionVerification.verify(valid, configuration: config, now: now + 3600))
        var altered = try JSONDecoder().decode(ConnectionEnvelope.self, from: valid)
        altered.payload[0] ^= 1
        XCTAssertThrowsError(try ConnectionVerification.verify(JSONEncoder().encode(altered), configuration: config, now: now))
        var wrongKey = config; wrongKey.publicKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        XCTAssertThrowsError(try ConnectionVerification.verify(valid, configuration: wrongKey, now: now))
        payload.instanceID = UUID().uuidString.lowercased()
        XCTAssertThrowsError(try ConnectionVerification.verify(envelope(payload), configuration: config, now: now))
        payload.instanceID = config.instanceID
        for invalid in ["http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com?secret=123"] {
            payload.url = invalid
            XCTAssertThrowsError(try ConnectionVerification.verify(envelope(payload), configuration: config, now: now))
        }
        payload.url = nil
        XCTAssertNil(try ConnectionVerification.verify(envelope(payload), configuration: config, now: now).url)
    }

    func testExistingVaultMigratesWithoutChangingPhoneKeys() throws {
        let state = VaultState()
        let data = try JSONEncoder().encode(state)
        var old = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        old.removeValue(forKey: "connection"); old.removeValue(forKey: "discoveryRevision")
        let restored = try JSONDecoder().decode(VaultState.self, from: JSONSerialization.data(withJSONObject: old))
        XCTAssertEqual(restored.identity, state.identity)
        XCTAssertEqual(restored.registrationID, state.registrationID)
        XCTAssertNil(restored.connection)
        XCTAssertNil(restored.discoveryRevision)
    }
}
