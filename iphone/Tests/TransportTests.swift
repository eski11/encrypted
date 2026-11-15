import XCTest
import CryptoKit
@testable import ENCPTD

final class TransportTests: XCTestCase {
    func testPinnedRequestAndAuthenticatedResponseRoundTrip() throws {
        let server = P256.KeyAgreement.PrivateKey()
        let config = ServerConfiguration(version: 1, instanceID: UUID().uuidString.lowercased(), publicKey: Data(repeating: 1, count: 32),
            discoveryURL: URL(string: "https://gist.githubusercontent.com/test-owner/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/raw/connection.json")!, transportKey: server.publicKey.x963Representation)
        let secret = Data("a password and private API request".utf8)
        let exchange = try TransportExchange(configuration: config, path: "/v1/login", method: "POST", body: secret, token: nil)
        let wire = try JSONEncoder().encode(exchange.envelope)
        XCTAssertNil(wire.range(of: secret))
        var receiver = try HPKE.Recipient(privateKey: server, ciphersuite: .P256_SHA256_AES_GCM_256,
            info: Data("ENCPTD-request-v1|\(config.instanceID)".utf8), encapsulatedKey: exchange.envelope.enc)
        let clear = try receiver.open(exchange.envelope.ciphertext, authenticating: TransportExchange.aad)
        XCTAssertEqual(clear.count % 1024, 0)
        let request = try TransportPadding.unpack(clear, as: ProtectedRequest.self)
        XCTAssertEqual(request.body, secret)
        XCTAssertEqual(request.path, "/v1/login")
        func response(key: P256.KeyAgreement.PrivateKey, requestID: String) throws -> Data {
            var sender = try HPKE.Sender(recipientKey: P256.KeyAgreement.PublicKey(x963Representation: request.replyKey),
                ciphersuite: .P256_SHA256_AES_GCM_256,
                info: Data("ENCPTD-response-v1|\(config.instanceID)|\(exchange.requestID)".utf8), authenticatedBy: key)
            let body = try TransportPadding.pack(ProtectedReply(requestID: requestID, status: 200, body: Data("{}".utf8)))
            return try JSONEncoder().encode(TransportEnvelope(enc: sender.encapsulatedKey, ciphertext: sender.seal(body, authenticating: TransportExchange.aad)))
        }
        let valid = try response(key: server, requestID: exchange.requestID)
        XCTAssertEqual(try exchange.open(valid).status, 200)
        XCTAssertThrowsError(try exchange.open(response(key: P256.KeyAgreement.PrivateKey(), requestID: exchange.requestID)))
        XCTAssertThrowsError(try exchange.open(response(key: server, requestID: UUID().uuidString.lowercased())))
        var tampered = try JSONDecoder().decode(TransportEnvelope.self, from: valid)
        tampered.ciphertext[0] ^= 1
        XCTAssertThrowsError(try exchange.open(JSONEncoder().encode(tampered)))
    }

    func testMalformedPaddingAndMissingPinnedKeyFailClosed() throws {
        XCTAssertThrowsError(try TransportPadding.unpack(Data(repeating: 0, count: 1024), as: ProtectedReply.self))
        let config = ServerConfiguration(version: 1, instanceID: UUID().uuidString.lowercased(), publicKey: Data(repeating: 1, count: 32),
            discoveryURL: URL(string: "https://gist.githubusercontent.com/test-owner/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/raw/connection.json")!)
        XCTAssertThrowsError(try TransportExchange(configuration: config, path: "/v1/login", method: "POST", body: nil, token: nil))
    }
}
