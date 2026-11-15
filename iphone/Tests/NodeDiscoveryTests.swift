import XCTest
@testable import ENCPTD

// Generated with Node crypto.sign using an ephemeral test-only Ed25519 key.
final class NodeDiscoveryTests: XCTestCase {
    func testNodeSignatureVerifiesWithCryptoKit() throws {
        let config = ServerConfiguration(version: 1, instanceID: "15f4dd93-b492-450b-a426-8661df53c0cb",
            publicKey: Data(base64Encoded: "26j0G6iaT/HxMeLpU/XhR0DioN62RjeqGLDJ2s0LH/0=")!,
            discoveryURL: URL(string: "https://gist.githubusercontent.com/test-owner/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/raw/connection.json")!)
        let envelope = Data(base64Encoded: "eyJwYXlsb2FkIjoiZXlKMlpYSnphVzl1SWpveExDSnpaWEoyYVdObElqb2lSVTVEVUZSRUlpd2lhVzV6ZEdGdVkyVkpSQ0k2SWpFMVpqUmtaRGt6TFdJME9USXRORFV3WWkxaE5ESTJMVGcyTmpGa1pqVXpZekJqWWlJc0luSmxkbWx6YVc5dUlqb3hOeXdpYVhOemRXVmtRWFFpT2pFNU1EQXdNREF3TURBc0ltVjRjR2x5WlhOQmRDSTZNVGt3TURBd016WXdNQ3dpZFhKc0lqb2lhSFIwY0hNNkx5OXViMlJsTFdacGVIUjFjbVV1ZEhKNVkyeHZkV1JtYkdGeVpTNWpiMjBpZlE9PSIsInNpZ25hdHVyZSI6Ikc5MWFpcTNybWRVUXNiQkpxZHQ1a0sxV1NIVzhscjlkS3R6ZjlmaWk3enJMYmdKTU03cDRRbk5RdDNjV1FWR1h6WVo5aDFXVDg2VXV6ZW15RDREcURRPT0ifQ==")!
        let value = try ConnectionVerification.verify(envelope, configuration: config, minimumRevision: 17, now: 1_900_000_001)
        XCTAssertEqual(value.url, "https://node-fixture.trycloudflare.com")
        XCTAssertEqual(value.revision, 17)
    }
}
