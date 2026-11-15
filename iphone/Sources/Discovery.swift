// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit

struct ServerConfiguration: Codable {
    var version: Int
    var instanceID: String
    var publicKey: Data
    var discoveryURL: URL
    var transportKey: Data? = nil

    static func bundled() throws -> ServerConfiguration {
        guard let url = Bundle.main.url(forResource: "Server", withExtension: "json") else {
            throw ChatFailure(message: "This app build is missing its connection configuration.")
        }
        return try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }
    func validate() throws {
        guard version == 1, UUID(uuidString: instanceID) != nil, publicKey.count == 32,
              transportKey == nil || transportKey?.count == 65,
              discoveryURL.scheme == "https", discoveryURL.host == "gist.githubusercontent.com",
              discoveryURL.user == nil, discoveryURL.password == nil, discoveryURL.port == nil,
              discoveryURL.query == nil, discoveryURL.fragment == nil,
              discoveryURL.path.range(of: "^/[A-Za-z0-9-]+/[a-f0-9]{20,64}/raw/connection\\.json$", options: .regularExpression) != nil else {
            throw ChatFailure(message: "This app build has an invalid connection configuration.")
        }
    }
}

struct VerifiedConnection: Codable {
    var instanceID: String
    var revision: Int64
    var expiresAt: Double
    var url: String?
}
struct ConnectionEnvelope: Codable { var payload: Data; var signature: Data }
struct ConnectionPayload: Codable {
    var version: Int; var service: String; var instanceID: String
    var revision: Int64; var issuedAt: Double; var expiresAt: Double; var url: String?
}
enum ConnectionVerification {
    static func origin(_ value: String) throws -> String {
        guard let url = URL(string: value), url.scheme == "https", let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty || url.path == "/" else {
            throw ChatFailure(message: "The signed connection address is invalid.")
        }
        return url.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }
    static func verify(_ data: Data, configuration: ServerConfiguration, minimumRevision: Int64 = 0, now: Double = Date().timeIntervalSince1970) throws -> VerifiedConnection {
        try configuration.validate()
        guard data.count <= 16384 else { throw ChatFailure(message: "The connection record is too large.") }
        let envelope = try JSONDecoder().decode(ConnectionEnvelope.self, from: data)
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: configuration.publicKey)
        guard envelope.signature.count == 64, key.isValidSignature(envelope.signature, for: envelope.payload) else {
            throw ChatFailure(message: "The server connection could not be verified. Please try again later.")
        }
        let value = try JSONDecoder().decode(ConnectionPayload.self, from: envelope.payload)
        guard value.version == 1, value.service == "ENCPTD", value.instanceID == configuration.instanceID,
              value.revision > 0, value.revision >= minimumRevision,
              value.issuedAt.isFinite, value.expiresAt.isFinite,
              value.issuedAt <= now + 300, value.expiresAt > now,
              value.expiresAt > value.issuedAt, value.expiresAt - value.issuedAt <= 86400 else {
            throw ChatFailure(message: "The server connection is outdated. Keep the PC and internet connector running, then try again.")
        }
        return try VerifiedConnection(instanceID: value.instanceID, revision: value.revision, expiresAt: value.expiresAt, url: value.url.map(origin))
    }
}

// Never forward a login body or bearer token through an HTTP redirect.
final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
enum ENCPTDNetwork {
    static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        return URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
    }()
}
