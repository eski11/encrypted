// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit

struct TransportEnvelope: Codable { var version: Int = 1; var enc: Data; var ciphertext: Data }
struct ProtectedRequest: Codable {
    var requestID: String; var sentAt: Int64; var method: String; var path: String
    var token: String?; var body: Data?; var replyKey: Data
}
struct ProtectedReply: Codable { var requestID: String; var status: Int; var body: Data }
enum TransportPadding {
    static func pack<T: Encodable>(_ value: T) throws -> Data {
        let json = try JSONEncoder().encode(value)
        guard json.count + 4 <= 3 * 1024 * 1024 else { throw ChatFailure(message: "Request is too large.") }
        let n = UInt32(json.count)
        var data = Data([UInt8((n >> 24) & 255), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)])
        data.append(json)
        data.append(Data(repeating: 0, count: ((data.count + 1023) / 1024) * 1024 - data.count))
        return data
    }
    static func unpack<T: Decodable>(_ data: Data, as type: T.Type) throws -> T {
        guard data.count >= 1024, data.count <= 3 * 1024 * 1024, data.count % 1024 == 0 else { throw ChatFailure(message: "Invalid encrypted response.") }
        let length = data.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard length >= 2, length <= data.count - 4 else { throw ChatFailure(message: "Invalid encrypted response.") }
        return try JSONDecoder().decode(type, from: data.subdata(in: 4..<(4 + length)))
    }
}
struct TransportExchange {
    static let aad = Data("ENCPTD-transport-v1".utf8)
    let requestID: String
    let configuration: ServerConfiguration
    let replyPrivateKey: P256.KeyAgreement.PrivateKey
    let envelope: TransportEnvelope

    init(configuration: ServerConfiguration, path: String, method: String, body: Data?, token: String?,
         replyPrivateKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey(), requestID: String = UUID().uuidString.lowercased()) throws {
        try configuration.validate()
        guard let key = configuration.transportKey, key.count == 65 else { throw ChatFailure(message: "This build needs its private server connection configured.") }
        self.configuration = configuration; self.requestID = requestID; self.replyPrivateKey = replyPrivateKey
        let server = try P256.KeyAgreement.PublicKey(x963Representation: key)
        var sender = try HPKE.Sender(recipientKey: server, ciphersuite: .P256_SHA256_AES_GCM_256, info: Data("ENCPTD-request-v1|\(configuration.instanceID)".utf8))
        let request = ProtectedRequest(requestID: requestID, sentAt: Int64(Date().timeIntervalSince1970 * 1000), method: method, path: path,
            token: token, body: body, replyKey: replyPrivateKey.publicKey.x963Representation)
        let ciphertext = try sender.seal(TransportPadding.pack(request), authenticating: Self.aad)
        envelope = TransportEnvelope(enc: sender.encapsulatedKey, ciphertext: ciphertext)
    }
    func open(_ bytes: Data) throws -> ProtectedReply {
        guard bytes.count <= 4 * 1024 * 1024, let key = configuration.transportKey else { throw ChatFailure(message: "Invalid encrypted response.") }
        let reply = try JSONDecoder().decode(TransportEnvelope.self, from: bytes)
        guard reply.version == 1, reply.enc.count == 65, reply.ciphertext.count <= 3 * 1024 * 1024 + 16 else { throw ChatFailure(message: "Invalid encrypted response.") }
        var receiver = try HPKE.Recipient(privateKey: replyPrivateKey, ciphersuite: .P256_SHA256_AES_GCM_256,
            info: Data("ENCPTD-response-v1|\(configuration.instanceID)|\(requestID)".utf8), encapsulatedKey: reply.enc,
            authenticatedBy: P256.KeyAgreement.PublicKey(x963Representation: key))
        let clear = try receiver.open(reply.ciphertext, authenticating: Self.aad)
        let value = try TransportPadding.unpack(clear, as: ProtectedReply.self)
        guard value.requestID == requestID, (100...599).contains(value.status) else { throw ChatFailure(message: "The encrypted response does not match this request.") }
        return value
    }
}
