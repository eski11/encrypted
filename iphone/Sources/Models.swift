// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import SignalBridge

struct ChatFailure: LocalizedError {
    var message: String
    var errorDescription: String? { message }
}
struct LoginReply: Decodable { var id: String; var username: String; var token: String }
struct LoginSession: Codable { var id: String; var username: String; var token: String; var serverURL: String }
struct PublicKeyItem: Codable { var id: UInt32; var key: Data; var signature: Data? = nil }
struct PublishedDevice: Codable {
    var identityKey: Data; var registrationId: UInt32; var signedPreKey: PublicKeyItem
    var preKeys: [PublicKeyItem]; var kyberPreKeys: [PublicKeyItem]
}
struct RemoteBundle: Codable {
    var identityKey: Data; var registrationId: UInt32; var signedPreKey: PublicKeyItem
    var preKey: PublicKeyItem; var kyberPreKey: PublicKeyItem
    func signalBundle() throws -> PreKeyBundle {
        guard let ecSignature = signedPreKey.signature, let pqSignature = kyberPreKey.signature else {
            throw ChatFailure(message: "Recipient keys are incomplete.")
        }
        return try PreKeyBundle(registrationId: registrationId, deviceId: 1,
            prekeyId: preKey.id, prekey: PublicKey(preKey.key),
            signedPrekeyId: signedPreKey.id, signedPrekey: PublicKey(signedPreKey.key),
            signedPrekeySignature: ecSignature, identity: IdentityKey(bytes: identityKey),
            kyberPrekeyId: kyberPreKey.id, kyberPrekey: KEMPublicKey(kyberPreKey.key),
            kyberPrekeySignature: pqSignature)
    }
}
struct Contact: Codable, Identifiable, Hashable { var id: String; var username: String; var identityKey: Data; var verified: Bool = false }
struct OutgoingPacket: Codable, Identifiable {
    var messageId: String; var recipient: String; var kind: UInt8; var ciphertext: Data
    var id: String { messageId }
}
struct IncomingPacket: Codable { var seq: Int; var sender: String; var senderUsername: String; var messageId: String; var kind: UInt8; var ciphertext: Data; var created: Int64 }
struct Inbox: Codable { var messages: [IncomingPacket] }
struct Acknowledgement: Codable { var sequences: [Int] }
struct DeviceInventory: Decodable { var identityKey: Data?; var preKeys: Int; var kyberPreKeys: Int }
struct ChatMessage: Codable, Identifiable {
    var id: String; var contactID: String; var text: String; var outgoing: Bool; var date: Date; var pending: Bool
}
struct MessageContent: Codable { var version: Int = 1; var text: String; var created: Date }
struct VaultState: Codable {
    var identity: Data = IdentityKeyPair.generate().serialize()
    var registrationID: UInt32 = UInt32.random(in: 1...16383)
    var ownerID: String?; var login: LoginSession?
    var signedKeys: [String: Data] = [:]; var preKeys: [String: Data] = [:]; var kyberKeys: [String: Data] = [:]
    var nextKeyID: UInt32 = 2; var sessions: [String: Data] = [:]; var trusted: [String: Data] = [:]
    var usedKyberBases: Set<String> = []; var contacts: [Contact] = []; var messages: [ChatMessage] = []
    var outbox: [OutgoingPacket] = []; var receivedIDs: Set<String> = []
}

final class SignalStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore {
    var state: VaultState
    init(state: VaultState = VaultState()) { self.state = state }
    func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair { try IdentityKeyPair(bytes: state.identity) }
    func localRegistrationId(context: StoreContext) throws -> UInt32 { state.registrationID }
    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> IdentityChange {
        guard state.trusted[address.name] == identity.serialize() else { throw ChatFailure(message: "Verify this person's safety number before messaging.") }
        return .newOrUnchanged
    }
    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool {
        state.trusted[address.name] == identity.serialize()
    }
    func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey? {
        try state.trusted[address.name].map { try IdentityKey(bytes: $0) }
    }
    func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        guard let data = state.preKeys[String(id)] else { throw ChatFailure(message: "Encryption key is unavailable.") }
        return try PreKeyRecord(bytes: data)
    }
    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws { state.preKeys[String(id)] = record.serialize() }
    func removePreKey(id: UInt32, context: StoreContext) throws { state.preKeys.removeValue(forKey: String(id)) }
    func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord {
        guard let data = state.signedKeys[String(id)] else { throw ChatFailure(message: "Encryption key is unavailable.") }
        return try SignedPreKeyRecord(bytes: data)
    }
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws { state.signedKeys[String(id)] = record.serialize() }
    func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord {
        guard let data = state.kyberKeys[String(id)] else { throw ChatFailure(message: "Encryption key is unavailable.") }
        return try KyberPreKeyRecord(bytes: data)
    }
    func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws { state.kyberKeys[String(id)] = record.serialize() }
    func markKyberPreKeyUsed(id: UInt32, signedPreKeyId: UInt32, baseKey: PublicKey, context: StoreContext) throws {
        let marker = "\(id):\(signedPreKeyId):\(baseKey.serialize().base64EncodedString())"
        guard state.usedKyberBases.insert(marker).inserted else { throw ChatFailure(message: "Repeated encrypted session request rejected.") }
    }
    func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord? {
        try state.sessions[address.name].map { try SessionRecord(bytes: $0) }
    }
    func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext) throws -> [SessionRecord] {
        try addresses.map {
            guard let record = try loadSession(for: $0, context: context) else { throw ChatFailure(message: "Encryption session is unavailable.") }
            return record
        }
    }
    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws { state.sessions[address.name] = record.serialize() }

    func prepareKeys(count: Int = 25) throws {
        let identity = try identityKeyPair(context: NullContext())
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        if state.signedKeys["1"] == nil {
            let key = PrivateKey.generate()
            let record = try SignedPreKeyRecord(id: 1, timestamp: now, privateKey: key, signature: identity.privateKey.generateSignature(message: key.publicKey.serialize()))
            state.signedKeys["1"] = record.serialize()
        }
        for _ in 0..<count {
            let id = state.nextKeyID; state.nextKeyID += 1
            let ec = try PreKeyRecord(id: id, privateKey: PrivateKey.generate())
            let pq = KEMKeyPair.generate()
            let kyber = try KyberPreKeyRecord(id: id, timestamp: now, keyPair: pq, signature: identity.privateKey.generateSignature(message: pq.publicKey.serialize()))
            state.preKeys[String(id)] = ec.serialize(); state.kyberKeys[String(id)] = kyber.serialize()
        }
    }
    func publication() throws -> PublishedDevice {
        let signed = try loadSignedPreKey(id: 1, context: NullContext())
        let ec = try state.preKeys.values.map { bytes -> PublicKeyItem in
            let key = try PreKeyRecord(bytes: bytes); return try PublicKeyItem(id: key.id, key: key.publicKey().serialize())
        }
        let pq = try state.kyberKeys.values.map { bytes -> PublicKeyItem in
            let key = try KyberPreKeyRecord(bytes: bytes); return try PublicKeyItem(id: key.id, key: key.publicKey().serialize(), signature: key.signature)
        }
        return try PublishedDevice(identityKey: identityKeyPair(context: NullContext()).publicKey.serialize(), registrationId: state.registrationID,
            signedPreKey: PublicKeyItem(id: signed.id, key: signed.publicKey().serialize(), signature: signed.signature),
            preKeys: Array(ec.sorted { $0.id > $1.id }.prefix(100)), kyberPreKeys: Array(pq.sorted { $0.id > $1.id }.prefix(100)))
    }
}
