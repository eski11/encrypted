// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import CryptoKit
import SignalBridge

struct AdministratorIdentity: Codable {
    var id: String; var username: String; var identityKey: Data
}
struct AdministratorRecord: Codable {
    var version: Int; var service: String; var instanceID: String; var revision: Int64
    var issuedAt: Double; var expiresAt: Double; var administrator: AdministratorIdentity?
}
enum AdministratorVerification {
    static let domain = Data("ENCPTD-administrator-v1\u{0}".utf8)
    static func verify(_ data: Data, configuration: ServerConfiguration, minimumRevision: Int64 = 0, now: Double = Date().timeIntervalSince1970) throws -> AdministratorRecord {
        try configuration.validate()
        guard data.count <= 16384 else { throw ChatFailure(message: "Administrator identity record is too large.") }
        let envelope = try JSONDecoder().decode(ConnectionEnvelope.self, from: data)
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: configuration.publicKey)
        guard envelope.signature.count == 64, key.isValidSignature(envelope.signature, for: domain + envelope.payload) else {
            throw ChatFailure(message: "The server administrator identity could not be verified.")
        }
        let value = try JSONDecoder().decode(AdministratorRecord.self, from: envelope.payload)
        guard value.version == 1, value.service == "ENCPTD-administrator", value.instanceID == configuration.instanceID,
              value.revision >= 0, value.revision >= minimumRevision,
              value.issuedAt.isFinite, value.expiresAt.isFinite, value.issuedAt <= now + 300,
              value.expiresAt > now, value.expiresAt > value.issuedAt, value.expiresAt - value.issuedAt <= 3600 else {
            throw ChatFailure(message: "The administrator identity record is expired or outdated.")
        }
        if let admin = value.administrator {
            guard UUID(uuidString: admin.id) != nil,
                  admin.username.range(of: "^[a-z0-9_]{3,32}$", options: .regularExpression) != nil,
                  admin.identityKey.count == 33, try PublicKey(admin.identityKey).serialize() == admin.identityKey else {
                throw ChatFailure(message: "Invalid administrator encryption identity.")
            }
        }
        return value
    }
    static func apply(_ value: AdministratorRecord, to state: inout VaultState) throws {
        guard value.revision >= (state.administratorRevision ?? 0), value.administrator?.id != state.ownerID else {
            throw ChatFailure(message: "Administrator identity does not match this account.")
        }
        let admin = value.administrator
        let existing = admin.flatMap { admin in state.contacts.first { $0.id == admin.id } }
        let existingKey = admin.flatMap { state.trusted[$0.id] }
        // Legacy verified contacts predate the role flag; preserve their independent trust.
        let independent = existing?.independentlyVerified == true || (existing?.administrator != true && existingKey != nil)
        if let admin, let existingKey, independent, existingKey != admin.identityKey {
            throw ChatFailure(message: "The administrator record conflicts with a private contact you already verified. That contact's key was kept unchanged.")
        }
        for index in state.contacts.indices where state.contacts[index].administrator == true {
            let old = state.contacts[index]
            if old.id != admin?.id || old.identityKey != admin?.identityKey {
                if old.independentlyVerified != true {
                    state.trusted.removeValue(forKey: old.id); state.sessions.removeValue(forKey: old.id)
                    state.contacts[index].verified = false
                }
                state.contacts[index].administrator = false
            }
        }
        if let admin {
            if let old = state.trusted[admin.id], old != admin.identityKey { state.sessions.removeValue(forKey: admin.id) }
            state.trusted[admin.id] = admin.identityKey
            let contact = Contact(id: admin.id, username: admin.username, identityKey: admin.identityKey, verified: true, administrator: true, independentlyVerified: independent)
            if let index = state.contacts.firstIndex(where: { $0.id == admin.id }) { state.contacts[index] = contact }
            else { state.contacts.append(contact) }
        }
        state.administratorRevision = value.revision
        state.administratorExpiresAt = Date(timeIntervalSince1970: value.expiresAt)
    }
}
