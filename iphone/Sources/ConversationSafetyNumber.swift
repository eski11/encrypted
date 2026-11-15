// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import SignalBridge

enum ConversationSafetyNumber {
    static func make(ownerID: String, identity: IdentityKeyPair, contact: Contact) throws -> String {
        let digits = try NumericFingerprintGenerator(iterations: 5200).create(version: 2,
            localIdentifier: Data(ownerID.utf8), localKey: identity.publicKey,
            remoteIdentifier: Data(contact.id.utf8), remoteKey: PublicKey(contact.identityKey)).displayable.formatted
        // Explicit groups prevent a long, unbroken number from being truncated on small phones.
        let characters = Array(digits)
        return stride(from: 0, to: characters.count, by: 5).enumerated().map { index, start in
            (index == 0 ? "" : index.isMultiple(of: 4) ? "\n" : " ") + String(characters[start..<min(start + 5, characters.count)])
        }.joined()
    }
}
