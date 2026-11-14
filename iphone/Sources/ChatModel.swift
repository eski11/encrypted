// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI
import LocalAuthentication
import SignalBridge

@MainActor final class ChatModel: ObservableObject {
    @Published var locked = true
    @Published var busy = false
    @Published var error: String?
    @Published private var revision = 0
    private var vault: Vault?
    private(set) var store: SignalStore?
    var login: LoginSession? { store?.state.login }
    var contacts: [Contact] { store?.state.contacts ?? [] }
    var messages: [ChatMessage] { store?.state.messages ?? [] }
    var pendingCount: Int { store?.state.outbox.count ?? 0 }
    var defaultServer: String {
        guard let url = Bundle.main.url(forResource: "Server", withExtension: "json"),
              let data = try? Data(contentsOf: url), let value = try? JSONDecoder().decode([String: String].self, from: data) else { return "" }
        return value["url"] ?? ""
    }

    func unlock() async {
        guard !busy else { return }; busy = true; defer { busy = false }
        do {
            let context = LAContext()
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your ENCPTD chats") else { return }
            if store == nil { let disk = try Vault.onDevice(); vault = disk; store = SignalStore(state: try disk.load()) }
            locked = false; error = nil
        } catch { self.error = error.localizedDescription }
    }
    func lock() { locked = true }
    private func persist() throws {
        guard let state = store?.state, let vault else { throw ChatFailure(message: "Unlock ENCPTD first.") }
        try vault.save(state); revision += 1
    }
    private func serverOrigin(_ value: String) throws -> String {
        guard let url = URL(string: value.trimmingCharacters(in: .whitespacesAndNewlines)), url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/" else {
            throw ChatFailure(message: "Use the HTTPS server address shown on your PC.")
        }
        return url.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }
    private struct ServerError: Decodable { var error: String }
    private struct OK: Decodable { var ok: Bool }
    private func request<T: Decodable>(_ path: String, method: String = "GET", body: Data? = nil, session: LoginSession? = nil, origin: String? = nil) async throws -> T {
        let current = session ?? login
        let root = try serverOrigin(origin ?? current?.serverURL ?? "")
        guard let url = URL(string: root + path) else { throw ChatFailure(message: "Invalid server address.") }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.httpMethod = method; request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if path != "/v1/login", let current { request.setValue("Bearer \(current.token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ChatFailure(message: "Server response is unavailable.") }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401, login != nil { store?.state.login = nil; try persist() }
            let detail = (try? JSONDecoder().decode(ServerError.self, from: data).error) ?? "Server request failed."
            throw ChatFailure(message: detail)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func signIn(server: String, username: String, password: String) async {
        guard !busy, !locked, let store else { return }; busy = true; defer { busy = false }
        do {
            let origin = try serverOrigin(server)
            let data = try JSONSerialization.data(withJSONObject: ["username": username.lowercased().trimmingCharacters(in: .whitespaces), "password": password])
            let result: LoginReply = try await request("/v1/login", method: "POST", body: data, origin: origin)
            guard store.state.ownerID == nil || store.state.ownerID == result.id else { throw ChatFailure(message: "This installation belongs to another account. Use its original account to preserve your encryption keys.") }
            let old = store.state
            do {
                store.state.ownerID = result.id
                store.state.login = LoginSession(id: result.id, username: result.username, token: result.token, serverURL: origin)
                if store.state.signedKeys.isEmpty { try store.prepareKeys() }
                try persist()
            } catch { store.state = old; throw error }
            try await publishKeys(); self.error = nil
        } catch { self.error = error.localizedDescription }
    }
    private func publishKeys() async throws {
        guard let store else { return }
        let _: OK = try await request("/v1/device", method: "PUT", body: JSONEncoder().encode(store.publication()))
    }
    func findContact(_ username: String) async -> Contact? {
        guard !busy, !locked else { return nil }; busy = true; defer { busy = false }
        do {
            guard username.range(of: "^[a-z0-9_]{3,32}$", options: .regularExpression) != nil else { throw ChatFailure(message: "Enter the person's ENCPTD username.") }
            struct Lookup: Decodable { var id: String; var username: String; var identityKey: Data }
            let found: Lookup = try await request("/v1/users/\(username)")
            guard found.id != login?.id else { throw ChatFailure(message: "Enter another person's username.") }
            return Contact(id: found.id, username: found.username, identityKey: found.identityKey)
        } catch { self.error = error.localizedDescription; return nil }
    }
    func safetyNumber(_ contact: Contact) throws -> String {
        guard let store, let me = store.state.ownerID else { throw ChatFailure(message: "Sign in first.") }
        return try NumericFingerprintGenerator(iterations: 5200).create(version: 2,
            localIdentifier: Data(me.utf8), localKey: store.identityKeyPair(context: NullContext()).publicKey,
            remoteIdentifier: Data(contact.id.utf8), remoteKey: PublicKey(contact.identityKey)).displayable.formatted
    }
    func verify(_ contact: Contact) {
        guard !busy, let store else { return }
        let before = store.state
        do {
            if let old = store.state.trusted[contact.id], old != contact.identityKey { store.state.sessions.removeValue(forKey: contact.id) }
            store.state.trusted[contact.id] = contact.identityKey
            var verified = contact; verified.verified = true
            store.state.contacts.removeAll { $0.id == contact.id }; store.state.contacts.append(verified)
            try persist(); error = nil
        } catch { store.state = before; self.error = error.localizedDescription }
    }
    func send(_ text: String, to contact: Contact) async {
        guard !busy, !locked, let store, let me = login, contact.verified else { return }
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, text.utf8.count <= 8192 else { error = "Send text between 1 and 8192 bytes."; return }
        busy = true; defer { busy = false }
        let before = store.state
        do {
            guard store.state.trusted[contact.id] == contact.identityKey else { throw ChatFailure(message: "Verify the contact's current safety number.") }
            let address = try ProtocolAddress(name: contact.id, deviceId: 1), local = try ProtocolAddress(name: me.id, deviceId: 1)
            if try store.loadSession(for: address, context: NullContext())?.hasCurrentState != true {
                let remote: RemoteBundle = try await request("/v1/keys/\(contact.id)/claim", method: "POST")
                guard remote.identityKey == contact.identityKey else { throw ChatFailure(message: "This person's key changed. Find them again and verify the new safety number.") }
                try processPreKeyBundle(remote.signalBundle(), for: address, ourAddress: local, sessionStore: store, identityStore: store, context: NullContext())
            }
            let now = Date(), messageID = UUID().uuidString.lowercased()
            let clear = try JSONEncoder().encode(MessageContent(text: text, created: now))
            let cipher = try signalEncrypt(message: clear, for: address, localAddress: local, sessionStore: store, identityStore: store, context: NullContext())
            guard cipher.messageType == .preKey || cipher.messageType == .whisper else { throw ChatFailure(message: "An encrypted message could not be created.") }
            store.state.outbox.append(OutgoingPacket(messageId: messageID, recipient: contact.id, kind: cipher.messageType.rawValue, ciphertext: cipher.serialize()))
            store.state.messages.append(ChatMessage(id: messageID, contactID: contact.id, text: text, outgoing: true, date: now, pending: true))
            try persist()
        } catch { store.state = before; self.error = error.localizedDescription; return }
        do { try await flushOutbox(); error = nil }
        catch { self.error = "Saved on this phone and queued. \(error.localizedDescription)" }
    }
    private func flushOutbox() async throws {
        guard let store else { return }
        for packet in store.state.outbox {
            let _: OK = try await request("/v1/messages", method: "POST", body: JSONEncoder().encode(packet))
            let before = store.state
            do {
                store.state.outbox.removeAll { $0.messageId == packet.messageId }
                if let index = store.state.messages.firstIndex(where: { $0.id == packet.messageId }) { store.state.messages[index].pending = false }
                try persist()
            } catch { store.state = before; throw error }
        }
    }
    func sync() async {
        guard !busy, !locked, let store, let me = login else { return }; busy = true; defer { busy = false }
        do {
            try await flushOutbox()
            let inbox: Inbox = try await request("/v1/inbox")
            var acknowledged: [Int] = []
            for packet in inbox.messages {
                let marker = "\(packet.sender):\(packet.messageId)"
                if store.state.receivedIDs.contains(marker) { acknowledged.append(packet.seq); continue }
                guard let contact = store.state.contacts.first(where: { $0.id == packet.sender }), contact.verified else {
                    error = "New message from @\(packet.senderUsername). Add this person and compare safety numbers before opening it."
                    continue
                }
                let before = store.state
                do {
                    let remote = try ProtocolAddress(name: packet.sender, deviceId: 1), local = try ProtocolAddress(name: me.id, deviceId: 1)
                    let clear: Data
                    if packet.kind == CiphertextMessage.MessageType.preKey.rawValue {
                        clear = try signalDecryptPreKey(message: PreKeySignalMessage(bytes: packet.ciphertext), from: remote, localAddress: local,
                            sessionStore: store, identityStore: store, preKeyStore: store, signedPreKeyStore: store, kyberPreKeyStore: store, context: NullContext())
                    } else if packet.kind == CiphertextMessage.MessageType.whisper.rawValue {
                        clear = try signalDecrypt(message: SignalMessage(bytes: packet.ciphertext), from: remote, to: local, sessionStore: store, identityStore: store, context: NullContext())
                    } else { throw ChatFailure(message: "Unencrypted message type rejected.") }
                    let message = try JSONDecoder().decode(MessageContent.self, from: clear)
                    guard message.version == 1, message.text.utf8.count <= 8192 else { throw ChatFailure(message: "Unsupported message content.") }
                    store.state.messages.append(ChatMessage(id: packet.messageId, contactID: contact.id, text: message.text, outgoing: false, date: message.created, pending: false))
                    store.state.receivedIDs.insert(marker); try persist(); acknowledged.append(packet.seq)
                } catch { store.state = before; self.error = "Could not decrypt a message from @\(contact.username). It remains in your inbox." }
            }
            if !acknowledged.isEmpty { let _: OK = try await request("/v1/inbox/ack", method: "POST", body: JSONEncoder().encode(Acknowledgement(sequences: acknowledged))) }
            var inventory: DeviceInventory = try await request("/v1/device")
            if min(inventory.preKeys, inventory.kyberPreKeys) < 10 {
                try await publishKeys()
                inventory = try await request("/v1/device")
            }
            if min(inventory.preKeys, inventory.kyberPreKeys) < 10 {
                let before = store.state
                do { try store.prepareKeys(count: 15); try persist() } catch { store.state = before; throw error }
                try await publishKeys()
            }
        } catch { self.error = error.localizedDescription }
    }
}
