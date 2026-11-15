// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI
import LocalAuthentication
import SignalBridge
import UIKit

@MainActor final class ChatModel: ObservableObject {
    @Published var locked = true
    @Published var busy = false
    @Published var error: String?
    @Published private(set) var captureActive = UIScreen.main.isCaptured
    @Published private var revision = 0
    private var vault: Vault?
    private var connectionCheckedAt: Date?
    private var discoveryHighWater: Int64 = 0
    private var accessGeneration = UUID()
    private var lastInteraction = Date()
    private(set) var store: SignalStore?
    var login: LoginSession? { store?.state.login }
    var contacts: [Contact] { store?.state.contacts ?? [] }
    var messages: [ChatMessage] { store?.state.messages ?? [] }
    var pendingCount: Int { store?.state.outbox.count ?? 0 }
    var hasAccount: Bool { store?.state.ownerID != nil }

    func unlock() async {
        guard !busy, !captureActive else { return }; busy = true; defer { busy = false }
        let generation = accessGeneration
        do {
            let context = LAContext()
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your ENCPTD chats") else { return }
            guard !captureActive, generation == accessGeneration else { return }
            if store == nil {
                let disk = try Vault.onDevice(authenticationContext: context); vault = disk; store = SignalStore(state: try disk.load())
                discoveryHighWater = store?.state.discoveryRevision ?? 0
            }
            try removeExpiredMessages()
            locked = false; lastInteraction = Date(); error = nil
        } catch { lock(); self.error = error.localizedDescription }
    }
    func lock() {
        locked = true; accessGeneration = UUID(); connectionCheckedAt = nil
        store = nil; vault = nil; error = nil; revision += 1
    }
    func updateCaptureState() {
        captureActive = UIScreen.main.isCaptured
        if captureActive { lock() }
    }
    func noteActivity() { if !locked { lastInteraction = Date() } }
    func checkInactivity() { if !locked && Date().timeIntervalSince(lastInteraction) >= 60 { lock() } }
    func screenshotTaken() { lock(); error = "A screenshot was taken. It may already contain chat content. Your chats are now locked." }
    private func persist() throws {
        if let store { store.state.discoveryRevision = max(discoveryHighWater, store.state.discoveryRevision ?? 0) }
        guard let state = store?.state, let vault else { throw ChatFailure(message: "Unlock ENCPTD first.") }
        try vault.save(state); revision += 1
    }
    private func removeExpiredMessages() throws {
        guard let store else { return }
        let before = store.state, now = Date()
        let expired = Set(store.state.messages.filter { ($0.expiresAt ?? .distantFuture) <= now }.map(\.id))
        guard !expired.isEmpty else { return }
        store.state.messages.removeAll { expired.contains($0.id) }
        store.state.outbox.removeAll { expired.contains($0.messageId) }
        do { try persist() } catch { store.state = before; throw error }
    }
    private func connectionOrigin(force: Bool = false) async throws -> String {
        guard !locked, let store else { throw ChatFailure(message: "Unlock ENCPTD first.") }
        let generation = accessGeneration
        let config = try ServerConfiguration.bundled()
        try config.validate()
        let cached = store.state.connection
        let now = Date()
        if !force, let checked = connectionCheckedAt, now.timeIntervalSince(checked) < 60,
           let cached, cached.instanceID == config.instanceID, cached.revision >= discoveryHighWater, cached.expiresAt > now.timeIntervalSince1970 {
            guard let url = cached.url else { throw ChatFailure(message: "Your ENCPTD server is offline. Start it and the internet connector on the PC, then try again.") }
            return try ConnectionVerification.origin(url)
        }
        var components = URLComponents(url: config.discoveryURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "encptd", value: UUID().uuidString)]
        var lookup = URLRequest(url: components.url!, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        lookup.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        let data: Data
        do {
            let (result, response) = try await ENCPTDNetwork.session.data(for: lookup)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw ChatFailure(message: "The connection service is unavailable. Please try again shortly.")
            }
            data = result
        } catch let failure as URLError {
            // A cached address was previously signature-checked and is protected by
            // the encrypted vault. Never use it after expiry or signature failure.
            if let cached, cached.instanceID == config.instanceID, cached.revision >= discoveryHighWater, cached.expiresAt > now.timeIntervalSince1970,
               let url = cached.url { return try ConnectionVerification.origin(url) }
            throw ChatFailure(message: "Could not find your ENCPTD server. Check the phone's internet connection. \(failure.localizedDescription)")
        }
        guard !locked, generation == accessGeneration else { throw CancellationError() }
        let connection = try ConnectionVerification.verify(data, configuration: config, minimumRevision: discoveryHighWater)
        let before = store.state
        do {
            store.state.connection = connection
            store.state.discoveryRevision = connection.revision
            discoveryHighWater = connection.revision
            try persist()
        } catch { store.state = before; throw error }
        connectionCheckedAt = now
        guard let url = connection.url else { throw ChatFailure(message: "Your ENCPTD server is offline. Start it and the internet connector on the PC, then try again.") }
        return url
    }
    private struct ServerError: Decodable { var error: String }
    private struct OK: Decodable { var ok: Bool }
    private func request<T: Decodable>(_ path: String, method: String = "GET", body: Data? = nil) async throws -> T {
        let root = try await connectionOrigin()
        do { return try await perform(path, method: method, body: body, root: root) }
        catch {
            // Refresh after a failed connection so a restarted tunnel is discovered
            // immediately. Retry only if the newly signed origin actually changed.
            let retryable = error is URLError || (error as? ConnectionUnavailable) != nil
            guard retryable else { throw error }
            let updated = try await connectionOrigin(force: true)
            guard updated != root else { throw ChatFailure(message: "Your ENCPTD server is unavailable. Keep the PC and internet connector running, then try again.") }
            return try await perform(path, method: method, body: body, root: updated)
        }
    }
    private struct ConnectionUnavailable: Error {}
    private func perform<T: Decodable>(_ path: String, method: String, body: Data?, root: String) async throws -> T {
        guard !locked else { throw ChatFailure(message: "Unlock ENCPTD first.") }
        let generation = accessGeneration
        let authenticated = path != "/v1/login" && path != "/v1/register"
        let exchange = try TransportExchange(configuration: ServerConfiguration.bundled(), path: path, method: method,
            body: body, token: authenticated ? login?.token : nil)
        guard let url = URL(string: root + "/v2/transport") else { throw ChatFailure(message: "Invalid server address.") }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.httpMethod = "POST"; request.httpBody = try JSONEncoder().encode(exchange.envelope)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (wire, response) = try await ENCPTDNetwork.session.data(for: request)
        guard !locked, generation == accessGeneration else { throw CancellationError() }
        guard let http = response as? HTTPURLResponse else { throw ChatFailure(message: "Server response is unavailable.") }
        guard http.statusCode == 200 else {
            if http.statusCode >= 500 { throw ConnectionUnavailable() }
            throw ChatFailure(message: "The private server connection failed. Check that the PC server is updated. No unencrypted fallback was used.")
        }
        let reply = try exchange.open(wire), data = reply.body
        guard (200..<300).contains(reply.status) else {
            if reply.status == 401, authenticated, login != nil { store?.state.login = nil; try persist() }
            let detail = (try? JSONDecoder().decode(ServerError.self, from: data).error) ?? "Server request failed."
            throw ChatFailure(message: detail)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func signIn(username: String, password: String) async { await authenticate(username: username, password: password, registering: false) }
    func register(username: String, password: String) async { await authenticate(username: username, password: password, registering: true) }
    func changePassword(current: String, replacement: String) async {
        guard !busy, !locked, login != nil else { return }; busy = true; defer { busy = false }
        do {
            let body = try JSONSerialization.data(withJSONObject: ["oldPassword": current, "newPassword": replacement])
            let reply: LoginReply = try await request("/v1/password", method: "POST", body: body)
            guard reply.id == login?.id else { throw ChatFailure(message: "Password update response did not match your account.") }
            store?.state.login?.token = reply.token
            try persist(); error = nil
        } catch { if !locked { self.error = error.localizedDescription } }
    }
    private func authenticate(username: String, password: String, registering: Bool) async {
        guard !busy, !locked, let store else { return }; busy = true; defer { busy = false }
        do {
            if registering, hasAccount { throw ChatFailure(message: "This phone already belongs to an account. Sign in with its original username to keep your encryption keys.") }
            _ = try await connectionOrigin(force: true)
            let data = try JSONSerialization.data(withJSONObject: ["username": username.lowercased().trimmingCharacters(in: .whitespaces), "password": password])
            let result: LoginReply = try await request(registering ? "/v1/register" : "/v1/login", method: "POST", body: data)
            guard UUID(uuidString: result.id) != nil, result.token.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
                  let origin = store.state.connection?.url else { throw ChatFailure(message: "Invalid sign-in response.") }
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
            let expiry = now.addingTimeInterval(86400)
            let clear = try JSONEncoder().encode(MessageContent(text: text, created: now, expiresAt: expiry))
            let cipher = try signalEncrypt(message: clear, for: address, localAddress: local, sessionStore: store, identityStore: store, context: NullContext())
            guard cipher.messageType == .preKey || cipher.messageType == .whisper else { throw ChatFailure(message: "An encrypted message could not be created.") }
            store.state.outbox.append(OutgoingPacket(messageId: messageID, recipient: contact.id, kind: cipher.messageType.rawValue, ciphertext: cipher.serialize()))
            store.state.messages.append(ChatMessage(id: messageID, contactID: contact.id, text: text, outgoing: true, date: now, pending: true, expiresAt: expiry))
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
            try removeExpiredMessages()
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
                    if message.expiresAt == nil || message.expiresAt! > Date() {
                        store.state.messages.append(ChatMessage(id: packet.messageId, contactID: contact.id, text: message.text, outgoing: false, date: message.created, pending: false, expiresAt: message.expiresAt))
                    }
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
