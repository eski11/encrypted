// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI
import LocalAuthentication
import SignalBridge
import UIKit
import CryptoKit

@MainActor final class ChatModel: ObservableObject {
    @Published var locked = true
    @Published var busy = false
    @Published var error: String?
    @Published private(set) var captureActive = UIScreen.main.isCaptured
    @Published private var revision = 0
    @Published private(set) var deviceAuthorized = false
    @Published private(set) var awaitingPasscode = false
    @Published private(set) var profiles: [LocalAccount] = []
    @Published private(set) var protection = AccountProtection()
    @Published private(set) var securityPending = false
    @Published private(set) var selectedLocalID: String?
    private var accounts: AccountVaults?
    private var stagedLogin: LoginReply?
    private var processingDeletions = false
    private var activeDeletionDeadline: Date?
    private var securityChangeToken: String?
    private let backgroundSync = BackgroundWork()
    private var safetyAccess: (token: UUID, contactID: String)?
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
    var selectedAccount: LocalAccount? { profiles.first { $0.id == selectedLocalID } }
    var pendingDeletionCount: Int { accounts?.index.pendingDeletes.count ?? 0 }
    private static let publicSecurityPaths: Set<String> = ["/v1/security/confirm", "/v1/security/challenge", "/v1/security/unlock", "/v1/security/destroy"]

    // Polling never publishes the foreground busy state or disables text fields.
    // Cancel and drain it before a user action takes a vault snapshot or changes policy.
    private func stopSyncForAction() async {
        await backgroundSync.cancelAndWait()
    }

    func unlock() async {
        guard !busy, !captureActive else { return }; busy = true; defer { busy = false }
        let generation = accessGeneration
        do {
            let context = LAContext()
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your ENCPTD chats") else { return }
            guard !captureActive, generation == accessGeneration else { return }
            let saved = try AccountVaults.onDevice(context: context)
            accounts = saved; deviceAuthorized = true
            discoveryHighWater = max(discoveryHighWater, saved.index.discoveryRevision)
            refreshAccounts(); error = nil
            if let active = saved.index.activeID, profiles.contains(where: { $0.id == active }) {
                try activateProfile(active)
            } else if profiles.isEmpty {
                let profile = try saved.createDraft(); refreshAccounts(); try activateProfile(profile.id)
            }
            if saved.expiredRemovals > 0 { error = "An account reached its inactivity deadline and was removed from this phone. Its server deletion is queued if offline." }
            Task { await self.flushDeletionJobs() }
        } catch { lock(); self.error = error.localizedDescription }
    }
    func lock() {
        backgroundSync.cancel()
        safetyAccess = nil
        locked = true; accessGeneration = UUID(); connectionCheckedAt = nil
        store = nil; vault = nil; error = nil; revision += 1
        accounts = nil; stagedLogin = nil; deviceAuthorized = false; awaitingPasscode = false
        profiles = []; selectedLocalID = nil; protection = AccountProtection(); securityPending = false
        activeDeletionDeadline = nil
        securityChangeToken = nil
    }
    private func refreshAccounts() { profiles = accounts?.index.profiles ?? []; revision += 1 }
    private func clearOpenedProfile() {
        backgroundSync.cancel()
        safetyAccess = nil
        locked = true; awaitingPasscode = false; accessGeneration = UUID(); connectionCheckedAt = nil
        store = nil; vault = nil; error = nil; selectedLocalID = nil; revision += 1
        activeDeletionDeadline = nil
        securityChangeToken = nil
    }
    func showAccounts() {
        guard !busy, accounts != nil else { return }
        clearOpenedProfile(); stagedLogin = nil; refreshAccounts()
    }
    func addAccount() {
        guard !busy, let accounts else { return }
        do {
            clearOpenedProfile(); stagedLogin = nil
            let profile: LocalAccount
            if let draft = accounts.index.profiles.first(where: { $0.accountID == nil }) { profile = draft }
            else { profile = try accounts.createDraft() }
            refreshAccounts(); try activateProfile(profile.id)
        } catch { self.error = error.localizedDescription }
    }
    func selectAccount(_ id: String) {
        guard !busy, let accounts else { return }
        do {
            clearOpenedProfile(); stagedLogin = nil
            try accounts.sweepExpired(); refreshAccounts(); try activateProfile(id)
        } catch { self.error = error.localizedDescription; refreshAccounts() }
    }
    private func activateProfile(_ id: String, passcode: String? = nil) throws {
        guard let accounts else { throw ChatFailure(message: "Unlock the phone first.") }
        try accounts.select(id); selectedLocalID = id
        let record = try accounts.secret(id)
        protection = record.protection; securityPending = record.remote?.needsConfirmation != false && record.remote != nil
        activeDeletionDeadline = record.protection.inactivityDays.map { record.lastSuccess.addingTimeInterval(Double($0) * 86400) }
        let disk: Vault
        do { disk = try accounts.open(id, passcode: passcode) }
        catch AccountAccessError.needsPasscode { awaitingPasscode = true; locked = true; return }
        let state = try disk.load()
        let loaded = SignalStore(state: state)
        if let stagedLogin {
            guard stagedLogin.id == state.ownerID, let origin = accounts.index.connection?.url else { throw ChatFailure(message: "Sign in using this saved account's original identity.") }
            loaded.state.login = LoginSession(id: stagedLogin.id, username: stagedLogin.username, token: stagedLogin.token, serverURL: origin)
            try disk.save(loaded.state); self.stagedLogin = nil
        }
        if let owner = loaded.state.ownerID {
            try accounts.bind(id, accountID: owner, username: loaded.state.login?.username ?? selectedAccount?.username ?? "Saved account")
        }
        vault = disk; store = loaded
        discoveryHighWater = max(discoveryHighWater, loaded.state.discoveryRevision ?? 0)
        if passcode != nil, let counter = try accounts.secret(id).remote?.unlockCounter, counter > 0 {
            loaded.state.pendingPasscodeCounter = counter; try persist()
        }
        try removeExpiredMessages()
        let opened = try accounts.secret(id)
        activeDeletionDeadline = opened.protection.inactivityDays.map { opened.lastSuccess.addingTimeInterval(Double($0) * 86400) }
        awaitingPasscode = false; locked = false; lastInteraction = Date(); error = nil; refreshAccounts()
    }
    func submitPasscode(_ code: String) async {
        guard !busy, awaitingPasscode, !captureActive, let id = selectedLocalID else { return }
        busy = true; defer { busy = false }
        do {
            try activateProfile(id, passcode: code)
            try await reportPasscodeUnlock()
        } catch let failure as AccountAccessError {
            switch failure {
            case .deleted, .deletionPending:
                clearOpenedProfile(); stagedLogin = nil; refreshAccounts(); error = failure.localizedDescription
                Task { await self.flushDeletionJobs() }
            default: self.error = failure.localizedDescription
            }
        } catch { self.error = error.localizedDescription }
    }
    func updateCaptureState() {
        captureActive = UIScreen.main.isCaptured
        if captureActive { lock() }
    }
    func noteActivity() { if !locked { lastInteraction = Date() } }
    func checkInactivity() {
        if let deadline = activeDeletionDeadline, Date() >= deadline, let accounts, let id = selectedLocalID {
            do {
                try accounts.destroy(id); clearOpenedProfile(); stagedLogin = nil; refreshAccounts()
                error = AccountAccessError.deleted.localizedDescription
                Task { await self.flushDeletionJobs() }
            } catch { lock(); self.error = error.localizedDescription }
            return
        }
        if !locked && Date().timeIntervalSince(lastInteraction) >= 60 { lock() }
    }
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
        guard let accounts, deviceAuthorized, !captureActive else { throw ChatFailure(message: "Unlock ENCPTD first.") }
        let generation = accessGeneration
        let config = try ServerConfiguration.bundled()
        try config.validate()
        let cached = accounts.index.connection ?? store?.state.connection
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
        guard deviceAuthorized, generation == accessGeneration else { throw CancellationError() }
        let connection = try ConnectionVerification.verify(data, configuration: config, minimumRevision: discoveryHighWater)
        try accounts.saveConnection(connection)
        discoveryHighWater = connection.revision
        connectionCheckedAt = now
        guard let url = connection.url else { throw ChatFailure(message: "Your ENCPTD server is offline. Start it and the internet connector on the PC, then try again.") }
        return url
    }
    private struct ServerError: Decodable { var error: String }
    private struct APIError: LocalizedError { var status: Int; var message: String; var errorDescription: String? { message } }
    private struct OK: Decodable { var ok: Bool }
    private func request<T: Decodable>(_ path: String, method: String = "GET", body: Data? = nil) async throws -> T {
        try Task.checkCancellation()
        let generation = accessGeneration
        let root = try await connectionOrigin()
        guard generation == accessGeneration else { throw CancellationError() }
        do { return try await perform(path, method: method, body: body, root: root) }
        catch {
            try Task.checkCancellation()
            // Refresh after a failed connection so a restarted tunnel is discovered
            // immediately. Retry only if the newly signed origin actually changed.
            let retryable = error is URLError || (error as? ConnectionUnavailable) != nil
            guard retryable else { throw error }
            let updated = try await connectionOrigin(force: true)
            guard generation == accessGeneration else { throw CancellationError() }
            guard updated != root else { throw ChatFailure(message: "Your ENCPTD server is unavailable. Keep the PC and internet connector running, then try again.") }
            return try await perform(path, method: method, body: body, root: updated)
        }
    }
    private struct ConnectionUnavailable: Error {}
    private func perform<T: Decodable>(_ path: String, method: String, body: Data?, root: String) async throws -> T {
        let publicSecurity = Self.publicSecurityPaths.contains(path)
        guard (!locked || publicSecurity), deviceAuthorized, !captureActive else { throw ChatFailure(message: "Unlock ENCPTD first.") }
        let generation = accessGeneration
        let authenticated = path != "/v1/login" && path != "/v1/register" && !publicSecurity
        let exchange = try TransportExchange(configuration: ServerConfiguration.bundled(), path: path, method: method,
            body: body, token: authenticated ? login?.token : nil)
        guard let url = URL(string: root + "/v2/transport") else { throw ChatFailure(message: "Invalid server address.") }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.httpMethod = "POST"; request.httpBody = try JSONEncoder().encode(exchange.envelope)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (wire, response) = try await ENCPTDNetwork.session.data(for: request)
        try Task.checkCancellation()
        guard (!locked || publicSecurity), deviceAuthorized, generation == accessGeneration else { throw CancellationError() }
        guard let http = response as? HTTPURLResponse else { throw ChatFailure(message: "Server response is unavailable.") }
        guard http.statusCode == 200 else {
            if http.statusCode >= 500 { throw ConnectionUnavailable() }
            throw ChatFailure(message: "The private server connection failed. Check that the PC server is updated. No unencrypted fallback was used.")
        }
        let reply = try exchange.open(wire), data = reply.body
        guard (200..<300).contains(reply.status) else {
            if reply.status == 401, authenticated, login != nil { store?.state.login = nil; try persist() }
            let detail = (try? JSONDecoder().decode(ServerError.self, from: data).error) ?? "Server request failed."
            throw APIError(status: reply.status, message: detail)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func signIn(username: String, password: String) async { await authenticate(username: username, password: password, registering: false) }
    func register(username: String, password: String) async { await authenticate(username: username, password: password, registering: true) }
    func changePassword(current: String, replacement: String) async {
        guard !busy, !locked, login != nil else { return }; busy = true; defer { busy = false }
        let generation = accessGeneration
        await stopSyncForAction()
        guard !locked, generation == accessGeneration else { return }
        do {
            let body = try JSONSerialization.data(withJSONObject: ["oldPassword": current, "newPassword": replacement])
            let reply: LoginReply = try await request("/v1/password", method: "POST", body: body)
            guard reply.id == login?.id else { throw ChatFailure(message: "Password update response did not match your account.") }
            store?.state.login?.token = reply.token
            try persist(); error = nil
        } catch { if !locked { self.error = error.localizedDescription } }
    }
    private func authenticate(username: String, password: String, registering: Bool) async {
        guard !busy, !locked, var store, let accounts else { return }; busy = true; defer { busy = false }
        let generation = accessGeneration
        await stopSyncForAction()
        guard !locked, generation == accessGeneration else { return }
        do {
            _ = try await connectionOrigin(force: true)
            let data = try JSONSerialization.data(withJSONObject: ["username": username.lowercased().trimmingCharacters(in: .whitespaces), "password": password])
            let result: LoginReply = try await request(registering ? "/v1/register" : "/v1/login", method: "POST", body: data)
            guard UUID(uuidString: result.id) != nil, result.token.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
                  let origin = accounts.index.connection?.url else { throw ChatFailure(message: "Invalid sign-in response.") }
            guard !accounts.index.pendingDeletes.contains(where: { $0.accountID == result.id }) else { throw ChatFailure(message: "This account is already queued for permanent deletion and cannot be added again.") }
            if let existing = profiles.first(where: { $0.accountID == result.id && $0.id != selectedLocalID }) {
                clearOpenedProfile(); stagedLogin = result; try activateProfile(existing.id)
                if awaitingPasscode { return }
                guard let current = self.store else { return }; store = current
            } else if let owner = store.state.ownerID, owner != result.id {
                clearOpenedProfile()
                let draft = try accounts.createDraft(); refreshAccounts(); stagedLogin = nil; try activateProfile(draft.id)
                guard let current = self.store else { return }; store = current
            }
            let old = store.state
            do {
                store.state.ownerID = result.id
                store.state.login = LoginSession(id: result.id, username: result.username, token: result.token, serverURL: origin)
                if store.state.signedKeys.isEmpty { try store.prepareKeys() }
                try persist()
                if let id = selectedLocalID { try accounts.bind(id, accountID: result.id, username: result.username); refreshAccounts() }
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
        let generation = accessGeneration
        await stopSyncForAction()
        guard !locked, generation == accessGeneration else { return nil }
        do {
            guard username.range(of: "^[a-z0-9_]{3,32}$", options: .regularExpression) != nil else { throw ChatFailure(message: "Enter the person's ENCPTD username.") }
            try await checkPublishedIdentity()
            struct Lookup: Decodable { var id: String; var username: String; var identityKey: Data }
            let found: Lookup = try await request("/v1/users/\(username)")
            guard found.id != login?.id else { throw ChatFailure(message: "Enter another person's username.") }
            self.error = nil
            return Contact(id: found.id, username: found.username, identityKey: found.identityKey)
        } catch { self.error = error.localizedDescription; return nil }
    }
    private func checkPublishedIdentity() async throws {
        guard let store else { throw ChatFailure(message: "Unlock ENCPTD first.") }
        let inventory: DeviceInventory = try await request("/v1/device")
        guard inventory.identityKey == (try store.identityKeyPair(context: NullContext()).publicKey.serialize()) else {
            throw ChatFailure(message: "This phone's encryption identity does not match this account's published key. Do not verify contacts or send messages. Use the original paired installation; do not delete the app to troubleshoot.")
        }
    }
    func authorizeSafetyNumbers(_ code: String, contactID: String) -> UUID? {
        safetyAccess = nil
        guard !busy, !locked, let accounts, let id = selectedLocalID, let store else { return nil }
        guard protection.requirePasscode else { error = "Set an app passcode in Account → Passcode and automatic deletion before viewing safety numbers."; return nil }
        do {
            _ = try accounts.open(id, passcode: code)
            let record = try accounts.secret(id)
            activeDeletionDeadline = record.protection.inactivityDays.map { record.lastSuccess.addingTimeInterval(Double($0) * 86400) }
            store.state.pendingPasscodeCounter = record.remote?.unlockCounter
            try persist(); noteActivity(); error = nil
            let token = UUID()
            safetyAccess = (token, contactID)
            return token
        } catch let failure as AccountAccessError {
            switch failure {
            case .deleted, .deletionPending:
                clearOpenedProfile(); stagedLogin = nil; refreshAccounts()
                Task { await self.flushDeletionJobs() }
            default: break
            }
            error = failure.localizedDescription
        } catch { self.error = error.localizedDescription }
        return nil
    }
    func revokeSafetyNumbers(_ token: UUID?) {
        if safetyAccess?.token == token { safetyAccess = nil }
    }
    private func requireSafetyAccess(_ token: UUID, contact: Contact) throws {
        guard !locked, !captureActive, safetyAccess?.token == token, safetyAccess?.contactID == contact.id else {
            throw ChatFailure(message: "Enter the app passcode to view or verify safety numbers.")
        }
    }
    func safetyNumber(_ contact: Contact, authorization: UUID) throws -> String {
        try requireSafetyAccess(authorization, contact: contact)
        guard let store, let me = store.state.ownerID else { throw ChatFailure(message: "Sign in first.") }
        return try ConversationSafetyNumber.make(ownerID: me, identity: store.identityKeyPair(context: NullContext()), contact: contact)
    }
    func verify(_ contact: Contact, authorization: UUID) {
        guard !busy, let store else { return }
        let before = store.state
        do {
            try requireSafetyAccess(authorization, contact: contact)
            _ = try safetyNumber(contact, authorization: authorization)
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
        let generation = accessGeneration
        await stopSyncForAction()
        guard !locked, generation == accessGeneration else { return }
        let before = store.state
        do {
            guard store.state.trusted[contact.id] == contact.identityKey else { throw ChatFailure(message: "Verify the contact's current safety number.") }
            try await checkPublishedIdentity()
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
        guard !busy else { return }
        await backgroundSync.run { await self.syncInBackground() }
    }
    private func syncInBackground() async {
        if deviceAuthorized { await flushDeletionJobs() }
        guard !Task.isCancelled, !busy, !locked, let store else { return }
        do {
            try await reportPasscodeUnlock()
            guard let me = login else { return }
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
        } catch {
            if !Task.isCancelled, !locked { self.error = error.localizedDescription }
        }
    }
    private struct ProtectionReply: Decodable { var version: Int; var wipeAfterThree: Bool; var inactivityDays: Int?; var lastUnlockAt: Double?; var deadline: Double?; var changeToken: String? }
    private struct UnlockChallenge: Decodable { var nonce: String; var version: Int; var expiresAt: Double }
    private func confirmProtection(_ id: String) async throws {
        guard let accounts, let profile = profiles.first(where: { $0.id == id }), let accountID = profile.accountID,
              let remote = try accounts.secret(id).remote, remote.needsConfirmation != false else { return }
        let body = try JSONSerialization.data(withJSONObject: ["accountID": accountID, "commitToken": remote.commitToken])
        let _: ProtectionReply = try await request("/v1/security/confirm", method: "POST", body: body)
        try accounts.markConfirmed(id); securityPending = false
    }
    private func reportPasscodeUnlock() async throws {
        guard let accounts, let id = selectedLocalID, let store else { return }
        do {
            try await confirmProtection(id)
            guard let counter = store.state.pendingPasscodeCounter, let owner = store.state.ownerID,
                  let signingBytes = store.state.securitySigningKey, let remote = try accounts.secret(id).remote else { return }
            let body = try JSONSerialization.data(withJSONObject: ["accountID": owner, "unlockToken": remote.unlockToken])
            let challenge: UnlockChallenge = try await request("/v1/security/challenge", method: "POST", body: body)
            guard challenge.version == remote.version else { throw ChatFailure(message: "Account security settings changed. Reopen Settings before updating them.") }
            let message = Data("ENCPTD-unlock-v1|\(owner)|\(challenge.nonce)|\(challenge.version)|\(counter)".utf8)
            let signature = try Curve25519.Signing.PrivateKey(rawRepresentation: signingBytes).signature(for: message)
            let proof = try JSONSerialization.data(withJSONObject: ["accountID": owner, "nonce": challenge.nonce, "counter": counter, "signature": signature.base64EncodedString()])
            let reply: ProtectionReply = try await request("/v1/security/unlock", method: "POST", body: proof)
            securityChangeToken = reply.changeToken
            if store.state.pendingPasscodeCounter == counter { store.state.pendingPasscodeCounter = nil; try persist() }
        } catch let failure as APIError where failure.status == 410 {
            do { try accounts.destroy(id) }
            catch { clearOpenedProfile(); stagedLogin = nil; refreshAccounts(); throw AccountAccessError.deletionPending }
            clearOpenedProfile(); stagedLogin = nil; refreshAccounts()
            throw AccountAccessError.deleted
        }
    }
    func saveProtection(_ value: AccountProtection, currentCode: String, newCode: String, password: String) async -> Bool {
        guard !busy, !locked, let accounts, let id = selectedLocalID, let vault, let store else { return false }
        busy = true; defer { busy = false }
        safetyAccess = nil
        let generation = accessGeneration
        await stopSyncForAction()
        guard !locked, generation == accessGeneration else { return false }
        do {
            if protection.requirePasscode {
                _ = try accounts.open(id, passcode: currentCode)
                store.state.pendingPasscodeCounter = try accounts.secret(id).remote?.unlockCounter
                try persist(); try await reportPasscodeUnlock()
            } else if let event = try accounts.settingsUnlockEvent(id) {
                store.state.pendingPasscodeCounter = event; try persist(); try await reportPasscodeUnlock()
            }
            let chosenCode = newCode.isEmpty ? currentCode : newCode
            if value.requirePasscode, !AppPasscodeCrypto.valid(chosenCode) { throw ChatFailure(message: "Choose a six-digit app passcode.") }
            if !value.requirePasscode && (value.wipeAfterThree || value.inactivityDays != nil) { throw ChatFailure(message: "Automatic deletion requires an app passcode.") }
            if store.state.securitySigningKey == nil { store.state.securitySigningKey = Curve25519.Signing.PrivateKey().rawRepresentation; try persist() }
            let signing = try Curve25519.Signing.PrivateKey(rawRepresentation: store.state.securitySigningKey!)
            let body = try JSONSerialization.data(withJSONObject: ["password": password, "wipeAfterThree": value.wipeAfterThree,
                "inactivityDays": value.inactivityDays.map { $0 as Any } ?? NSNull(), "signingPublicKey": signing.publicKey.rawRepresentation.base64EncodedString(),
                "changeToken": securityChangeToken.map { $0 as Any } ?? NSNull()])
            let remote: RemoteProtection = try await request("/v1/security/prepare", method: "POST", body: body)
            try accounts.configure(id, vault: vault, protection: value, passcode: value.requirePasscode ? chosenCode : nil, remote: remote)
            let saved = try accounts.secret(id)
            activeDeletionDeadline = value.inactivityDays.map { saved.lastSuccess.addingTimeInterval(Double($0) * 86400) }
            protection = value; securityPending = true; store.state.pendingPasscodeCounter = nil; try persist()
            try await confirmProtection(id); error = nil
            return true
        } catch let failure as AccountAccessError {
            switch failure {
            case .deleted, .deletionPending:
                clearOpenedProfile(); stagedLogin = nil; refreshAccounts(); error = failure.localizedDescription
                Task { await self.flushDeletionJobs() }
            default: self.error = failure.localizedDescription
            }
        } catch { self.error = error.localizedDescription }
        return false
    }
    private func flushDeletionJobs() async {
        guard !processingDeletions, let accounts, deviceAuthorized, !captureActive else { return }
        let generation = accessGeneration
        processingDeletions = true; defer { processingDeletions = false }
        for job in accounts.index.pendingDeletes {
            do {
                let body = try JSONEncoder().encode(job)
                let _: OK = try await request("/v1/security/destroy", method: "POST", body: body)
                guard self.accounts === accounts, generation == accessGeneration else { return }
                try accounts.acknowledgeDeletion(job.accountID)
                refreshAccounts()
                if error == AccountAccessError.deleted.localizedDescription { error = "Account deleted from this phone and the PC server." }
            } catch { return }
        }
    }
}
