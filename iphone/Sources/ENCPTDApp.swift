// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI

@main struct ENCPTDApp: App {
    @StateObject private var model = ChatModel()
    @Environment(\.scenePhase) private var scene
    var body: some Scene {
        WindowGroup {
            Group {
                if model.locked { UnlockScreen() }
                else if model.login == nil { NavigationStack { SignInScreen() } }
                else { ContactsScreen() }
            }
            .environmentObject(model)
            .tint(Color(red: 0.68, green: 0.54, blue: 1))
            .preferredColorScheme(.dark)
            .privacySensitive()
            .overlay {
                if scene != .active { Color(red: 0.06, green: 0.06, blue: 0.1).ignoresSafeArea().overlay(Image(systemName: "lock.shield.fill").font(.system(size: 56))) }
            }
            .safeAreaInset(edge: .bottom) {
                if !model.locked, let error = model.error {
                    HStack(alignment: .top) {
                        Text(error).font(.footnote)
                        Spacer()
                        Button { model.error = nil } label: { Image(systemName: "xmark.circle.fill") }
                    }.padding().background(.ultraThinMaterial)
                }
            }
            .onChange(of: scene) { _, phase in if phase == .background { model.lock() } }
            .task {
                while !Task.isCancelled {
                    await model.sync()
                    do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { break }
                }
            }
        }
    }
}

struct UnlockScreen: View {
    @EnvironmentObject var model: ChatModel
    var body: some View {
        VStack(spacing: 28) {
            Image(systemName: "lock.shield.fill").font(.system(size: 72)).foregroundStyle(.purple)
            Text("ENCPTD").font(.largeTitle.bold()).tracking(5)
            Text("Your conversations. Your server.").foregroundStyle(.secondary)
            Button { Task { await model.unlock() } } label: { Label("Unlock", systemImage: "faceid").frame(maxWidth: .infinity) }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy)
            if let error = model.error { Text(error).font(.footnote).foregroundStyle(.orange) }
        }.padding(36)
    }
}

struct SignInScreen: View {
    @EnvironmentObject var model: ChatModel
    @Environment(\.dismiss) var dismiss
    @State private var server = ""
    @State private var username = ""
    @State private var password = ""
    var body: some View {
        Form {
            Section {
                Text("Connect to the ENCPTD server running on your PC.").foregroundStyle(.secondary)
                TextField("https://your-server-address", text: $server).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            } header: { Text("Your server") }
            Section {
                TextField("Username", text: $username).textInputAutocapitalization(.never).autocorrectionDisabled().textContentType(.username)
                SecureField("Password", text: $password).textContentType(.password)
                Button {
                    Task {
                        await model.signIn(server: server, username: username, password: password)
                        password = ""
                        if model.login != nil { dismiss() }
                    }
                } label: { HStack { Text("Sign in"); Spacer(); if model.busy { ProgressView() } } }
                .disabled(model.busy || server.isEmpty || username.isEmpty || password.isEmpty)
            } header: { Text("Your ENCPTD account") } footer: {
                Text("Create accounts in the owner console on your PC. This first version pairs one phone installation to each account.")
            }
        }
        .navigationTitle("ENCPTD")
        .onAppear { server = model.login?.serverURL ?? model.defaultServer; username = model.login?.username ?? "" }
    }
}

struct ContactsScreen: View {
    @EnvironmentObject var model: ChatModel
    @State private var adding = false
    @State private var connecting = false
    var body: some View {
        NavigationStack {
            List {
                if model.contacts.isEmpty {
                    ContentUnavailableView("Start a private conversation", systemImage: "bubble.left.and.bubble.right", description: Text("Add an ENCPTD username, then compare safety numbers before sending your first message."))
                }
                ForEach(model.contacts) { contact in
                    NavigationLink(value: contact) {
                        HStack(spacing: 14) {
                            Image(systemName: "person.crop.circle.fill").font(.largeTitle).foregroundStyle(.purple)
                            VStack(alignment: .leading, spacing: 5) {
                                Text("@\(contact.username)").font(.headline)
                                Label("Safety number verified", systemImage: "checkmark.shield").font(.caption).foregroundStyle(.secondary)
                            }
                        }.padding(.vertical, 6)
                    }
                }
                if model.pendingCount > 0 { Text("\(model.pendingCount) message(s) queued on this phone").font(.footnote).foregroundStyle(.secondary) }
            }
            .navigationTitle("ENCPTD")
            .navigationDestination(for: Contact.self) { ChatScreen(contact: $0) }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Menu {
                    Text("@\(model.login?.username ?? "")")
                    Button("Server connection") { connecting = true }
                    Button("Lock", systemImage: "lock") { model.lock() }
                } label: { Image(systemName: "person.crop.circle") } }
                ToolbarItem(placement: .topBarTrailing) { Button { adding = true } label: { Image(systemName: "square.and.pencil") } }
            }
            .refreshable { await model.sync() }
            .sheet(isPresented: $adding) { NavigationStack { AddContactScreen() } }
            .sheet(isPresented: $connecting) { NavigationStack { SignInScreen() } }
        }
    }
}

struct AddContactScreen: View {
    @EnvironmentObject var model: ChatModel
    @Environment(\.dismiss) var dismiss
    @State private var username = ""
    @State private var contact: Contact?
    var body: some View {
        Form {
            Section {
                TextField("Their username", text: $username).textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Find person") { Task { contact = await model.findContact(username.lowercased()) } }.disabled(model.busy)
            }
            if let contact {
                SafetyNumberContent(contact: contact)
                Section {
                    Button("I compared every digit — trust this key") { model.verify(contact); if model.error == nil { dismiss() } }.disabled(model.busy)
                }
            }
        }.navigationTitle("Add a person")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
    }
}

struct SafetyNumberContent: View {
    @EnvironmentObject var model: ChatModel
    var contact: Contact
    var body: some View {
        Section("Safety number with @\(contact.username)") {
            if let number = try? model.safetyNumber(contact) {
                Text(number).font(.system(.title3, design: .monospaced)).textSelection(.enabled)
            }
            Text("Compare this with the same screen on their phone, in person or over a trusted call. Only confirm when every digit matches. A changed key needs a new comparison.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }
}

struct ChatScreen: View {
    @EnvironmentObject var model: ChatModel
    var contact: Contact
    @State private var draft = ""
    @State private var safety = false
    var body: some View {
        ScrollViewReader { scroll in
            ScrollView {
                LazyVStack(spacing: 12) {
                    Label("End-to-end encrypted · verified keys", systemImage: "lock.shield").font(.caption).foregroundStyle(.secondary).padding()
                    ForEach(model.messages.filter { $0.contactID == contact.id }) { message in
                        HStack {
                            if message.outgoing { Spacer(minLength: 40) }
                            VStack(alignment: .leading, spacing: 5) {
                                Text(message.text).textSelection(.enabled)
                                Text(message.pending ? "Queued" : message.date.formatted(date: .omitted, time: .shortened)).font(.caption2).foregroundStyle(.secondary)
                            }
                            .padding(13).background(message.outgoing ? Color.purple.opacity(0.45) : Color.secondary.opacity(0.18)).clipShape(RoundedRectangle(cornerRadius: 17))
                            if !message.outgoing { Spacer(minLength: 40) }
                        }.id(message.id)
                    }
                }.padding(.horizontal)
            }
            .onChange(of: model.messages.count) { _, _ in if let last = model.messages.last(where: { $0.contactID == contact.id }) { scroll.scrollTo(last.id, anchor: .bottom) } }
        }
        .navigationTitle("@\(contact.username)").navigationBarTitleDisplayMode(.inline)
        .toolbar { Button { safety = true } label: { Image(systemName: "checkmark.shield") } }
        .sheet(isPresented: $safety) { NavigationStack { Form { SafetyNumberContent(contact: contact) }.navigationTitle("Verify keys") } }
        .safeAreaInset(edge: .bottom) {
            HStack(alignment: .bottom) {
                TextField("Encrypted message", text: $draft, axis: .vertical).lineLimit(1...5).padding(12).background(.thinMaterial).clipShape(RoundedRectangle(cornerRadius: 20))
                Button {
                    Task { let before = model.messages.count; await model.send(draft, to: contact); if model.messages.count > before { draft = "" } }
                } label: { Image(systemName: "arrow.up.circle.fill").font(.system(size: 38)) }
                    .disabled(model.busy || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }.padding().background(.ultraThinMaterial)
        }
    }
}
