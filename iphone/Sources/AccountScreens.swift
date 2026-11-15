// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI

struct AccountsScreen: View {
    @EnvironmentObject var model: ChatModel
    var body: some View {
        NavigationStack {
            List {
                Section("Saved on this phone") {
                    if model.profiles.isEmpty { Text("No saved accounts. Add an account to sign in or create one.").foregroundStyle(.secondary) }
                    ForEach(model.profiles) { profile in
                        Button { model.selectAccount(profile.id) } label: {
                            Label(profile.accountID == nil ? "Finish adding an account" : "@\(profile.username)", systemImage: "person.crop.circle")
                        }.disabled(model.busy)
                    }
                }
                Button { model.addAccount() } label: { Label("Add or create account", systemImage: "person.badge.plus") }.disabled(model.busy)
                if model.pendingDeletionCount > 0 { Text("\(model.pendingDeletionCount) server deletion(s) pending. Keep the app open with an internet connection to finish.").font(.footnote).foregroundStyle(.orange) }
                if let error = model.error { Text(error).font(.footnote).foregroundStyle(.orange) }
            }.navigationTitle("Accounts")
                .toolbar { Button("Lock") { model.lock() } }
        }
    }
}

struct AppPasscodeScreen: View {
    @EnvironmentObject var model: ChatModel
    @State private var code = ""
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 18), count: 3)
    var body: some View {
        VStack(spacing: 22) {
            Spacer()
            Image(systemName: "lock.fill").font(.largeTitle)
            Text("Enter app passcode").font(.title2.bold())
            Text("@\(model.selectedAccount?.username ?? "")").foregroundStyle(.secondary)
            HStack(spacing: 14) {
                ForEach(0..<6) { position in Circle().fill(position < code.count ? Color.primary : Color.secondary.opacity(0.25)).frame(width: 13, height: 13) }
            }.accessibilityElement(children: .ignore).accessibilityLabel("\(code.count) of 6 digits entered")
            if model.protection.wipeAfterThree { Text("Three wrong complete passcodes in a row permanently delete this account from the phone and server.").font(.footnote).foregroundStyle(.orange).multilineTextAlignment(.center) }
            if let error = model.error { Text(error).font(.footnote).foregroundStyle(.orange).multilineTextAlignment(.center) }
            if model.busy { ProgressView() }
            LazyVGrid(columns: columns, spacing: 18) {
                ForEach(1...9, id: \.self) { digit in number(digit) }
                Color.clear.frame(height: 58)
                number(0)
                Button { if !code.isEmpty { code.removeLast() } } label: { Image(systemName: "delete.left").frame(maxWidth: .infinity, minHeight: 58) }.accessibilityLabel("Delete digit")
            }.disabled(model.busy).buttonStyle(.plain)
            Button("Switch accounts") { code = ""; model.showAccounts() }.disabled(model.busy)
            Button("Lock") { code = ""; model.lock() }
            Spacer()
        }.padding(30).frame(maxWidth: 400).privacySensitive()
    }
    private func number(_ value: Int) -> some View {
        Button {
            guard code.count < 6 else { return }
            model.noteActivity(); code += String(value)
            if code.count == 6 {
                let entered = code; code = ""
                Task { await model.submitPasscode(entered) }
            }
        } label: { Text(String(value)).font(.largeTitle).frame(maxWidth: .infinity, minHeight: 58).background(Color.secondary.opacity(0.12), in: Circle()) }
    }
}

struct AccountSecurityScreen: View {
    @EnvironmentObject var model: ChatModel
    @State private var requirePasscode = false
    @State private var wipeAfterThree = false
    @State private var useInactivity = false
    @State private var days = "7"
    @State private var currentCode = ""
    @State private var newCode = ""
    @State private var confirmation = ""
    @State private var password = ""
    @State private var confirming = false
    @State private var saved = false
    @State private var loaded = false
    private var requested: AccountProtection { AccountProtection(requirePasscode: requirePasscode, wipeAfterThree: requirePasscode && wipeAfterThree, inactivityDays: requirePasscode && useInactivity ? Int(days) : nil) }
    private var valid: Bool {
        !password.isEmpty && (!model.protection.requirePasscode || AppPasscodeCrypto.valid(currentCode)) &&
        (!requirePasscode || (newCode.isEmpty && model.protection.requirePasscode) || (AppPasscodeCrypto.valid(newCode) && newCode == confirmation)) &&
        (!useInactivity || Int(days).map { (1...365).contains($0) } == true)
    }
    var body: some View {
        Form {
            Section {
                Toggle("Require app passcode", isOn: $requirePasscode)
                Text("After password sign-in, require this account's six-digit code each time you reopen the app or switch to it. Your phone's Face ID/passcode protection remains.").font(.footnote).foregroundStyle(.secondary)
                if model.protection.requirePasscode { SecureField("Current app passcode", text: $currentCode).keyboardType(.numberPad) }
                if requirePasscode {
                    SecureField(model.protection.requirePasscode ? "New code (optional)" : "New six-digit code", text: $newCode).keyboardType(.numberPad)
                    SecureField("Confirm new code", text: $confirmation).keyboardType(.numberPad)
                }
            } header: { Text("App passcode") }
            Section {
                Toggle("Delete after 3 wrong passcodes", isOn: $wipeAfterThree).disabled(!requirePasscode)
                Toggle("Delete after inactivity", isOn: $useInactivity).disabled(!requirePasscode)
                if useInactivity {
                    TextField("Days without a successful app passcode", text: $days).keyboardType(.numberPad)
                    Text("Choose 1–365 days. Open online before the deadline so the PC can receive proof of the correct code. Offline entries cannot extend the PC's deadline.").font(.footnote)
                }
                Text("These options are off by default. When enabled, deletion removes this account, messages and encryption keys from this phone and the PC server. It cannot remove other people's saved copies. There is no recovery.").font(.footnote).foregroundStyle(.orange)
                Text("The PC enforces its timer while running, or when it next starts. iOS checks the phone deadline before the next unlock. An offline phone queues server deletion until a connection is available.").font(.footnote).foregroundStyle(.secondary)
            } header: { Text("Automatic account deletion") }
            Section {
                SecureField("Account password to save changes", text: $password).textContentType(.password)
                Button("Save security settings") { confirming = true }.disabled(!valid || model.busy)
                if model.busy { ProgressView() }
                if saved { Text("Settings saved.").foregroundStyle(.green) }
                if model.securityPending { Text("Phone settings saved; server confirmation is pending. Previous server rules remain active until it confirms.").font(.footnote).foregroundStyle(.orange) }
                if let error = model.error { Text(error).font(.footnote).foregroundStyle(.orange) }
            }
        }.navigationTitle("Security").disabled(model.busy)
            .onAppear {
                guard !loaded else { return }
                requirePasscode = model.protection.requirePasscode; wipeAfterThree = model.protection.wipeAfterThree
                useInactivity = model.protection.inactivityDays != nil; days = String(model.protection.inactivityDays ?? 7)
                loaded = true
            }
            .onChange(of: requirePasscode) { _, enabled in if !enabled { wipeAfterThree = false; useInactivity = false }; model.noteActivity(); saved = false }
            .onChange(of: currentCode) { _, value in model.noteActivity(); if !value.isEmpty { saved = false } }
            .onChange(of: newCode) { _, value in model.noteActivity(); if !value.isEmpty { saved = false } }
            .onChange(of: confirmation) { _, value in model.noteActivity(); if !value.isEmpty { saved = false } }
            .onChange(of: password) { _, value in model.noteActivity(); if !value.isEmpty { saved = false } }
            .onChange(of: days) { _, _ in model.noteActivity(); saved = false }
            .onChange(of: wipeAfterThree) { _, _ in model.noteActivity(); saved = false }
            .onChange(of: useInactivity) { _, _ in model.noteActivity(); saved = false }
            .confirmationDialog("Save security settings for this account?", isPresented: $confirming, titleVisibility: .visible) {
                Button(requested.wipeAfterThree || requested.inactivityDays != nil ? "Enable permanent automatic deletion" : "Save settings", role: requested.wipeAfterThree || requested.inactivityDays != nil ? .destructive : nil) {
                    let value = requested
                    let enteredCurrent = currentCode, enteredNew = newCode, enteredPassword = password
                    Task {
                        saved = await model.saveProtection(value, currentCode: enteredCurrent, newCode: enteredNew, password: enteredPassword)
                        if saved || model.securityPending { currentCode = ""; newCode = ""; confirmation = ""; password = "" }
                    }
                }
            } message: {
                Text(requested.wipeAfterThree || requested.inactivityDays != nil ? "This permanently deletes the selected account from this phone and your PC server when an enabled rule triggers. Wrong codes are counted across app restarts. An inactivity rule needs an online unlock before its deadline. Messages and encryption keys cannot be recovered." : "This changes only the selected account's passcode settings. Automatic deletion will be disabled on the PC after it confirms.")
            }
    }
}
