import AppKit
import CommunityKit
import SwiftUI

extension SecretKind {
    var label: String {
        switch self {
        case .apiKey: "API key"
        case .password: "Password"
        case .secureNote: "Secure note"
        }
    }

    var symbol: String {
        switch self {
        case .apiKey: "key.horizontal"
        case .password: "lock"
        case .secureNote: "note.text"
        }
    }
}

struct VaultView: View {
    @EnvironmentObject private var workspace: WorkspaceModel
    @State private var query = ""
    @State private var selectedID: UUID?
    @State private var showingAdd = false
    @State private var secretToDelete: SecretSummary?

    private var filteredSecrets: [SecretSummary] {
        guard !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return workspace.secrets }
        return workspace.secrets.filter {
            $0.title.localizedCaseInsensitiveContains(query) || $0.folder.localizedCaseInsensitiveContains(query)
        }
    }

    private var selectedSecret: SecretSummary? { workspace.secrets.first { $0.id == selectedID } }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(alignment: .top) {
                SectionTitle(title: "Your vault", description: "A quiet home for the secrets you keep on this Mac.")
                Spacer()
                Button { showingAdd = true } label: { Label("Add secret", systemImage: "plus") }
                    .buttonStyle(AccentButton()).disabled(workspace.isBusy)
                    .keyboardShortcut("n", modifiers: .command)
            }
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(CommunityTheme.muted).accessibilityHidden(true)
                TextField("Search titles and folders", text: $query)
                    .textFieldStyle(.plain)
                    .accessibilityLabel("Search secret titles and folders. Values are never searched.")
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(CommunityTheme.muted)
                        .accessibilityLabel("Clear search")
                }
            }
            .padding(12).background(CommunityTheme.panel, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(CommunityTheme.stroke))

            if workspace.secrets.isEmpty {
                EmptyWorkspace(symbol: "lock.rectangle", title: "Start with one secret", description: "Save an API key, password or note. Only its title and folder appear in your workspace.")
            } else if filteredSecrets.isEmpty {
                EmptyWorkspace(symbol: "magnifyingglass", title: "No matching labels", description: "Try another title or folder. Search never reads a secret value.")
            } else {
                HStack(spacing: 20) {
                    ScrollView {
                        LazyVStack(spacing: 7) {
                            ForEach(filteredSecrets) { secret in
                                secretRow(secret)
                            }
                        }
                        .padding(1)
                    }
                    .frame(minWidth: 215, maxWidth: 300)
                    if let secret = selectedSecret {
                        secretDetail(secret)
                    } else {
                        EmptyWorkspace(symbol: "cursorarrow.click", title: "Choose a secret", description: "View its labels, reveal its value, or connect it to a project environment.")
                            .background(CommunityTheme.panel, in: RoundedRectangle(cornerRadius: 16))
                    }
                }.frame(maxHeight: .infinity)
            }
        }
        .padding(30)
        .sheet(isPresented: $showingAdd) { AddSecretSheet() }
        .onAppear { workspace.selectSecretForDisclosure(selectedID) }
        .onDisappear { workspace.selectSecretForDisclosure(nil) }
        .onChange(of: selectedID) { _, id in workspace.selectSecretForDisclosure(id) }
        .onChange(of: query) { _, _ in workspace.clearDisclosure() }
        .onChange(of: workspace.secrets.map(\.id)) { _, ids in
            if let selectedID, !ids.contains(selectedID) { self.selectedID = nil }
        }
        .confirmationDialog("Delete this secret?", isPresented: Binding(
            get: { secretToDelete != nil },
            set: { if !$0 { secretToDelete = nil } }
        ), titleVisibility: .visible) {
            Button("Delete secret", role: .destructive) {
                if let secretToDelete { Task { await workspace.deleteSecret(secretToDelete.id) } }
                secretToDelete = nil
            }
            Button("Cancel", role: .cancel) { secretToDelete = nil }
        } message: {
            Text("This removes “\(secretToDelete?.title ?? "")” from Keychain and removes all project bindings to it. This cannot be undone.")
        }
    }

    private func secretRow(_ secret: SecretSummary) -> some View {
        Button { selectedID = secret.id } label: {
            HStack(spacing: 12) {
                Image(systemName: secret.kind.symbol)
                    .font(.system(size: 17))
                    .foregroundStyle(CommunityTheme.accent)
                    .frame(width: 34, height: 38)
                    .background(CommunityTheme.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 5) {
                    Text(secret.title).font(.system(size: 13, weight: .medium)).lineLimit(2)
                    Text(secret.folder.isEmpty ? secret.kind.label : "\(secret.kind.label) · \(secret.folder)")
                        .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted).lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(12)
            .foregroundStyle(CommunityTheme.foreground)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(selectedID == secret.id ? CommunityTheme.accent.opacity(0.08) : CommunityTheme.panel, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(selectedID == secret.id ? CommunityTheme.accent.opacity(0.4) : CommunityTheme.stroke))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(secret.title), \(secret.kind.label), \(secret.folder.isEmpty ? "no folder" : secret.folder)")
        .accessibilityAddTraits(selectedID == secret.id ? .isSelected : [])
    }

    private func secretDetail(_ secret: SecretSummary) -> some View {
        VStack(alignment: .leading, spacing: 21) {
            HStack {
                Image(systemName: secret.kind.symbol).font(.system(size: 24)).foregroundStyle(CommunityTheme.accent)
                    .accessibilityHidden(true)
                Spacer()
                Button { secretToDelete = secret; workspace.clearDisclosure() } label: { Image(systemName: "trash") }
                    .buttonStyle(.plain).foregroundStyle(CommunityTheme.muted)
                    .accessibilityLabel("Delete \(secret.title)").disabled(workspace.isBusy)
            }
            Text(secret.title).font(.system(size: 22, weight: .semibold)).fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 9) {
                detailLabel("Type", secret.kind.label)
                detailLabel("Folder", secret.folder.isEmpty ? "None" : secret.folder)
                detailLabel("Added", secret.createdAt.formatted(date: .abbreviated, time: .omitted))
            }
            Divider().overlay(CommunityTheme.stroke)
            Text("PROTECTED VALUE").font(.system(size: 9, weight: .semibold, design: .monospaced))
                .tracking(1.1).foregroundStyle(CommunityTheme.muted)
            if workspace.revealedID == secret.id, let value = workspace.revealedValue {
                ScrollView {
                    Text(value).font(.system(size: 13, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                }
                .frame(maxHeight: 180)
                .background(CommunityTheme.background, in: RoundedRectangle(cornerRadius: 9))
                .accessibilityLabel("Revealed secret value")
                Text("Hides when the 20-second approval expires, or when this window loses focus.")
                    .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted)
                Button("Hide value") { workspace.clearDisclosure() }.buttonStyle(QuietButton())
            } else if let prepared = workspace.preparedDisclosure, prepared.secretID == secret.id {
                Text("••••••••••••••••")
                    .font(.system(size: 21, design: .monospaced)).foregroundStyle(CommunityTheme.muted)
                    .accessibilityLabel("Authenticated value remains hidden")
                Text("Authentication complete. Your value is still hidden.")
                    .font(.system(size: 12, weight: .medium)).foregroundStyle(CommunityTheme.foreground)
                Text("Click below to \(prepared.purpose == .reveal ? "show it on screen" : "copy it to the clipboard"). This approval expires within 20 seconds and is cleared if this window loses focus.")
                    .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted).lineSpacing(4)
                HStack {
                    if prepared.purpose == .reveal {
                        Button("Show value") { workspace.showPreparedValue(prepared) }.buttonStyle(AccentButton())
                    } else {
                        Button("Copy value") { workspace.copyPreparedValue(prepared) }.buttonStyle(AccentButton())
                    }
                    Button("Cancel") { workspace.clearDisclosure() }.buttonStyle(QuietButton())
                }.disabled(workspace.isBusy)
            } else {
                Text("••••••••••••••••")
                    .font(.system(size: 21, design: .monospaced)).foregroundStyle(CommunityTheme.muted)
                    .accessibilityLabel("Value is hidden")
                Text("Authenticate with macOS, then explicitly choose Show value or Copy value. Values stay hidden during authentication and never appear in lists or project bindings.")
                    .font(.system(size: 12)).foregroundStyle(CommunityTheme.muted).lineSpacing(4)
                HStack {
                    Button { Task { await workspace.reveal(secret.id) } } label: { Label("Reveal", systemImage: "eye") }
                        .buttonStyle(QuietButton())
                    Button { Task { await workspace.copy(secret.id) } } label: { Label("Copy", systemImage: "doc.on.doc") }
                        .buttonStyle(QuietButton())
                }.disabled(workspace.isBusy)
            }
            Spacer(minLength: 12)
        }
        .padding(23)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(CommunityTheme.panel, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(CommunityTheme.stroke))
    }

    private func detailLabel(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(CommunityTheme.muted).frame(width: 50, alignment: .leading)
            Text(value).foregroundStyle(CommunityTheme.foreground).lineLimit(2)
        }.font(.system(size: 12))
    }
}

struct AddSecretSheet: View {
    @EnvironmentObject private var workspace: WorkspaceModel
    @Environment(\.dismiss) private var dismiss
    @State private var title = ""
    @State private var kind: SecretKind = .apiKey
    @State private var folder = ""
    @State private var value = ""
    @FocusState private var titleFocused: Bool

    var body: some View {
        SheetFrame(title: "Add a secret", description: "Its value stays in macOS Keychain. Titles and folders are local metadata.") {
            VStack(alignment: .leading, spacing: 16) {
                field("Title") { TextField("For example, Development API key", text: $title).focused($titleFocused) }
                field("Type") {
                    Picker("Type", selection: $kind) {
                        Text("API key").tag(SecretKind.apiKey)
                        Text("Password").tag(SecretKind.password)
                        Text("Secure note").tag(SecretKind.secureNote)
                    }.labelsHidden()
                }
                field("Folder (optional)") { TextField("For example, Personal", text: $folder) }
                field("Secret value") { SecureField("Enter the value", text: $value) }
                Text("Use labels that do not contain credentials. Keep your own recovery copy: this workspace has no cloud backup.")
                    .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted).lineSpacing(3)
            }.textFieldStyle(.roundedBorder)
            HStack {
                Button("Cancel") { value = ""; dismiss() }.buttonStyle(QuietButton()).keyboardShortcut(.cancelAction)
                    .disabled(workspace.isBusy)
                Spacer()
                Button("Save secret") {
                    Task {
                        if await workspace.addSecret(title: title, kind: kind, folder: folder, value: value) {
                            value = ""; dismiss()
                        }
                    }
                }
                .buttonStyle(AccentButton()).keyboardShortcut(.defaultAction)
                .disabled(workspace.isBusy || title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || value.isEmpty || value.utf8.count > 65_536)
            }
        }
        .interactiveDismissDisabled(workspace.isBusy)
        .background(PrivateWindow())
        .onAppear { titleFocused = true }
        .onDisappear { value = "" }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in value = "" }
    }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(label).font(.system(size: 12, weight: .medium))
            content().accessibilityLabel(label)
        }
    }
}
