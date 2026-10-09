import AppKit
import CommunityKit
import Foundation
import SwiftUI
import VaultageCore

@MainActor
final class WorkspaceModel: ObservableObject {
    @Published private(set) var secrets: [SecretSummary] = []
    @Published private(set) var projects: [CommunityProject] = []
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?
    @Published var notice: String?
    @Published private(set) var revealedValue: String?
    @Published private(set) var revealedID: UUID?

    private let store: CommunityStore
    private var disclosureGeneration: UInt64 = 0
    private var revealExpiry: Task<Void, Never>?
    private var clipboardExpiry: Task<Void, Never>?
    private var clipboardOwnership: (changeCount: Int, token: String)?
    private let ownershipType = NSPasteboard.PasteboardType("dev.arcalab.vaultage-community.clipboard-owner")

    init(store: CommunityStore? = nil) {
        if let store {
            self.store = store
        } else {
            #if DEBUG
            // Isolate metadata during native UI smoke checks. This never
            // accepts credentials and is absent from release builds.
            if let workspacePath = ProcessInfo.processInfo.environment["VAULTAGE_COMMUNITY_WORKSPACE"],
               !workspacePath.isEmpty {
                self.store = CommunityStore(directory: URL(fileURLWithPath: workspacePath, isDirectory: true))
            } else {
                self.store = CommunityStore()
            }
            #else
            self.store = CommunityStore()
            #endif
        }
    }

    func refresh() async {
        do {
            let snapshot = try await store.snapshot()
            secrets = snapshot.secrets.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
            projects = snapshot.projects.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        } catch {
            errorMessage = "The local workspace could not be opened. Check that its Application Support directory is accessible. No value has been disclosed."
        }
    }

    func addSecret(title: String, kind: SecretKind, folder: String, value: String) async -> Bool {
        guard !isBusy else { return false }
        isBusy = true
        defer { isBusy = false }
        var bytes = Data(value.utf8)
        defer { bytes.withUnsafeMutableBytes { SecretMemory.zero($0) } }
        do {
            _ = try await store.createSecret(title: title, kind: kind, folder: folder, value: bytes)
            await refresh()
            notice = "Secret saved locally."
            return true
        } catch {
            errorMessage = "The secret could not be saved. Check the title and folder, and that macOS Keychain is available to this build. Your existing records were kept."
            return false
        }
    }

    func deleteSecret(_ id: UUID) async {
        guard !isBusy else { return }
        clearDisclosure()
        isBusy = true
        defer { isBusy = false }
        do {
            try await store.deleteSecret(id: id)
            await refresh()
            notice = "Secret and its project references removed."
        } catch {
            errorMessage = "The secret could not be removed. Check Keychain and local storage access, then try again."
        }
    }

    func reveal(_ id: UUID) async {
        guard !isBusy else { return }
        clearDisclosure()
        let generation = disclosureGeneration
        isBusy = true
        defer { isBusy = false }
        do {
            let title = secrets.first { $0.id == id }?.title ?? "Selected secret"
            let secret = try await store.readSecret(id: id, prompt: "Reveal on screen: \(title)")
            guard generation == disclosureGeneration, NSApp.isActive else {
                notice = "Reveal canceled because this window lost focus. Authenticate again to reveal."
                return
            }
            // This is the deliberate human disclosure boundary. Swift's String
            // copies cannot be deterministically zeroed; release UI references
            // after 20 seconds and whenever the app deactivates.
            try secret.withDisclosureText { revealedValue = $0 }
            revealedID = id
            revealExpiry = Task { [weak self] in
                try? await Task.sleep(for: .seconds(20))
                guard !Task.isCancelled else { return }
                self?.clearDisclosure()
            }
        } catch {
            errorMessage = "The value was not revealed. Authenticate with macOS and keep this window active. A source build may need signing before Keychain access works."
        }
    }

    func copy(_ id: UUID) async {
        guard !isBusy else { return }
        clearDisclosure()
        let generation = disclosureGeneration
        isBusy = true
        defer { isBusy = false }
        do {
            let title = secrets.first { $0.id == id }?.title ?? "Selected secret"
            let secret = try await store.readSecret(id: id, prompt: "Copy to clipboard: \(title)")
            guard generation == disclosureGeneration, NSApp.isActive else {
                notice = "Copy canceled because this window lost focus. Authenticate again to copy."
                return
            }
            let pasteboard = NSPasteboard.general
            let token = UUID().uuidString
            let item = NSPasteboardItem()
            // The sole other deliberate human disclosure boundary. Concealed
            // and transient markers are advisory to clipboard consumers.
            try secret.withDisclosureText { item.setString($0, forType: .string) }
            item.setString(token, forType: ownershipType)
            item.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            item.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
            pasteboard.clearContents()
            guard pasteboard.writeObjects([item]) else {
                errorMessage = "The clipboard could not accept this value."
                return
            }
            clipboardExpiry?.cancel()
            clipboardOwnership = (pasteboard.changeCount, token)
            notice = "Copied for 30 seconds. Clipboard history apps may retain their own copies."
            clipboardExpiry = Task { [weak self] in
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled else { return }
                self?.clearOwnedClipboard()
            }
        } catch {
            errorMessage = "The value was not copied. Authenticate with macOS and keep this window active. A source build may need signing before Keychain access works."
        }
    }

    func clearDisclosure() {
        disclosureGeneration &+= 1
        hideVisibleDisclosure()
    }

    func hideVisibleDisclosure() {
        revealedValue = nil
        revealedID = nil
        revealExpiry?.cancel()
        revealExpiry = nil
    }

    func clearOwnedClipboard() {
        clipboardExpiry?.cancel()
        clipboardExpiry = nil
        defer { clipboardOwnership = nil }
        guard let ownership = clipboardOwnership else { return }
        let pasteboard = NSPasteboard.general
        guard pasteboard.changeCount == ownership.changeCount,
              pasteboard.string(forType: ownershipType) == ownership.token else { return }
        pasteboard.clearContents()
    }

    func addProject(name: String) async -> Bool {
        guard !isBusy else { return false }
        isBusy = true
        defer { isBusy = false }
        do {
            _ = try await store.createProject(name: name)
            await refresh()
            notice = "Project created with Development, Staging and Production."
            return true
        } catch {
            errorMessage = "The project could not be created. Check its name and local storage access."
            return false
        }
    }

    func deleteProject(_ id: UUID) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            try await store.deleteProject(id: id)
            await refresh()
            notice = "Project removed. Secrets remain in your vault."
        } catch { errorMessage = "The project could not be removed. Check local storage access, then try again." }
    }

    func bind(projectID: UUID, environmentID: UUID, key: String, secretID: UUID) async -> Bool {
        guard !isBusy else { return false }
        isBusy = true
        defer { isBusy = false }
        do {
            try await store.setBinding(projectID: projectID, environmentID: environmentID, key: key, secretID: secretID)
            await refresh()
            notice = "Environment binding saved. No value was disclosed."
            return true
        } catch {
            errorMessage = "The binding could not be saved. Use a unique environment key such as API_KEY and choose a secret that still exists."
            return false
        }
    }

    func removeBinding(projectID: UUID, environmentID: UUID, bindingID: UUID) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            try await store.removeBinding(projectID: projectID, environmentID: environmentID, bindingID: bindingID)
            await refresh()
            notice = "Binding removed. The secret remains in your vault."
        } catch { errorMessage = "The binding could not be removed. Check local storage access, then try again." }
    }

    func exportEnvironment(projectID: UUID, environmentID: UUID, to url: URL, confirmation: String) async -> Bool {
        guard !isBusy else { return false }
        clearDisclosure()
        isBusy = true
        defer { isBusy = false }
        do {
            try await store.exportEnvironment(projectID: projectID, environmentID: environmentID, to: url, confirmation: confirmation)
            notice = "Plaintext file exported. Keep it private and out of version control."
            return true
        } catch {
            switch error as? CommunityError {
            case .exportValueUnsupported:
                errorMessage = "This environment contains a value outside the supported .env format. Values must be single-line text without apostrophes, backslashes or control characters. No value was changed to fit the format."
            case .unsafeFile:
                errorMessage = "Export was refused. Choose a new file in a writable local directory without symbolic links. No existing file is overwritten."
            default:
                errorMessage = "Export was refused. Authenticate with macOS, use exact EXPORT, and choose a new file in a writable directory. No existing file is overwritten."
            }
            return false
        }
    }
}
