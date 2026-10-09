import AppKit
import CommunityKit
import SwiftUI

struct ProjectsView: View {
    @EnvironmentObject private var workspace: WorkspaceModel
    @State private var selectedProjectID: UUID?
    @State private var selectedEnvironmentID: UUID?
    @State private var showingAddProject = false
    @State private var showingBinding = false
    @State private var showingExport = false
    @State private var projectToDelete: CommunityProject?
    @State private var bindingToRemove: EnvironmentBinding?

    private var project: CommunityProject? { workspace.projects.first { $0.id == selectedProjectID } ?? workspace.projects.first }
    private var environment: ProjectEnvironment? {
        project?.environments.first { $0.id == selectedEnvironmentID } ?? project?.environments.first
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(alignment: .top) {
                SectionTitle(title: "Your projects", description: "Organize secret references by project and environment.")
                Spacer()
                Button { showingAddProject = true } label: { Label("New project", systemImage: "plus") }
                    .buttonStyle(AccentButton()).disabled(workspace.isBusy)
                    .keyboardShortcut("n", modifiers: .command)
            }
            if workspace.projects.isEmpty {
                EmptyWorkspace(symbol: "square.stack.3d.up", title: "Make room for a project", description: "Each project starts with Development, Staging and Production. Bind environment keys to secrets already in your vault.")
            } else {
                HStack(alignment: .top, spacing: 20) {
                    projectList
                    if let project, let environment {
                        environmentPanel(project, environment)
                    }
                }.frame(maxHeight: .infinity)
            }
        }
        .padding(30)
        .sheet(isPresented: $showingAddProject) { AddProjectSheet() }
        .sheet(isPresented: $showingBinding) {
            if let project, let environment { AddBindingSheet(project: project, environment: environment) }
        }
        .sheet(isPresented: $showingExport) {
            if let project, let environment { ExportEnvironmentSheet(project: project, environment: environment) }
        }
        .confirmationDialog("Delete this project?", isPresented: Binding(
            get: { projectToDelete != nil }, set: { if !$0 { projectToDelete = nil } }
        ), titleVisibility: .visible) {
            Button("Delete project", role: .destructive) {
                if let projectToDelete { Task { await workspace.deleteProject(projectToDelete.id) } }
                projectToDelete = nil
            }
            Button("Cancel", role: .cancel) { projectToDelete = nil }
        } message: {
            Text("This removes “\(projectToDelete?.name ?? "")” and its environment bindings. Your secrets remain in the vault.")
        }
        .confirmationDialog("Remove this binding?", isPresented: Binding(
            get: { bindingToRemove != nil }, set: { if !$0 { bindingToRemove = nil } }
        ), titleVisibility: .visible) {
            Button("Remove binding", role: .destructive) {
                if let project, let environment, let bindingToRemove {
                    Task { await workspace.removeBinding(projectID: project.id, environmentID: environment.id, bindingID: bindingToRemove.id) }
                }
                bindingToRemove = nil
            }
            Button("Cancel", role: .cancel) { bindingToRemove = nil }
        } message: { Text("This removes the environment reference. Its secret remains in your vault.") }
    }

    private var projectList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 7) {
                ForEach(workspace.projects) { item in
                    Button {
                        selectedProjectID = item.id
                        selectedEnvironmentID = nil
                    } label: {
                        VStack(alignment: .leading, spacing: 7) {
                            HStack(spacing: 9) {
                                Image(systemName: "folder").foregroundStyle(CommunityTheme.accent).accessibilityHidden(true)
                                Text(item.name).font(.system(size: 13, weight: .medium)).lineLimit(2)
                            }
                            Text("\(item.environments.count) environments")
                                .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted)
                        }
                        .padding(15).frame(maxWidth: .infinity, alignment: .leading)
                        .background(project?.id == item.id ? CommunityTheme.accent.opacity(0.08) : CommunityTheme.panel, in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(project?.id == item.id ? CommunityTheme.accent.opacity(0.4) : CommunityTheme.stroke))
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(project?.id == item.id ? .isSelected : [])
                }
            }.padding(1)
        }.frame(width: 190)
    }

    private func environmentPanel(_ project: CommunityProject, _ environment: ProjectEnvironment) -> some View {
        ScrollView {
          VStack(alignment: .leading, spacing: 21) {
            HStack {
                Text(project.name).font(.system(size: 22, weight: .semibold)).lineLimit(2)
                Spacer()
                Button { projectToDelete = project } label: { Image(systemName: "trash") }
                    .buttonStyle(.plain).foregroundStyle(CommunityTheme.muted)
                    .accessibilityLabel("Delete \(project.name)").disabled(workspace.isBusy)
            }
            HStack(spacing: 9) {
                Text("Environment").font(.system(size: 12)).foregroundStyle(CommunityTheme.muted)
                Picker("Environment", selection: Binding(
                    get: { environment.id }, set: { selectedEnvironmentID = $0 }
                )) {
                    ForEach(project.environments) { item in Text(item.name).tag(item.id) }
                }.labelsHidden().frame(maxWidth: 180)
                Spacer(minLength: 0)
            }
            Divider().overlay(CommunityTheme.stroke)
            HStack {
                Text("SECRET REFERENCES").font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .tracking(1.1).foregroundStyle(CommunityTheme.muted)
                Spacer()
                Button { showingBinding = true } label: { Label("Add binding", systemImage: "plus") }
                    .buttonStyle(QuietButton()).disabled(workspace.isBusy || workspace.secrets.isEmpty)
            }
            if workspace.secrets.isEmpty {
                Text("Add a secret in Vault before creating a binding.")
                    .font(.system(size: 12)).foregroundStyle(CommunityTheme.muted)
            }
            if environment.bindings.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    Text("No bindings yet").font(.system(size: 16, weight: .medium))
                    Text("Give a secret an environment key such as API_KEY. A binding stores a reference, not a duplicate value.")
                        .font(.system(size: 12)).foregroundStyle(CommunityTheme.muted).lineSpacing(3)
                }.padding(.vertical, 26)
            } else {
                LazyVStack(spacing: 9) {
                    ForEach(environment.bindings) { binding in bindingRow(binding) }
                }.padding(1)
            }
            VStack(alignment: .leading, spacing: 11) {
                Text("Export intentionally")
                    .font(.system(size: 13, weight: .semibold))
                Text("Exporting creates a plaintext .env file. It exposes values to anyone or any tool that can read that file.")
                    .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted).lineSpacing(3)
                Button { showingExport = true } label: { Label("Export .env…", systemImage: "square.and.arrow.up") }
                    .buttonStyle(QuietButton()).disabled(workspace.isBusy || environment.bindings.isEmpty)
            }.padding(.top, 15)
                .overlay(alignment: .top) { Rectangle().fill(CommunityTheme.stroke).frame(height: 1) }
          }
          .padding(23).frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(CommunityTheme.panel, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(CommunityTheme.stroke))
    }

    private func bindingRow(_ binding: EnvironmentBinding) -> some View {
        HStack(spacing: 13) {
            VStack(alignment: .leading, spacing: 6) {
                Text(binding.key).font(.system(size: 12, weight: .medium, design: .monospaced))
                Label(workspace.secrets.first { $0.id == binding.secretID }?.title ?? "Unavailable secret", systemImage: "link")
                    .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted).lineLimit(2)
            }
            Spacer()
            Button { bindingToRemove = binding } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.plain).foregroundStyle(CommunityTheme.muted)
                .accessibilityLabel("Remove binding \(binding.key)").disabled(workspace.isBusy)
        }
        .padding(14).background(CommunityTheme.background, in: RoundedRectangle(cornerRadius: 9))
    }
}

struct AddProjectSheet: View {
    @EnvironmentObject private var workspace: WorkspaceModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @FocusState private var focused: Bool

    var body: some View {
        SheetFrame(title: "New project", description: "A local workspace for Development, Staging and Production.") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Project name").font(.system(size: 12, weight: .medium))
                TextField("For example, My app", text: $name).textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Project name").focused($focused)
            }
            HStack {
                Button("Cancel") { dismiss() }.buttonStyle(QuietButton()).keyboardShortcut(.cancelAction)
                    .disabled(workspace.isBusy)
                Spacer()
                Button("Create project") {
                    Task { if await workspace.addProject(name: name) { dismiss() } }
                }
                .buttonStyle(AccentButton()).keyboardShortcut(.defaultAction)
                .disabled(workspace.isBusy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }.interactiveDismissDisabled(workspace.isBusy).onAppear { focused = true }
    }
}

struct AddBindingSheet: View {
    @EnvironmentObject private var workspace: WorkspaceModel
    @Environment(\.dismiss) private var dismiss
    let project: CommunityProject
    let environment: ProjectEnvironment
    @State private var key = ""
    @State private var secretID: UUID?
    @FocusState private var focused: Bool

    private var validKey: Bool {
        key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil
    }
    private var duplicateKey: Bool { environment.bindings.contains { $0.key == key } }

    var body: some View {
        SheetFrame(title: "Add a binding", description: "\(project.name) · \(environment.name). Only a reference is saved.") {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Environment key").font(.system(size: 12, weight: .medium))
                    TextField("API_KEY", text: $key).textFieldStyle(.roundedBorder)
                        .font(.system(size: 13, design: .monospaced)).accessibilityLabel("Environment key").focused($focused)
                    Text("Letters, numbers and underscores. Start with a letter or underscore.")
                        .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted)
                    if duplicateKey {
                        Text("That key is already bound. Remove its current binding first to change the reference.")
                            .font(.system(size: 11)).foregroundStyle(CommunityTheme.accent)
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("Saved secret").font(.system(size: 12, weight: .medium))
                    Picker("Saved secret", selection: $secretID) {
                        Text("Choose a secret").tag(nil as UUID?)
                        ForEach(workspace.secrets) { item in Text(item.title).tag(Optional(item.id)) }
                    }.labelsHidden()
                }
            }
            HStack {
                Button("Cancel") { dismiss() }.buttonStyle(QuietButton()).keyboardShortcut(.cancelAction)
                    .disabled(workspace.isBusy)
                Spacer()
                Button("Save binding") {
                    guard let secretID else { return }
                    Task {
                        if await workspace.bind(projectID: project.id, environmentID: environment.id, key: key, secretID: secretID) { dismiss() }
                    }
                }.buttonStyle(AccentButton()).keyboardShortcut(.defaultAction)
                    .disabled(workspace.isBusy || !validKey || duplicateKey || secretID == nil)
            }
        }.interactiveDismissDisabled(workspace.isBusy).onAppear { focused = true }
    }
}

struct ExportEnvironmentSheet: View {
    @EnvironmentObject private var workspace: WorkspaceModel
    @Environment(\.dismiss) private var dismiss
    let project: CommunityProject
    let environment: ProjectEnvironment
    @State private var confirmation = ""
    @State private var choosingFile = false

    var body: some View {
        SheetFrame(title: "Export plaintext", description: "\(project.name) · \(environment.name) · \(environment.bindings.count) bindings") {
            VStack(alignment: .leading, spacing: 13) {
                Label("This writes actual secret values to a file.", systemImage: "exclamationmark.triangle")
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(CommunityTheme.accent)
                Text("The file is not encrypted or protected by Keychain. Keep it out of Git, shared folders, backups and tools you do not trust. Export needs macOS authentication for each secret and will only create a new file.")
                    .font(.system(size: 12)).foregroundStyle(CommunityTheme.muted).lineSpacing(4)
                Text("Supported .env format: single-line text without apostrophes, backslashes or control characters. Other values are refused rather than changed.")
                    .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted).lineSpacing(3)
                Text("Type EXPORT to continue").font(.system(size: 12, weight: .medium))
                TextField("EXPORT", text: $confirmation).textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Type exact EXPORT to confirm plaintext exposure")
                    .font(.system(size: 13, design: .monospaced))
            }
            HStack {
                Button("Cancel") { dismiss() }.buttonStyle(QuietButton()).keyboardShortcut(.cancelAction)
                    .disabled(workspace.isBusy || choosingFile)
                Spacer()
                Button("Choose a new file…") { chooseFile() }
                    .buttonStyle(AccentButton())
                    .disabled(confirmation != "EXPORT" || workspace.isBusy || choosingFile)
            }
        }.interactiveDismissDisabled(workspace.isBusy || choosingFile)
    }

    private func chooseFile() {
        guard confirmation == "EXPORT" else { return }
        choosingFile = true
        let panel = NSSavePanel()
        panel.title = "Export a plaintext environment file"
        panel.message = "Choose a new file. Existing files will not be overwritten."
        panel.nameFieldStringValue = "environment.env"
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.begin { response in
            Task { @MainActor in
                choosingFile = false
                guard response == .OK, let url = panel.url else { return }
                if await workspace.exportEnvironment(projectID: project.id, environmentID: environment.id, to: url, confirmation: confirmation) {
                    dismiss()
                }
            }
        }
    }
}
