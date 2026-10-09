import SwiftUI

enum WorkspaceSection: String, CaseIterable, Identifiable {
    case vault = "Vault"
    case projects = "Projects"
    var id: String { rawValue }
    var symbol: String { self == .vault ? "lock.rectangle" : "square.stack.3d.up" }
}

struct WorkspaceView: View {
    @EnvironmentObject private var workspace: WorkspaceModel
    @State private var section: WorkspaceSection = .vault

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Rectangle().fill(CommunityTheme.stroke).frame(width: 1)
            VStack(spacing: 0) {
                if section == .vault { VaultView() } else { ProjectsView() }
                statusBar
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(CommunityTheme.background)
        .foregroundStyle(CommunityTheme.foreground)
        .tint(CommunityTheme.accent)
        .background(PrivateWindow())
        .task { await workspace.refresh() }
        .onChange(of: section) { _, _ in workspace.clearDisclosure() }
        .alert("Operation unavailable", isPresented: Binding(
            get: { workspace.errorMessage != nil },
            set: { if !$0 { workspace.errorMessage = nil } }
        )) {
            Button("OK") { workspace.errorMessage = nil }
        } message: { Text(workspace.errorMessage ?? "") }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                Image(systemName: "square.stack.3d.up.fill")
                    .font(.system(size: 25, weight: .light))
                    .foregroundStyle(CommunityTheme.accent)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Vaultage").font(.system(size: 20, weight: .semibold))
                    Text("COMMUNITY").font(.system(size: 9, weight: .medium, design: .monospaced))
                        .tracking(2).foregroundStyle(CommunityTheme.muted)
                }
            }.padding(.bottom, 32)

            Text("LOCAL WORKSPACE")
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .tracking(1.4).foregroundStyle(CommunityTheme.muted)
                .padding(.bottom, 12)

            ForEach(WorkspaceSection.allCases) { item in
                Button {
                    section = item
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: item.symbol).frame(width: 20).accessibilityHidden(true)
                        Text(item.rawValue)
                        Spacer()
                        Text("\(item == .vault ? workspace.secrets.count : workspace.projects.count)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(CommunityTheme.muted)
                    }
                    .font(.system(size: 13, weight: section == item ? .semibold : .regular))
                    .padding(.horizontal, 13).padding(.vertical, 12)
                    .foregroundStyle(section == item ? CommunityTheme.accent : CommunityTheme.foreground)
                    .background(section == item ? CommunityTheme.accent.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 9))
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(section == item ? .isSelected : [])
                .padding(.bottom, 5)
            }
            Spacer()
            VStack(alignment: .leading, spacing: 13) {
                CommunityBadge()
                Text("Local vault. No account.")
                    .font(.system(size: 12, weight: .medium))
                Text("Free forever. Open source.\nThis source preview is not a signed or notarized release. Secret actions need a correctly signed, Keychain-enabled build; see the build guide.")
                    .font(.system(size: 11)).foregroundStyle(CommunityTheme.muted).lineSpacing(4)
            }
            .padding(.top, 20)
            .overlay(alignment: .top) { Rectangle().fill(CommunityTheme.stroke).frame(height: 1) }
        }
        .padding(22)
        .frame(width: 238)
        .background(CommunityTheme.panel)
    }

    private var statusBar: some View {
        HStack(spacing: 9) {
            if workspace.isBusy {
                ProgressView().controlSize(.small)
                Text("Working locally…")
            } else if let notice = workspace.notice {
                Image(systemName: "checkmark.circle").foregroundStyle(CommunityTheme.accent)
                Text(notice).lineLimit(2)
                Spacer()
                Button { workspace.notice = nil } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain).accessibilityLabel("Dismiss status")
            } else {
                Image(systemName: "externaldrive").accessibilityHidden(true)
                Text("Metadata on this Mac · Secret values in macOS Keychain")
                Spacer()
            }
        }
        .font(.system(size: 11))
        .foregroundStyle(CommunityTheme.muted)
        .padding(.horizontal, 26).padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .top) { Rectangle().fill(CommunityTheme.stroke).frame(height: 1) }
    }
}
