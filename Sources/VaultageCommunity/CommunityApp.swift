import AppKit
import SwiftUI

@main
struct VaultageCommunityApp: App {
    @StateObject private var workspace = WorkspaceModel()

    var body: some Scene {
        Window("Vaultage Community", id: "workspace") {
            WorkspaceView()
                .environmentObject(workspace)
                .preferredColorScheme(.dark)
                .frame(minWidth: 850, minHeight: 600)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                    workspace.disclosureFocusLost()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResignKeyNotification)) { _ in
                    workspace.disclosureFocusLost()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                    workspace.clearDisclosure()
                    workspace.clearOwnedClipboard()
                }
        }
        .defaultSize(width: 1160, height: 780)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Refresh Workspace") { Task { await workspace.refresh() } }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(workspace.isBusy)
            }
            CommandGroup(after: .pasteboard) {
                Divider()
                Button("Hide Revealed Value") { workspace.clearDisclosure() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
    }
}
