import AppKit
import SwiftUI

enum CommunityTheme {
    static let background = Color(red: 0.055, green: 0.073, blue: 0.068)
    static let panel = Color(red: 0.084, green: 0.105, blue: 0.098)
    static let raised = Color(red: 0.112, green: 0.135, blue: 0.125)
    static let stroke = Color.white.opacity(0.09)
    static let accent = Color(red: 0.74, green: 0.67, blue: 1)
    static let muted = Color(red: 0.65, green: 0.72, blue: 0.68)
    static let foreground = Color(red: 0.94, green: 0.96, blue: 0.94)
}

struct AccentButton: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .foregroundStyle(CommunityTheme.background)
            .background(CommunityTheme.accent.opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.35))
            .clipShape(RoundedRectangle(cornerRadius: 9))
    }
}

struct QuietButton: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .padding(.horizontal, 13)
            .padding(.vertical, 9)
            .foregroundStyle(CommunityTheme.foreground.opacity(isEnabled ? 1 : 0.35))
            .background(configuration.isPressed ? CommunityTheme.raised : CommunityTheme.panel)
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(CommunityTheme.stroke))
    }
}

struct CommunityBadge: View {
    var body: some View {
        Text("SOURCE PREVIEW")
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .tracking(0.7)
            .foregroundStyle(CommunityTheme.accent)
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(CommunityTheme.accent.opacity(0.1), in: Capsule())
            .accessibilityLabel("Source preview. This is not a signed release.")
    }
}

struct SectionTitle: View {
    let title: String
    let description: String

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.system(size: 29, weight: .semibold))
                .accessibilityAddTraits(.isHeader)
            Text(description).font(.system(size: 13)).foregroundStyle(CommunityTheme.muted)
        }
    }
}

struct EmptyWorkspace: View {
    let symbol: String
    let title: String
    let description: String

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: symbol)
                .font(.system(size: 34, weight: .light))
                .foregroundStyle(CommunityTheme.accent)
                .padding(22)
                .background(CommunityTheme.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: 22))
                .accessibilityHidden(true)
            Text(title).font(.system(size: 19, weight: .semibold))
            Text(description)
                .font(.system(size: 13))
                .foregroundStyle(CommunityTheme.muted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 350)
        }
        .padding(35)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct SheetFrame<Content: View>: View {
    let title: String
    let description: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SectionTitle(title: title, description: description)
            content
        }
        .padding(30)
        .frame(width: 480)
        .background(CommunityTheme.background)
        .foregroundStyle(CommunityTheme.foreground)
    }
}

/// The OS may restrict window capture; this is screen privacy, not a claim of
/// isolation from another process running as the same user.
struct PrivateWindow: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { ProtectedWindowView() }
    func updateNSView(_ nsView: NSView, context: Context) {}

    private final class ProtectedWindowView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            window?.sharingType = .none
            window?.backgroundColor = NSColor(red: 0.055, green: 0.073, blue: 0.068, alpha: 1)
        }
    }
}
