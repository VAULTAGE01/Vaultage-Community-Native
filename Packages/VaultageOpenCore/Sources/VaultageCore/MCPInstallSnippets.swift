import Foundation

/// BL-069 — the per-host MCP install snippets.
///
/// One function builds all four. They differ only in the shape each host's
/// configuration file wants; the substance is identical, and generating them
/// from a single place is what makes the property below checkable:
///
/// **A snippet contains exactly one secret-shaped value — the credential that
/// was just issued — and it sits in that host's environment block.** No
/// `<paste your token here>`, no `${VAULTAGE_TOKEN}`, no `YOUR_KEY`, and never
/// an argument on a command line. A placeholder a human is expected to fill in
/// is how v1's VS-036 taught people to paste a live token into a chat window;
/// a snippet that is already complete has nothing to teach that way.
///
/// The whole artifact is still credential-bearing and is labelled as such: it
/// is shown once, it is meant to be written to a file at `0600`, and it must
/// not be pasted into an agent transcript.
public enum MCPInstallSnippet {
    public enum Host: String, Codable, CaseIterable, Sendable, Identifiable {
        case claudeCode, codex, cursor, openCode
        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .claudeCode: "Claude Code"
            case .codex: "Codex"
            case .cursor: "Cursor"
            case .openCode: "OpenCode"
            }
        }

        /// Where the snippet goes. Shown to the human and recorded as the
        /// enrolled record's install path hint; never used as a path by
        /// Vaultage itself.
        public var configPath: String {
            switch self {
            case .claudeCode: "<project>/.mcp.json"
            case .codex: "~/.codex/config.toml"
            case .cursor: "~/.cursor/mcp.json"
            case .openCode: "~/.config/opencode/opencode.json"
            }
        }

        public var format: Format {
            switch self {
            case .codex: .toml
            case .claudeCode, .cursor, .openCode: .json
            }
        }
    }

    public enum Format: String, Codable, Sendable { case json, toml }

    public struct Snippet: Sendable, Identifiable {
        public let host: Host
        public let configPath: String
        public let format: Format
        /// The file content. Valid JSON or TOML with no comment lines, so it
        /// can be written as-is; the prose lives in `guidance` instead.
        public let body: String
        public let guidance: String
        public var id: String { host.rawValue }
    }

    public static let serverName = "vaultage"
    public static let credentialKey = ClientCredentialTransport.environmentKey

    /// The one generator. `executablePath` is the Vaultage binary inside the
    /// installed app bundle; `credential` is the plaintext that was just issued
    /// and that Vaultage does not store.
    public static func snippet(host: Host, executablePath: String, credential: ClientCredential) -> Snippet {
        let command = executablePath
        let secret = credential.wireValue
        let body: String
        switch host {
        case .claudeCode, .cursor:
            body = """
            {
              "mcpServers": {
                "\(serverName)": {
                  "command": \(json(command)),
                  "args": ["--mcp"],
                  "env": {
                    "\(credentialKey)": \(json(secret))
                  }
                }
              }
            }
            """
        case .codex:
            body = """
            [mcp_servers.\(serverName)]
            command = \(json(command))
            args = ["--mcp"]

            [mcp_servers.\(serverName).env]
            \(credentialKey) = \(json(secret))
            """
        case .openCode:
            body = """
            {
              "mcp": {
                "\(serverName)": {
                  "type": "local",
                  "command": [\(json(command)), "--mcp"],
                  "enabled": true,
                  "environment": {
                    "\(credentialKey)": \(json(secret))
                  }
                }
              }
            }
            """
        }
        return Snippet(host: host, configPath: host.configPath, format: host.format, body: body, guidance: guidance(for: host))
    }

    public static func all(executablePath: String, credential: ClientCredential) -> [Snippet] {
        Host.allCases.map { snippet(host: $0, executablePath: executablePath, credential: credential) }
    }

    /// Addressed to the human, not to an agent. v1's snippet was written to the
    /// agent — "your agent name", request shape, expected behaviour — which is
    /// what made pasting it into a chat window the obvious thing to do.
    public static func guidance(for host: Host) -> String {
        """
        Write this into \(host.configPath) and set the file to 0600, then restart \(host.title).

        This text contains a live Vaultage client credential. It is shown once and Vaultage does not store it — only a hash. Do not paste it into a chat, an agent transcript, an issue or a commit.

        The credential names this client on every approval sheet. By itself it approves nothing: every action asks you, in Vaultage's own window.

        It becomes more than a name the moment you give this client an auto-allow grant. A grant scoped to this client lets anything holding this credential run the covered actions, in the covered environments, without asking you, until the grant expires or you revoke it. Any program running as you can read this credential out of the configuration file or the environment. Grant accordingly, and revoke from Activity when you are done.

        If you lose it, rotate the client in Vaultage and write the new snippet; if it leaks, revoke the client.
        """
    }

    /// Minimal JSON string literal, also valid as a TOML basic string.
    private static func json(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }
}
