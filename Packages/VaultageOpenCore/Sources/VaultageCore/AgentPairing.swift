import CryptoKit
import Foundation
import Security

// BL-136 Part B (D70 as amended, 2026-09-21) — pairing an agent.
//
// The pure half of the ceremony: the code, the agent's origin and its digest,
// and one pending request's clock and attempt budget. No I/O here — no process
// inspection, no Keychain, no sheet — so every rule below is driven by the
// self-test suite directly. The broker service supplies the origin (it reads
// it from the operating system, never from the client) and the Keychain
// binding store; the `--mcp` process supplies the sheet.
//
// Two facts from the amendment shape everything in this file:
//
// * **The code is a binding, not a secret.** RFC 8628 shows its user code on
//   the untrusted device on purpose. Here the requesting agent is shown it and
//   the person types it into a capture-protected sheet on the Mac, so a
//   pairing someone else requested at the same moment cannot be approved by
//   mistake: the person types the code *their* agent showed. What must stay
//   out of an agent's reach is the pairing it produces, which lives in the
//   Keychain.
// * **Identity comes from the operating system.** The agent is the client that
//   launched `Vaultage --mcp` — its code signature, or its file location when
//   it has none — in the folder it was launched from. Nothing a client sends
//   is part of it.

// MARK: - The code

/// An RFC 8628 user code: eight characters from a base-20 alphabet of
/// consonants, shown as two groups of four.
///
/// RFC 8628 §6.1 recommends exactly this alphabet — no vowels, so no words,
/// and none of the letters people misread for digits — and eight characters,
/// which is about 34.6 bits: far beyond what five attempts in ten minutes can
/// search, and still something a person reads off a chat message and types
/// without error.
public struct PairingCode: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let alphabet: [Character] = Array("BCDFGHJKLMNPQRSTVWXZ")
    public static let length = 8

    /// The eight characters, no separator.
    private let characters: String

    private init(characters: String) { self.characters = characters }

    /// A fresh code from the system's secure random source, by rejection
    /// sampling so every character is exactly as likely as every other.
    public static func generate() -> PairingCode {
        var result = ""
        let accept = UInt8(256 - (256 % alphabet.count)) // 240: an exact multiple of 20
        while result.count < length {
            var bytes = [UInt8](repeating: 0, count: 16)
            // A failure here would yield a predictable code, so it is fatal
            // rather than degraded — the same rule as `ClientCredential`.
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
                fatalError("Vaultage could not obtain secure random bytes for a pairing code.")
            }
            for byte in bytes where byte < accept && result.count < length {
                result.append(alphabet[Int(byte) % alphabet.count])
            }
        }
        return PairingCode(characters: result)
    }

    /// For the contract suite only: a code with known characters.
    public static func fixture(_ characters: String) -> PairingCode? {
        guard characters.count == length, characters.allSatisfy(alphabet.contains) else { return nil }
        return PairingCode(characters: characters)
    }

    /// What the requesting agent is shown and the person reads: `XXXX-XXXX`.
    public var display: String {
        "\(characters.prefix(4))-\(characters.suffix(4))"
    }

    /// What a person typed, the way RFC 8628 §6.1 asks a verifier to read it:
    /// case-insensitive, and blind to the separator and to spaces. Anything
    /// that is not then exactly eight characters of the alphabet is nil.
    public static func normalized(_ typed: String) -> String? {
        let separators: Set<Character> = ["-", " ", "\u{2010}", "\u{2011}", "\u{2012}", "\u{2013}", "\u{2014}", "\u{2212}"]
        guard typed.utf8.count <= 64 else { return nil }
        let kept = typed.uppercased().filter { !separators.contains($0) }
        guard kept.count == length, kept.allSatisfy(alphabet.contains) else { return nil }
        return kept
    }

    /// Whether `typed` is this code, compared over the normalized bytes in
    /// constant time.
    public func matches(typed: String) -> Bool {
        guard let candidate = Self.normalized(typed) else { return false }
        let left = Array(characters.utf8), right = Array(candidate.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }

    // Never printed by accident: the one way out is `display`, which exists for
    // the first `vaultage_pair` result and nothing else.
    public var description: String { "PairingCode(redacted)" }
    public var debugDescription: String { "PairingCode(redacted)" }
}

// MARK: - Who is asking

/// The client half of an agent: what launched `Vaultage --mcp`.
public enum AgentClient: Hashable, Sendable {
    /// A valid code signature with a team identifier. The strongest claim the
    /// operating system can make about another process.
    case signed(teamID: String, identifier: String)
    /// No valid signature with a team — an interpreter such as `node` or
    /// `python` started from a terminal, or an ad-hoc build. Only its file
    /// location identifies it, and any program that runs as that file shares
    /// the identity.
    case unsigned(path: String)
    /// Nothing trustworthy could be read: the parent had already exited, was
    /// launchd, or started after the process it supposedly launched. Such an
    /// agent cannot pair and stays anonymous.
    case unknown
}

/// How strongly an origin identifies the agent. Said on every sheet, because
/// the claim about who is asking is only as strong as the path that made it.
public enum AgentIdentificationStrength: String, Codable, Hashable, Sendable {
    case codeSignature = "code-signature"
    case fileLocation = "file-location"
    case none

    public var sentence: String {
        switch self {
        case .codeSignature: "Identified by its code signature."
        case .fileLocation: "Identified by its file location only: any program that runs as that file in that folder is the same agent."
        case .none: "Not identified. It is served anonymously, with every action approved here, and it cannot be paired."
        }
    }
}

/// An agent: the client that launched `Vaultage --mcp`, in the folder it was
/// launched from — Descope's client × folder split, so one app in two
/// projects is two agents, each with its own pairing and its own grants.
///
/// Built by the broker service from the operating system. Every string is
/// bounded and stripped of control characters on the way in, because each of
/// them reaches an approval sheet.
public struct AgentOrigin: Hashable, Sendable {
    public static let maximumPathBytes = 1024
    public static let maximumIdentifierBytes = 255

    public let client: AgentClient
    /// The absolute folder, or nil when it could not be read.
    public let folder: String?

    public init(client: AgentClient, folder: String?) {
        switch client {
        case let .signed(teamID, identifier):
            if let team = Self.canonicalTeamID(teamID), let id = Self.bounded(identifier, maxBytes: Self.maximumIdentifierBytes) {
                self.client = .signed(teamID: team, identifier: id)
            } else {
                self.client = .unknown
            }
        case let .unsigned(path):
            if let clean = Self.bounded(path, maxBytes: Self.maximumPathBytes), clean.hasPrefix("/") {
                self.client = .unsigned(path: clean)
            } else {
                self.client = .unknown
            }
        case .unknown:
            self.client = .unknown
        }
        self.folder = folder.flatMap { Self.bounded($0, maxBytes: Self.maximumPathBytes) }.flatMap { $0.hasPrefix("/") ? $0 : nil }
    }

    public var strength: AgentIdentificationStrength {
        switch client {
        case .signed: .codeSignature
        case .unsigned: .fileLocation
        case .unknown: .none
        }
    }

    public var canPair: Bool { strength != .none }

    /// Canonical, injective fields: the kind first, so no path can pass for an
    /// identifier and no identifier for a path.
    public var canonicalFields: [String] {
        let clientFields: [String]
        switch client {
        case let .signed(teamID, identifier): clientFields = ["signed", teamID, identifier]
        case let .unsigned(path): clientFields = ["unsigned", "none", path]
        case .unknown: clientFields = ["unknown", "none", "none"]
        }
        return ["vaultage.agent.origin.v1"] + clientFields + ["folder", folder ?? "none"]
    }

    /// What the Keychain binding is keyed by. A digest rather than the fields,
    /// so the Keychain item's attributes say nothing about which folders hold
    /// which agents; the metadata record keeps the human-readable half.
    public var digest: String {
        SHA256.hash(data: CanonicalDigest.encode(canonicalFields)).map { String(format: "%02x", $0) }.joined()
    }

    /// The client, the way the sheet names it.
    public var clientLine: String {
        switch client {
        case let .signed(teamID, identifier): "\(Self.knownName(identifier) ?? identifier) (team \(teamID))"
        case let .unsigned(path): path
        case .unknown: "An unidentified program"
        }
    }

    /// The folder, with the home directory abbreviated.
    public var folderLine: String {
        guard let folder else { return "an unknown folder" }
        // `NSHomeDirectory()` rather than `homeDirectoryForCurrentUser`, which
        // iOS does not have: VaultageCore is compiled into the phone app too.
        let home = NSHomeDirectory()
        return folder == home ? "~" : (folder.hasPrefix(home + "/") ? "~" + folder.dropFirst(home.count) : folder)
    }

    /// The name the pairing sheet suggests; the person edits it there.
    public var suggestedName: String {
        let clientName: String
        switch client {
        case let .signed(_, identifier): clientName = Self.knownName(identifier) ?? identifier.split(separator: ".").last.map(String.init) ?? identifier
        case let .unsigned(path): clientName = (path as NSString).lastPathComponent
        case .unknown: clientName = "Agent"
        }
        guard let folder, folder != "/" else { return clientName }
        return "\(clientName) — \((folder as NSString).lastPathComponent)"
    }

    /// Display names for hosts people recognise by name rather than by bundle
    /// identifier. A label only: nothing is decided by it.
    static func knownName(_ identifier: String) -> String? {
        switch identifier {
        case "com.anthropic.claudefordesktop": "Claude"
        case "com.anthropic.claude-code", "claude": "Claude Code"
        case "com.todesktop.230313mzl4w4u92": "Cursor"
        case "com.microsoft.VSCode": "Visual Studio Code"
        case "com.exafunction.windsurf": "Windsurf"
        case "dev.zed.Zed": "Zed"
        default: nil
        }
    }

    /// Apple team identifiers are ten upper-case letters and digits.
    static func canonicalTeamID(_ value: String) -> String? {
        value.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil ? value : nil
    }

    static func bounded(_ raw: String, maxBytes: Int) -> String? {
        let stripped = String(raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && !CharacterSet.newlines.contains($0) })
        guard !stripped.isEmpty, stripped.utf8.count <= maxBytes, stripped == raw else { return nil }
        return stripped
    }
}

// MARK: - One pending request

/// One pairing request, held by the broker for one connection, in memory only.
public struct PendingPairing: Sendable {
    public static let lifetime: TimeInterval = 10 * 60
    public static let attemptBudget = 5

    public let origin: AgentOrigin
    public let code: PairingCode
    public let createdAt: Date
    public private(set) var wrongAttempts = 0

    public var expiresAt: Date { createdAt.addingTimeInterval(Self.lifetime) }

    public init(origin: AgentOrigin, code: PairingCode = .generate(), createdAt: Date) {
        self.origin = origin
        self.code = code
        self.createdAt = createdAt
    }

    public enum Check: Equatable, Sendable {
        /// The typed code is this request's. Touch ID comes next.
        case matched
        /// Wrong, with this many attempts left. The request stands.
        case wrong(remaining: Int)
        /// Wrong for the fifth time. The request is over.
        case exhausted
        /// Ten minutes have passed. The request is over, whatever was typed.
        case expired
    }

    /// Checks what the person typed. Expiry is decided first, so a correct
    /// code typed late is still refused; every wrong entry — malformed or
    /// empty included — spends one attempt.
    public mutating func check(typed: String, at now: Date) -> Check {
        guard now < expiresAt else { return .expired }
        guard wrongAttempts < Self.attemptBudget else { return .exhausted }
        if code.matches(typed: typed) { return .matched }
        wrongAttempts += 1
        let remaining = Self.attemptBudget - wrongAttempts
        return remaining > 0 ? .wrong(remaining: remaining) : .exhausted
    }

    public func isExpired(at now: Date) -> Bool { now >= expiresAt }
}
