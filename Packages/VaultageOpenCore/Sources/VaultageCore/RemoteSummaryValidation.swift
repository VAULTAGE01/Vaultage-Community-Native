import Foundation

/// BL-099 — §3.1's two validator classes, and §3.3 item 1c's byte rules.
///
/// **Where validation happens** (§3.1). Because the summary is sealed, the
/// Worker cannot screen it. Validation runs **twice, at the two parties that
/// matter**: the Mac validates before sealing, and the phone validates after
/// opening and refuses to render or sign a summary carrying any key it cannot
/// place in the canonical field list. The server-side screen is lost; that is a
/// strict improvement, because it existed to stop a credential-shaped label
/// reaching D1 and now no label reaches D1 at all.
///
/// **A failure is a refusal of the whole publication, never a silent scrub.**
///
/// **The split is load-bearing** (DB-M1). Version 2's "every string field runs
/// `secretLike`" rejects every well-formed publication: executed, `secretLike`
/// is true for every UUID, every 64-hex digest and every base64url thumbprint,
/// and `credentialWording` is true for `cloudflare.worker.secret.put`. So Class
/// A is shape-validated — exact regex or enum membership, no heuristic — and
/// only Class B, the human text, runs the intake heuristics.
public enum RemoteSummaryValidation {
    /// §3.1: whole object ≤ 4 KiB compact.
    public static let maximumEncodedBytes = 4096
    /// §6.3 / Q3.
    public static let maximumOpenPendingCount = 8
    /// §3.5's hard ceiling, enforced by the Worker and re-checked here.
    public static let maximumTTLSeconds = 15 * 60
    /// DB-H14.
    public static let maximumOfferedMutations = 32

    public struct Refusal: LocalizedError, Equatable {
        public let field: String
        public let reason: String
        public var errorDescription: String? { "\(field): \(reason)" }
    }

    static func refuse(_ field: String, _ reason: String) -> Refusal { Refusal(field: field, reason: reason) }

    // MARK: - Class A — shape-validated

    static func requireUUID(_ value: String, _ field: String) throws {
        guard UUID(uuidString: value) != nil else { throw refuse(field, "is not a UUID") }
    }

    static func requireHex64(_ value: String, _ field: String) throws {
        guard value.count == 64, value.allSatisfy({ $0.isASCII && ($0.isNumber || ("a"..."f").contains($0)) }) else {
            throw refuse(field, "is not 64 lower-case hex characters")
        }
    }

    static func requireMember(_ value: String, of set: [String], _ field: String) throws {
        guard set.contains(value) else { throw refuse(field, "is not one of \(set.sorted().joined(separator: ", "))") }
    }

    // MARK: - Class B — human text

    /// §3.1's Class B bounds, one per field, so a length is a property of the
    /// field rather than a number remembered at a call site.
    public enum ClassBField: String, CaseIterable, Sendable {
        case agentLabel, connectionLabel, principalHint, projectName, environmentName, resourceLabel
        case choiceLabel, choiceDetail, scriptName, variableName
        /// The **pinned** device name (§2.4, §4.8; BM-H4). It is not a summary
        /// field — it never travels in a sealed summary — but it is the same
        /// *kind* of string, from the same kind of source: the ceremony's
        /// caller takes it from the roster, which is served by the party this
        /// design treats as hostile, and it then lands verbatim in the arming
        /// prompt's `localizedReason`, the Activity line, every remote audit
        /// event, the Devices screen and the production banner. §3.1's rule —
        /// "every string is drawn from a resolved local record or a fixed
        /// enum" — was satisfied on a technicality: the pin record *is* local,
        /// and its contents were chosen by the relay at pairing time. §4.8's
        /// "never the roster's `name` at render time" closes the render-time
        /// half; this closes the pin-time half.
        case deviceName

        public var maximumLength: Int {
            switch self {
            case .agentLabel: 64
            /// §2.4's ceremony shows this beside six words on a fixed screen,
            /// and PF-9 makes the arming prompt the moment one evaluation
            /// becomes a capability. A device name is "Eden's iPhone", not a
            /// paragraph.
            case .deviceName: 64
            case .choiceDetail: 120
            default: 96
            }
        }

        /// §3.3 item 1c: **a per-field allowed-script declaration rather than an
        /// ASCII-only rule**, so ideographic and RTL locales still work. Every
        /// Class B field here is owner- or provider-authored prose, so all of
        /// them permit any single script — what is refused is *mixing* two
        /// scripts inside one token, which is the homoglyph attack.
        public var allowsNonLatinScripts: Bool { true }
    }

    /// The four intake heuristics plus the byte rules, in the order a failure is
    /// most useful to read.
    public static func validateClassB(_ value: String, _ field: ClassBField) throws {
        guard value.count <= field.maximumLength else {
            throw refuse(field.rawValue, "is longer than \(field.maximumLength) characters")
        }
        guard !APITokenRequestValidation.hasControlCharacters(value) else {
            throw refuse(field.rawValue, "carries a control character")
        }
        // §3.3 item 1c. `CanonicalDigest.encode` hashes raw UTF-8 with no
        // normalization, so one visual string must be one byte string before it
        // is digested *and* before it is rendered. NFD input is refused rather
        // than silently normalised: the Mac composes this text from its own
        // records, so an NFD value is a record that needs fixing, not a
        // publication to quietly repair.
        // Compared as **bytes**, not as Strings: Swift's `==` is Unicode
        // canonical equivalence, so an NFD string equals its NFC form and the
        // check would never fire. `CanonicalDigest.encode` hashes
        // `Data(field.utf8)` — the actual code units — so bytes are also the
        // thing that has to match.
        guard Array(value.utf8) == Array(value.precomposedStringWithCanonicalMapping.utf8) else {
            throw refuse(field.rawValue, "is not NFC-normalised")
        }
        if let scalar = value.unicodeScalars.first(where: { isBidiOrInvisible($0) }) {
            throw refuse(field.rawValue, "carries U+\(String(format: "%04X", scalar.value)), a bidi control or invisible separator")
        }
        // **The token is not echoed** (BM-M10). This was the one interpolation of
        // untrusted text on the whole surface: the refusal reaches
        // `RemotePublishOutcome.transportUnavailable` and
        // `RemoteConnectRequestOutcome.unavailable`, and the latter is designed
        // to reach an agent. The tokens are owner-chosen record labels rather
        // than credentials, so the leak was names and not values — and the field
        // name is enough for an owner and for a log either way.
        if mixedScriptToken(in: value) != nil {
            throw refuse(field.rawValue, "mixes two writing systems inside one word")
        }
        guard !APITokenRequestValidation.looksLikeASecret(value) else {
            throw refuse(field.rawValue, "looks like a credential")
        }
        guard !credentialWording(value) else {
            throw refuse(field.rawValue, "names a credential")
        }
        guard !looksLikeAResourcePath(value) else {
            throw refuse(field.rawValue, "looks like a resource path or ARN")
        }
    }

    /// `credentialWording` from `src/intake.ts`, transcribed. A label that says
    /// "api key" is either a secret or an invitation to paste one.
    public static func credentialWording(_ value: String) -> Bool {
        let pattern = "\\b(?:api[\\s_-]*key|access[\\s_-]*token|refresh[\\s_-]*token|secret|password|passphrase|bearer|private[\\s_-]*key|credential)\\b"
        return value.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
    }

    /// §3.1's resource-shape refusal, `/[/\\]|^arn:|:\/\//i`, exactly as BL-075
    /// does today.
    public static func looksLikeAResourcePath(_ value: String) -> Bool {
        value.range(of: "[/\\\\]|^arn:|://", options: [.regularExpression, .caseInsensitive]) != nil
    }

    /// Bidi overrides and isolates, the directional marks, the zero-width
    /// joiners and separators, the word joiner and the BOM. Each of these
    /// renders one visual string as another while both computers agree on the
    /// digest, which is DB-M11's whole case.
    public static func isBidiOrInvisible(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x200B...0x200F: true   // ZWSP, ZWNJ, ZWJ, LRM, RLM
        case 0x202A...0x202E: true   // LRE, RLE, PDF, LSO, RSO
        case 0x2060...0x2064: true   // word joiner and the invisible operators
        case 0x2066...0x2069: true   // LRI, RLI, FSI, PDI
        case 0xFEFF: true            // BOM as a zero-width no-break space
        default: false
        }
    }

    /// The first token that mixes two scripts, or `nil`.
    ///
    /// "Production" and "Ρroduction" differ by one glyph — a Greek capital rho —
    /// and `principalHint` is provider-supplied text (`Grant.swift:304` already
    /// treats it as untrusted for exactly this reason). A token is refused when
    /// its letters come from two different scripts; the Japanese trio (Han,
    /// Hiragana, Katakana) counts as one script, because ordinary Japanese text
    /// mixes all three inside one token.
    public static func mixedScriptToken(in value: String) -> String? {
        for token in value.split(whereSeparator: { $0.isWhitespace || $0.isPunctuation }) {
            var scripts: Set<Script> = []
            for scalar in token.unicodeScalars {
                guard let script = script(of: scalar), script != .common else { continue }
                scripts.insert(script)
            }
            if !scriptsAreCompatible(scripts) { return String(token) }
        }
        return nil
    }

    /// Which script combinations are one writing system rather than a
    /// homoglyph. Japanese mixes Kana and Han inside one word, and Korean mixes
    /// Hangul and Hanja, so both are permitted; every other pairing — Latin with
    /// Cyrillic, Latin with Greek — is the attack DB-M11 names.
    public static func scriptsAreCompatible(_ scripts: Set<Script>) -> Bool {
        scripts.count <= 1
            || scripts.isSubset(of: [.japanese, .otherCJK])
            || scripts.isSubset(of: [.hangul, .otherCJK])
    }

    /// The script families this protocol distinguishes. Deliberately coarse: the
    /// question is "could these two glyphs be confused for one another", and the
    /// answer only needs script-level resolution.
    public enum Script: Hashable, Sendable {
        case common, latin, greek, cyrillic, arabic, hebrew, devanagari, thai, japanese, hangul, otherCJK
    }

    public static func script(of scalar: Unicode.Scalar) -> Script? {
        switch scalar.value {
        case 0x0041...0x005A, 0x0061...0x007A, 0x00C0...0x024F, 0x1E00...0x1EFF: .latin
        case 0x0370...0x03FF, 0x1F00...0x1FFF: .greek
        case 0x0400...0x04FF, 0x0500...0x052F: .cyrillic
        case 0x0590...0x05FF: .hebrew
        case 0x0600...0x06FF, 0x0750...0x077F: .arabic
        case 0x0900...0x097F: .devanagari
        case 0x0E00...0x0E7F: .thai
        case 0x3040...0x30FF: .japanese                 // Hiragana and Katakana
        case 0x4E00...0x9FFF, 0x3400...0x4DBF: .otherCJK // Han
        case 0xAC00...0xD7AF, 0x1100...0x11FF: .hangul
        default: scalar.properties.isAlphabetic ? nil : .common
        }
    }

    // MARK: - The whole summary

    /// Everything §3.1 says about a summary, applied before it is sealed.
    ///
    /// Class A first, because a malformed id is a programming fault and Class B
    /// failures are the ones an owner might have caused.
    public static func validate(_ summary: RemoteApprovalSummary) throws {
        try requireUUID(summary.pendingId, "pendingId")
        try requireUUID(summary.macDeviceId, "macDeviceId")
        if let clientID = summary.agentClientId { try requireUUID(clientID, "agentClientId") }
        try requireHex64(summary.brokerRequestDigest, "brokerRequestDigest")
        guard summary.brokerDigestKind.count <= 48, !summary.brokerDigestKind.isEmpty else {
            throw refuse("brokerDigestKind", "is empty or longer than 48 characters")
        }
        try requireMember(summary.agentState, of: ["enrolled", "unenrolled"], "agentState")
        try requireMember(summary.sensitivity, of: EnvironmentSensitivity.allCases.map(\.rawValue), "sensitivity")
        try requireMember(summary.verb, of: ["read", "write", "deploy", "grant", "connect"], "verb")
        // **The four shipped raw values**, read off the shipped enum rather than
        // re-typed, so the summary renders what the Mac's own chip renders.
        // Note the raw value is `production-affecting`; §3.1's prose writes the
        // Swift case name `productionAffecting` while saying "raw values".
        try requireMember(summary.trustClass, of: OperationTrustClass.allCases.map(\.rawValue), "trustClass")
        guard (0...maximumOpenPendingCount).contains(summary.openPendingCount) else {
            throw refuse("openPendingCount", "is outside 0...\(maximumOpenPendingCount)")
        }
        guard summary.issuedAt > 0, summary.expiresAt > summary.issuedAt else {
            throw refuse("expiresAt", "is not after issuedAt")
        }
        guard summary.expiresAt - summary.issuedAt <= maximumTTLSeconds else {
            throw refuse("expiresAt", "is more than \(maximumTTLSeconds / 60) minutes after issuedAt")
        }
        for scope in summary.offeredScopes {
            try requireMember(scope, of: RemoteDecisionScope.allCases.map(\.rawValue), "offeredScopes")
        }
        for duration in summary.offeredDurations {
            try requireMember(duration, of: RemoteDecisionDuration.allCases.map(\.rawValue), "offeredDurations")
        }
        for project in summary.offeredProjects { try requireUUID(project.id, "offeredProjects.id") }
        for choice in summary.choices { try requireUUID(choice.id, "choices.id") }

        // The agent's identity is a fact about enrolment, not a free field.
        if summary.agentState == "unenrolled" {
            guard summary.agentLabel == nil, summary.agentClientId == nil else {
                throw refuse("agentState", "says unenrolled but the summary names a client")
            }
        } else {
            guard summary.agentLabel != nil, summary.agentClientId != nil else {
                throw refuse("agentState", "says enrolled but the summary names no client")
            }
        }

        // Class sections. Every class emits both headers in the digest; only the
        // matching class may carry a *populated* one.
        switch summary.summaryClass {
        case .grant:
            guard let grant = summary.grant, summary.connect == nil else {
                throw refuse("grant", "a grant summary must carry the grant section and no connect section")
            }
            guard grant.offeredMutations.count <= maximumOfferedMutations else {
                throw refuse("offeredMutations", "names more than \(maximumOfferedMutations) mutations")
            }
            for raw in grant.offeredMutations {
                guard let operation = Operation(rawValue: raw) else {
                    throw refuse("offeredMutations", "names \(raw), which is not a compiled operation")
                }
                guard operation.approvalRequirement.requiresExplicitGrantInclusion else {
                    throw refuse("offeredMutations", "names \(raw), which no grant may cover")
                }
            }
            try requireHex64(grant.offeredCoverageDigest, "offeredCoverageDigest")
            try requireUUID(grant.recipientDeviceId, "recipient")
            guard RemoteDeviceKeyThumbprint.isWellFormed(grant.recipientApvThumbprint) else {
                throw refuse("recipient", "carries a malformed apv thumbprint")
            }
        case .connect:
            guard summary.connect != nil, summary.grant == nil else {
                throw refuse("connect", "a connect summary must carry the connect section and no grant section")
            }
        case .action, .provisioningSelection:
            guard summary.grant == nil, summary.connect == nil else {
                throw refuse("class", "\(summary.summaryClass.rawValue) carries a class section that belongs to another class")
            }
        }

        // Class B.
        if let label = summary.agentLabel { try validateClassB(label, .agentLabel) }
        try validateClassB(summary.connectionLabel, .connectionLabel)
        if let hint = summary.principalHint { try validateClassB(hint, .principalHint) }
        try validateClassB(summary.projectName, .projectName)
        try validateClassB(summary.environmentName, .environmentName)
        if let resource = summary.resourceLabel { try validateClassB(resource, .resourceLabel) }
        for choice in summary.choices {
            try validateClassB(choice.label, .choiceLabel)
            try validateClassB(choice.detail, .choiceDetail)
        }
        if let destination = summary.destination {
            try validateClassB(destination.scriptName, .scriptName)
            try validateClassB(destination.variableName, .variableName)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(summary)
        guard encoded.count <= maximumEncodedBytes else {
            throw refuse("summary", "is \(encoded.count) bytes compact, over the \(maximumEncodedBytes)-byte ceiling")
        }
    }
}
