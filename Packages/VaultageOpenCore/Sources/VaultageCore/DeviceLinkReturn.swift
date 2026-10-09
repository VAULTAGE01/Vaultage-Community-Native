import Foundation

/// BL-113 (D47) — `vaultage://link/<authorization id>[?proof=<one-time proof>]`,
/// the browser's way of telling this app that the sign-in it started has been
/// approved.
///
/// ## What it is, and what it deliberately is not
///
/// **BL113-C1 changed what this URL is for.** It was a *wake-up*: it carried an
/// authorization id and nothing else, and a Mac that never received it linked
/// anyway because `waitForLink()` kept polling. The security pass showed that
/// this is exactly what made the automatic approval a device-code phishing
/// primitive — an attacker's Mac never needs the return, so approving on the
/// victim's browser was enough to link it.
///
/// So an **automatic** approval now puts a one-time proof in the query, and the
/// Worker will not complete the exchange for such an authorization without it.
/// The proof is not a credential on its own — it proves nothing without the
/// polling secret and the PKCE verifier, which were minted on this Mac and have
/// never left the Keychain — but it is the half of the binding that can only
/// travel machine-locally, because Launch Services resolves this URL on the
/// machine whose browser opened it. An attacker's Mac is not that machine.
///
/// Everything that actually links this Mac still happens in
/// `DeviceAccountClient.pollLink()`, and the device session still comes back
/// over TLS in a response body. What is no longer true is "a Mac that never
/// receives this URL still links": for an automatic approval it does not, and
/// the human falls back to the one-click approval card instead. A **manual**
/// approval is unchanged and needs no proof at all.
///
/// ## Why the id is checked against the pending link rather than parsed
///
/// D41 gives v2 the `vaultage://` scheme, which means any process on this Mac,
/// and any web page the human clicks, can hand this app a URL of this shape.
/// The rule is therefore not "is this a well-formed link URL" but "is this the
/// one authorization **this app** minted and is still waiting on". A URL naming
/// any other id is refused with a receipt, because being handed a link ceremony
/// this app did not start is a fact the owner is entitled to see.
///
/// The parse is deliberately strict and total: one host, one path component, a
/// lowercase canonical UUID, no fragment, no user, no password, no port — and
/// either no query at all or exactly the literal `proof=` followed by one
/// base64url token, read out of the raw query string so that nothing is
/// percent-decoded on the way. Nothing is normalised, so nothing can be
/// normalised wrongly.
public enum DeviceLinkReturn: Sendable {
    /// The scheme the app registers in `CFBundleURLTypes` (D41).
    public static let scheme = "vaultage"
    /// The host these URLs live under: `vaultage://link/<id>`.
    public static let host = "link"

    /// Why a return URL was refused. Each case is a distinct receipt line.
    public enum Refusal: String, Error, Sendable, Equatable {
        /// Not a `vaultage://link/<uuid>` URL at all.
        case malformed
        /// Well-formed, but naming an authorization this app did not mint.
        case unknownAuthorization
        /// Well-formed and known, but this app is not waiting on a link.
        case noPendingLink
    }

    /// BL113-C1. What a `vaultage://link/…` URL carries, once it has passed.
    ///
    /// `proof` is nil for the return of a **manual** approval, which needs
    /// none, and for the bare target this app builds as its own `next`.
    public struct Accepted: Sendable, Equatable {
        public let authorizationID: String
        /// The one-time proof the Worker minted at an automatic approval.
        /// **Never logged, never written to a receipt, never shown**: it is
        /// presented to the exchange and nowhere else.
        public let proof: String?
        public init(authorizationID: String, proof: String? = nil) {
            self.authorizationID = authorizationID
            self.proof = proof
        }
    }

    /// The whole of what this app will read out of a `vaultage://link/…` URL.
    ///
    /// Lowercase canonical UUID only: the Worker mints ids with
    /// `crypto.randomUUID()`, which is lowercase, and the comparison downstream
    /// is an equality test. Accepting an uppercase spelling here would mean
    /// either a case-insensitive comparison or a normalisation step, and both
    /// are more surface than this needs.
    ///
    /// BL113-C1's query is read the same way: the raw query string must be
    /// **exactly** `proof=` followed by one base64url token of the length the
    /// Worker mints. A second item, a different name, an empty value, an
    /// escaped character or any decoration is not a return this app will act
    /// on — it is not narrowed to "the proof is ignored", because a URL that is
    /// not the shape the Worker emits is a URL something else on this Mac
    /// composed.
    public static func accepted(in url: URL) -> Accepted? {
        guard url.scheme?.lowercased() == scheme,
              url.host?.lowercased() == host,
              url.fragment == nil,
              url.user == nil, url.password == nil, url.port == nil
        else { return nil }
        // The path and the query are read **as written**, through
        // `URLComponents`' percent-encoded accessors. `URL.path` decodes and
        // also silently drops a trailing slash, and `URL.query` decodes — both
        // of which are normalisations, and the Worker's own allowlist is a
        // whole-string equality that performs neither. This side must not be
        // the laxer of the two.
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let path = parts.percentEncodedPath.isEmpty ? nil : parts.percentEncodedPath,
              path.hasPrefix("/")
        else { return nil }
        let id = String(path.dropFirst())
        guard isCanonicalUUID(id) else { return nil }
        guard let query = parts.percentEncodedQuery else { return Accepted(authorizationID: id, proof: nil) }
        guard query.hasPrefix(proofQueryPrefix) else { return nil }
        let proof = String(query.dropFirst(proofQueryPrefix.count))
        guard isReturnProof(proof) else { return nil }
        return Accepted(authorizationID: id, proof: proof)
    }

    /// The authorization id in a `vaultage://link/<id>` URL, or nil. The URL
    /// handler needs exactly this much to decide whether to forward the URL at
    /// all; the proof is only ever read by the actor that holds the pending
    /// authorization.
    public static func authorizationID(in url: URL) -> String? {
        accepted(in: url)?.authorizationID
    }

    /// The one query item this scheme will ever carry, spelled once.
    static let proofQueryPrefix = "proof="

    /// The Worker mints the proof as 32 CSPRNG bytes, base64url — the same
    /// shape as the polling secret and the session token, and the same bound
    /// this client already applies to both.
    static func isReturnProof(_ value: String) -> Bool {
        guard (43 ... 128).contains(value.count) else { return false }
        return value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
    }

    /// The URL the Mac asks the browser to come back to, for an id it minted.
    ///
    /// Built from the compiled scheme and host and re-checked by the parser
    /// above, so the only string this function can produce is one
    /// `authorizationID(in:)` accepts. A non-canonical id produces nothing
    /// rather than a URL that would be refused on the way back.
    public static func url(authorizationID id: String) -> URL? {
        guard isCanonicalUUID(id), let url = URL(string: "\(scheme)://\(host)/\(id)") else { return nil }
        return authorizationID(in: url) == id ? url : nil
    }

    /// The whole decision, as a pure function of the URL and what this app is
    /// waiting on, so every branch can be driven without a Keychain or a
    /// network. `pendingRequestID` is nil when no link is in flight.
    public static func resolve(_ url: URL, pendingRequestID: String?) -> Result<Accepted, Refusal> {
        guard let value = accepted(in: url) else { return .failure(.malformed) }
        guard let pending = pendingRequestID else { return .failure(.noPendingLink) }
        // BL113-C1. Whole-string equality on the id, before the proof is looked
        // at at all: a proof that came with the wrong id is not a proof this app
        // will ever present, and a well-formed proof must never buy a URL any
        // latitude on which ceremony it belongs to.
        guard value.authorizationID == pending else { return .failure(.unknownAuthorization) }
        return .success(value)
    }

    /// 8-4-4-4-12 lowercase hexadecimal, and nothing else.
    static func isCanonicalUUID(_ value: String) -> Bool {
        let groups = value.split(separator: "-", omittingEmptySubsequences: false)
        guard groups.count == 5 else { return false }
        let widths = [8, 4, 4, 4, 12]
        for (group, width) in zip(groups, widths) {
            guard group.count == width, group.allSatisfy({ $0.isASCII && ($0.isNumber || ("a"..."f").contains($0)) }) else { return false }
        }
        return true
    }
}

/// BL-113 — what the sign-in screen is doing right now.
///
/// It is here rather than in the app target because the state machine is the
/// contract between `DeviceAccountClient` and the screen, and `--self-test`
/// drives every transition as a pure function rather than through a window.
public enum SignInPhase: Sendable, Equatable {
    /// The Keychain read for a live device session is in flight. Nothing is
    /// drawn behind this: an optimistic landing screen that then disappears is
    /// worse than a moment of honesty.
    case checking
    /// No device session. The two buttons.
    case signedOut
    /// The browser has been opened; this Mac is polling the exchange.
    case waitingForBrowser(deviceName: String, expiresAt: Date)
    /// The browser refused, denied, or the app was handed a link it did not start.
    case refused(reason: String)
    /// The ten-minute authorization window closed.
    case expired
    /// The account service could not be reached.
    case offline
    /// BL-113 follow-up. The Worker's own creation budget refused this Mac's
    /// attempt. Distinct from `offline`: this Mac was reached and answered,
    /// so it must never say so.
    ///
    /// BL113-M4. It carries the wait, because the Worker computes a true one
    /// and the screen was throwing it away to say "a few minutes" about a wait
    /// that can be fifty-nine. The budget's window is fixed and aligned to the
    /// hour, so the number only ever shrinks and quoting it is never an
    /// over-promise. `nil` is "the refusal offered no number", which is the
    /// only case the constant sentence is still used for.
    case rateLimited(retryAfterSeconds: TimeInterval?)
    /// A device session exists. The shell may draw the workspace.
    case signedIn

    /// The one question the shell asks. Everything that is not `signedIn` draws
    /// the sign-in screen and nothing else — no rail, no landing screen, no
    /// catalog, no vault content.
    public var showsWorkspace: Bool { self == .signedIn }
}
