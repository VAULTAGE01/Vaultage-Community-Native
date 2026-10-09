import CryptoKit
import Foundation

// BL-117 (D51) §3 — the authorization-code ceremony, on the Mac.
//
// `blueprint/design/credential-classes-spec.md` version 2 §3.2, §3.3, §3.4 and
// §3.5 are the normative pages. This file is the whole of what the Mac mints,
// holds and checks for one connect ceremony, and it is deliberately a pure
// value type plus a store: every rule below can be driven without a browser,
// without a Worker and without a Keychain, which is what lets §3.5's refusal
// list be asserted one case at a time.
//
// **Four values, and only the first two ever leave this Mac** (§3.4):
//
//   | Value | Travels | Lifetime |
//   |---|---|---|
//   | connect-request id | in the return target | 10 minutes |
//   | `state` (256-bit) | to the provider; **hash only** to the Worker | 10 minutes, single use |
//   | PKCE verifier | **never**, until the exchange call | one ceremony |
//   | OIDC `nonce` | to the provider; **never to the Worker** | one ceremony |
//
// **Why the ceremony is not a credential.** None of these four is a secret the
// vault custodies: they are ephemeral, they are worthless after ten minutes,
// and the one that matters — the verifier — is worthless to anyone who does not
// also hold the code. They are held in memory for the life of the ceremony and
// dropped, which is why there is no `Codable` conformance anywhere in this file
// and no path under the broker's container for any of it.
//
// **Why PKCE is `S256` and never `plain`.** RFC 8252 §6 requires PKCE for every
// public native client, and GitHub is explicit that *"the plain code challenge
// method is not supported"* (read 2026-09-13). There is no representation for
// `plain` here at all, which is how that becomes a fact a reader can check
// rather than a sentence in a document.

/// BL-117 §3 — one authorization-code ceremony's minted values.
///
/// Deliberately **not** `Codable`, `Equatable` by identity, or printable: the
/// verifier and the nonce are the two halves of the ceremony an attacker would
/// need, and the type surface is what keeps them off a disk and out of a log.
/// `SecretExposureContracts`' type-surface test asserts the absence.
public struct ProviderConnectCeremony: Sendable {
    /// §3.4's connect-request id, and §5.1's `authorizationID` — *"it is not a
    /// second identifier"*. One UUID names the ceremony from the first browser
    /// open to the sealed refresh token.
    public let requestID: UUID
    /// 256 bits, base64url. A **ceremony selector**, not the anti-injection
    /// control: §3.3 says plainly that the callback route is necessarily
    /// unauthenticated, so anyone holding a victim's `state` can drive that
    /// ceremony's callback, and what stops a code injection is that the
    /// attacker's code was issued against the attacker's own challenge and
    /// fails the provider's verifier check. PKCE is the control; this is the
    /// row lookup.
    public let state: String
    /// RFC 7636's verifier. 43–128 characters of the unreserved set; this mints
    /// 64 base64url characters from 48 CSPRNG bytes, the same shape
    /// `AccountClient.startLink` already mints for the device flow.
    ///
    /// **It never leaves this Mac** until the exchange call of §3.3 step 4.
    public let codeVerifier: String
    /// The OIDC `nonce`, minted for every ceremony and carried in the authorize
    /// request. §3.3a checks it in an `id_token` where the provider issues one;
    /// GitHub issues none, so for GitHub the binding is the confirmed principal
    /// instead — the nonce is minted anyway, because a value that exists only
    /// for some providers is a value the next provider's author forgets.
    ///
    /// **Never to the Worker** (§3.4).
    public let nonce: String
    /// The provider this ceremony authorises. Compiled, never a caller's text.
    public let provider: Provider
    /// When the ceremony was minted. The window is ten minutes from here.
    public let startedAt: Date

    /// §3.2 step 4 and §3.5: ten minutes, single use.
    public static let window: TimeInterval = 600

    public init(
        requestID: UUID,
        state: String,
        codeVerifier: String,
        nonce: String,
        provider: Provider,
        startedAt: Date
    ) {
        self.requestID = requestID
        self.state = state
        self.codeVerifier = codeVerifier
        self.nonce = nonce
        self.provider = provider
        self.startedAt = startedAt
    }

    /// Mints a fresh ceremony. Every value is CSPRNG; nothing a server said
    /// becomes part of any of them, which is §3.2 step 2's rule stated as a
    /// signature rather than as a comment on a call site.
    public static func mint(provider: Provider, now: Date = Date()) throws -> ProviderConnectCeremony {
        ProviderConnectCeremony(
            requestID: UUID(),
            state: try randomBase64URL(bytes: 32),
            codeVerifier: try randomBase64URL(bytes: 48),
            nonce: try randomBase64URL(bytes: 32),
            provider: provider,
            startedAt: now
        )
    }

    /// The `S256` challenge: base64url of SHA-256 over the **ASCII** verifier,
    /// which is RFC 7636's own definition and is why the verifier is minted in
    /// the unreserved set rather than as arbitrary bytes.
    public var codeChallenge: String {
        Self.base64URL(SHA256.hash(data: Data(codeVerifier.utf8)))
    }

    /// The only thing the Worker is ever told about `state` (§3.3 step 1).
    ///
    /// Registering the **hash** rather than the value stays right for the reason
    /// §3.3 gives: the Worker only ever needs to find the row, and registering
    /// the value would let a compromised Worker forge a callback the Mac's own
    /// `state` check would then accept.
    public var stateHash: String {
        Self.base64URL(SHA256.hash(data: Data(state.utf8)))
    }

    /// §2.4's fifth `ExchangeBodyField` case, built **by the machinery** from the
    /// compiled scheme and the same request id the redirect used — never from a
    /// caller. It is the one string this ceremony hands the exchange body, and
    /// `ProviderConnectReturn.url(requestID:)` is the only thing that can
    /// produce it.
    public var ceremonyReturnTarget: String? {
        ProviderConnectReturn.url(requestID: requestID)?.absoluteString
    }

    public func isLive(at now: Date) -> Bool {
        now >= startedAt && now.timeIntervalSince(startedAt) < Self.window
    }

    /// §3.2 step 4's `state` check: **constant time**, over bytes.
    ///
    /// A short-circuiting `==` on two `String`s leaks the length of the common
    /// prefix, and the value being compared is the one a page holding half a
    /// ceremony would be guessing at. The length is compared first and is not
    /// secret: `state` is a fixed 43 characters for every ceremony this Mac
    /// mints, so a length mismatch reveals nothing a constant would not.
    public func stateMatches(_ candidate: String) -> Bool {
        Self.constantTimeEquals(state, candidate)
    }

    static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8), right = Array(rhs.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }

    static func base64URL(_ bytes: some Sequence<UInt8>) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func randomBase64URL(bytes: Int) throws -> String {
        var data = Data(count: bytes)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }
        guard status == errSecSuccess else {
            throw VaultageError.invalidInput("This Mac could not produce the random values a connect ceremony needs.")
        }
        return base64URL(data)
    }
}

/// BL-117 §3.2/§3.3 — `vaultage://connect/<request id>`, the browser's way of
/// telling this app that an authorisation it started has come back.
///
/// **It shares D41's scheme with BL-113's `vaultage://link/<id>` and disturbs
/// nothing about it.** The two are separated by the **host**, which is a
/// compiled literal on each side and is compared before anything else: `link`
/// is the sign-in return and `connect` is this one. `MainWindow`'s URL handler
/// asks `DeviceLinkReturn` first and this second, and neither parser accepts
/// the other's host, so a return for one ceremony can never be resolved as the
/// other. `Scripts/test-scheme-claims.sh` is untouched: no new bundle, no new
/// registration, no second `CFBundleURLTypes` entry — one scheme, two hosts.
///
/// ## The bare form, and why there is nothing else to parse
///
/// CC-H3 closed by simplification: under shape B **the provider's code never
/// travels through the browser**. The Worker holds it against the ceremony's
/// row and redirects to the **bare** target, which is character-for-character
/// the shape `/auto-approve` already returns and is compared by the same
/// whole-string equality. So this parser accepts exactly one string per
/// ceremony and every other refusal follows for free: another scheme, another
/// host, a query, a fragment, an authority, a port, a second path segment, an
/// uppercase scheme, a trailing slash, trailing whitespace.
///
/// **A return carrying any query at all is refused on the equality before any
/// of §3.5's other rules is reached**, which is exactly what §3.5 says. That is
/// the difference from `DeviceLinkReturn`, which has a documented query item
/// (`?proof=`) and therefore a parser for one: this has none, and a `?code=`
/// arriving here is a URL something else on this Mac composed.
public enum ProviderConnectReturn: Sendable {
    /// D41's scheme, shared with the link return and spelled once per parser so
    /// neither can drift from the bundle's registration.
    public static let scheme = "vaultage"
    /// The host these URLs live under. Not `link`.
    public static let host = "connect"

    /// §3.5, as a closed list. Every one of these refuses, leaves the connection
    /// uncreated, and **writes a receipt** — the owner is entitled to see in
    /// Activity that an authorisation ceremony they did not start arrived at
    /// their Mac, which is the rule `sign-in-at-launch-spec.md` §4 already sets
    /// for the link return.
    public enum Refusal: String, Error, Sendable, Equatable, CaseIterable {
        /// Not a bare `vaultage://connect/<uuid>` URL: wrong scheme, wrong host,
        /// no path component, more than one, a component that is not a canonical
        /// UUID, or **any query or fragment at all**.
        case malformed
        /// Well-formed, but naming a ceremony this app did not mint.
        case unmintedCeremony
        /// Well-formed and minted, but past its ten-minute window.
        case ceremonyExpired
        /// Well-formed and minted, but already exchanged. A second return for a
        /// completed ceremony is a refusal, not a no-op.
        case ceremonySpent
        /// No ceremony is in flight at all.
        case noPendingCeremony
    }

    /// The request id in a bare `vaultage://connect/<id>` URL, or nil.
    ///
    /// The path and query are read **as written**, through `URLComponents`'
    /// percent-encoded accessors, for `DeviceLinkReturn`'s reason: `URL.path`
    /// decodes and silently drops a trailing slash, and `URL.query` decodes.
    /// Both are normalisations, the Worker's own allowlist is a whole-string
    /// equality that performs neither, and this side must not be the laxer of
    /// the two.
    public static func requestID(in url: URL) -> UUID? {
        guard url.scheme?.lowercased() == scheme,
              url.host?.lowercased() == host,
              url.fragment == nil,
              url.user == nil, url.password == nil, url.port == nil
        else { return nil }
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              // CC-H3's whole-string equality, in the one place it can be
              // expressed as an absence: this scheme's connect return carries
              // **no** query, so a URL with one is not narrowed to "the query is
              // ignored" — it is refused.
              parts.percentEncodedQuery == nil,
              parts.percentEncodedFragment == nil
        else { return nil }
        let path = parts.percentEncodedPath
        guard path.hasPrefix("/") else { return nil }
        let id = String(path.dropFirst())
        guard DeviceLinkReturn.isCanonicalUUID(id) else { return nil }
        return UUID(uuidString: id)
    }

    /// The URL the Mac registers as its return target, for a ceremony it minted.
    ///
    /// Built from the compiled scheme and host and **re-checked by the parser
    /// above**, so the only string this function can produce is one
    /// `requestID(in:)` accepts. That round trip is what makes §2.4's
    /// *"built by the machinery from the compiled scheme and the same request id
    /// the redirect used, and never from a caller"* a property rather than a
    /// promise: there is no parameter here but the id, and the id is a `UUID`.
    public static func url(requestID: UUID) -> URL? {
        let id = requestID.uuidString.lowercased()
        guard let url = URL(string: "\(scheme)://\(host)/\(id)") else { return nil }
        return Self.requestID(in: url) == requestID ? url : nil
    }

    /// The whole decision, as a pure function of the URL and the ceremony this
    /// app is waiting on, so every branch of §3.5 can be driven without a
    /// browser, a Worker or a Keychain.
    ///
    /// - Parameter spent: whether this ceremony has already exchanged. §3.5
    ///   lists *"a second return for a ceremony already exchanged"* as its own
    ///   refusal, distinct from an expired one, because the two mean different
    ///   things to an owner reading a receipt.
    public static func resolve(
        _ url: URL,
        pending: ProviderConnectCeremony?,
        spent: Bool = false,
        now: Date = Date()
    ) -> Result<UUID, Refusal> {
        guard let id = requestID(in: url) else { return .failure(.malformed) }
        guard let pending else { return .failure(.noPendingCeremony) }
        guard id == pending.requestID else { return .failure(.unmintedCeremony) }
        guard !spent else { return .failure(.ceremonySpent) }
        guard pending.isLive(at: now) else { return .failure(.ceremonyExpired) }
        return .success(id)
    }
}
