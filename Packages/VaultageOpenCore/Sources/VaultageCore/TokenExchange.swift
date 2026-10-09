import Foundation

// BL-117 (D51) — the exchange request body, as a compiled field list.
//
// `blueprint/design/credential-classes-spec.md` version 2 §2.4 placement rule 3
// is the normative page, and it is the one place in the whole design where the
// approved-template gate is genuinely weakened: `ApprovedRequest.matchesExactly`
// compares a request body against the route's compiled bytes, and a token
// endpoint's body cannot be compiled bytes because it contains a secret.
//
// What replaces "equals the compiled bytes" is stricter than "compare nothing",
// and it is a contract rather than a convention:
//
// > An exchange route's body is produced by one builder from one compiled field
// > list. The caller supplies no field, no name and no order.
//
// The caller hands in a credential and gets a `SecretPayload`. There is no
// parameter for a field, a name, an order or an extra value, so a caller cannot
// add a parameter, rename one or reorder them, and nothing outside the compiled
// list can reach the wire. The gate becomes *the body's field names, in order,
// equal the compiled list, with no extra field* — which
// `ProviderCredentialClassContracts` asserts against a produced body, including
// against one built from a synthetic secret containing `& = + % ' '`.
//
// **What this buys, stated plainly rather than left to inference** (§2.4):
// `matchesExactly` is a gate against a *caller*, not against an attacker with
// code in the broker — such an attacker already holds the credential through
// `withBytes` and gains nothing from the body. What the compiled field list
// stops is a bug and a future author, and what it adds is that the property is
// assertable.
//
// Runbook §10 item 2: an exchange body field is one of the spec's compiled
// vocabularies. An onboarding change may not add one.

/// The three ephemeral values an exchange body can carry that are neither a
/// literal nor a stored field. None is produced at the Azure slot: client
/// credentials has no code, no verifier and — Microsoft states it plainly —
/// no refresh token.
public enum ExchangeEphemeral: String, Sendable, Codable, CaseIterable, Hashable {
    /// The authorization code of an authorization-code ceremony.
    case code
    /// The PKCE verifier of the same ceremony.
    case codeVerifier
    /// The durable half of a user grant, on the refresh path (§4.1).
    case refreshToken
}

/// One field of a compiled exchange body. Closed, ordered by its position in
/// `ExchangeBodySpec.fields`, and not extendable by an onboarding change.
public enum ExchangeBodyField: Sendable, Hashable {
    /// A compiled name and a compiled value — `grant_type=client_credentials`,
    /// `scope=https://graph.microsoft.com/.default`. Neither half comes from a
    /// caller.
    case literal(name: String, value: String)
    /// A named typed field of the stored credential. This is the only case that
    /// puts secret bytes on the wire, and it is the reason the builder exists:
    /// the value is appended straight out of the credential's own borrow, so it
    /// never becomes a `String`.
    case credentialField(name: String, CompositeCredentialField)
    /// A signed JWT assertion — Google's service-account grant (§7.3). No
    /// producer exists at the Azure slot.
    case assertion(name: String)
    /// One of the three ephemerals above. No producer exists at the Azure slot.
    case ephemeral(name: String, ExchangeEphemeral)
    /// GitHub's documented `redirect_uri`, whose value is per-ceremony — neither
    /// a literal nor one of the three ephemerals (§2.4). **Unused here**, and
    /// deliberately compiled with no producer: §7.4 is the slot that builds it
    /// from the compiled scheme and the same request id the redirect used, and
    /// never from a caller.
    case ceremonyReturnTarget(name: String)

    /// The parameter name this field is sent under. It is compiled on the case
    /// rather than derived, because the provider documents the name and the
    /// name is what the contract suite compares.
    public var name: String {
        switch self {
        case let .literal(name, _): name
        case let .credentialField(name, _): name
        case let .assertion(name): name
        case let .ephemeral(name, _): name
        case let .ceremonyReturnTarget(name): name
        }
    }
}

/// BL-117's GitHub slot (§7.4, CC-M7) — **the per-ceremony values the four
/// non-compiled fields are produced from.**
///
/// The three ephemerals and the ceremony return target were compiled with no
/// producer from the Azure slot onward and **refused**, which is the honest
/// shape for a field nothing can fill. This is the producer, and it is the same
/// shape `.assertion` took one slot earlier: the caller hands in values, and
/// the **spec** still owns every field name, every order and the derivation of
/// anything that can be derived.
///
/// Three rules make that true rather than merely intended:
///
///   1. **The return target is not in this type at all.** §2.4 requires it to be
///      *"built by the machinery from the compiled scheme and the same request
///      id the redirect used, and never from a caller"*, so the builder derives
///      it from `ceremony.requestID` through `ProviderConnectReturn`. A caller
///      cannot pass a target, cannot pass a scheme and cannot pass a host —
///      there is no parameter for any of them.
///   2. **The verifier is not in this type either.** It is read from the
///      ceremony, which is the only thing that minted it, so a body can never be
///      built with a verifier from one ceremony and a return target from
///      another.
///   3. **The two genuine secrets are `VaultSecret`s.** The authorization code
///      and the refresh token go into the body through the same scoped borrow
///      every stored field already takes, so neither is ever a Swift `String`
///      between the ceremony and the wire.
///
/// A field whose input is absent still **refuses**, exactly as it did when no
/// producer existed: a spec that compiles `.ephemeral(.code)` and is built with
/// no code is a bug, and the fail-closed answer is the same one §2.5 (a) gives.
public struct ExchangeCeremonyInputs: Sendable {
    /// The ceremony this body belongs to. Supplies the PKCE verifier and, by
    /// way of its request id, the return target.
    public let ceremony: ProviderConnectCeremony?
    /// The provider's authorization code. Nil on the refresh path and nil
    /// under §3.3's split, where the **Worker** holds the code and the Mac
    /// never sees it.
    public let code: VaultSecret?
    /// The durable half of a user grant, on the refresh path (§4.1). It is a
    /// vault value read under the presence proof of the action that needs it,
    /// and it arrives here already borrowed out of custody.
    public let refreshToken: VaultSecret?

    public init(ceremony: ProviderConnectCeremony? = nil, code: VaultSecret? = nil, refreshToken: VaultSecret? = nil) {
        self.ceremony = ceremony
        self.code = code
        self.refreshToken = refreshToken
    }
}

/// §2.4's `ExchangeBodySpec`: the compiled, ordered, closed field list one
/// exchange route's body is produced from.
public struct ExchangeBodySpec: Sendable, Hashable {
    public let fields: [ExchangeBodyField]

    /// BL-117's Google Cloud slot (§7.3). The compiled shape of the assertion
    /// an `.assertion` field is filled with, or nil for a body that carries
    /// none.
    ///
    /// **The producer is compiled on the spec rather than passed in**, and that
    /// is the whole reason this is a field and not a parameter on `body`. §2.4's
    /// replacement for the byte-equality gate is *"the caller supplies no field,
    /// no name and no order"*, expressed as a signature; a `body(credential:
    /// assertion:)` would have handed the caller back the one value that
    /// authenticates the request. With the spec owning the claim set, the
    /// builder signs it itself and a caller still supplies only a credential.
    public let assertion: JWTAssertionSpec?

    /// The largest body this spec may produce. A client secret is short and a
    /// scope is a URL; 8 KiB is three orders of magnitude of headroom and is
    /// the fixed capacity `SecretPayloadBuilder` is given, so appending never
    /// reallocates and never leaves a stale plaintext copy behind.
    public static let maximumBodyBytes = 8 * 1024

    public init(fields: [ExchangeBodyField], assertion: JWTAssertionSpec? = nil) {
        self.fields = fields
        self.assertion = assertion
    }

    /// The compiled names, in compiled order. This is the list the gate
    /// compares a produced body against.
    public var fieldNames: [String] { fields.map(\.name) }

    /// Builds the body for one credential, in a buffer `SecretPayloadBuilder`
    /// zeroes.
    ///
    /// The caller supplies **only** the credential: no field, no name, no order
    /// and no extra value. That is the whole of §2.4's replacement for the
    /// byte-equality gate, expressed as a signature rather than as a rule a
    /// reviewer has to check each call site for.
    ///
    /// - Parameter now: the clock the assertion's `iat` and `exp` are taken
    ///   from, defaulted so every existing call site is unchanged. It is here
    ///   for one reason — a test vector needs a fixed `iat` — and it is not a
    ///   field: it cannot name a parameter, rename one, reorder them or add
    ///   one, so the property above is untouched.
    /// - Throws: `VaultageError.unsupported` for a field whose producer does
    ///   not exist at this commit — the three ephemerals and the ceremony
    ///   return target. Refusing is the fail-closed answer and is stricter than
    ///   leaving the cases out: a route that compiled one would otherwise have
    ///   to be caught by review. **`.assertion` left that list at BL-117's
    ///   Google Cloud slot** and is now produced from the compiled
    ///   `JWTAssertionSpec` below; a spec that declares the field without the
    ///   producer still refuses, which is the honest shape for a body nothing
    ///   can fill.
    /// - Parameter ceremony: BL-117's GitHub slot. The per-ceremony values the
    ///   three ephemerals and the ceremony return target are produced from,
    ///   defaulted so every call site that predates §7.4 is unchanged. Like
    ///   `now`, it **cannot name a field, rename one, reorder them or add one**,
    ///   so §2.4's property is untouched: what it supplies is values, exactly as
    ///   `credential` does.
    public func body(credential: VaultSecret, ceremony: ExchangeCeremonyInputs? = nil, now: Date = Date()) throws -> SecretPayload {
        let builder = SecretPayloadBuilder(capacity: Self.maximumBodyBytes)
        for (index, field) in fields.enumerated() {
            if index > 0 { try builder.append("&") }
            try builder.appendFormName(field.name)
            try builder.append("=")
            switch field {
            case let .literal(_, value):
                try builder.appendFormValue(value)
            case let .credentialField(_, stored):
                try builder.appendFormValue(of: credential, field: stored)
            case .assertion:
                // §7.3's RS256 assertion, signed inside the broker from the
                // claim set compiled on this spec. The signed bytes come out of
                // `JWTAssertionSigner` as a `VaultSecret` and go into the body
                // through the same borrow every other secret takes, so the
                // assertion is never a `String` between the signer and the
                // wire.
                guard let assertion else {
                    throw VaultageError.unsupported("This exchange body compiles an assertion field with no assertion to sign.")
                }
                let signed = try JWTAssertionSigner.sign(assertion, credential: credential, now: now)
                try builder.appendFormValue(of: signed.assertion, field: .token)
            case let .ephemeral(_, ephemeral):
                // §3's ceremony values, produced from `ceremony` and from
                // nothing else. Each one refuses when its input is absent,
                // which is the same fail-closed answer the case gave when no
                // producer existed at all — a spec that compiles a field
                // nothing can fill is a bug, and it is refused before a
                // `URLSession` task exists rather than sent half-built.
                switch ephemeral {
                case .code:
                    guard let code = ceremony?.code else {
                        throw VaultageError.unsupported("This exchange body compiles an authorization code with no code to fill it.")
                    }
                    try builder.appendFormValue(of: code, field: .token)
                case .codeVerifier:
                    // Read from the ceremony rather than passed in, so a body
                    // can never carry one ceremony's verifier beside another
                    // ceremony's return target.
                    guard let verifier = ceremony?.ceremony?.codeVerifier else {
                        throw VaultageError.unsupported("This exchange body compiles a PKCE verifier with no ceremony to take one from.")
                    }
                    try builder.appendFormValue(verifier)
                case .refreshToken:
                    guard let refresh = ceremony?.refreshToken else {
                        throw VaultageError.unsupported("This exchange body compiles a refresh token with no refresh token to fill it.")
                    }
                    try builder.appendFormValue(of: refresh, field: .token)
                }
            case .ceremonyReturnTarget:
                // §2.4 / CC-M7 and §7.4's `redirect_uri`. **Derived**, never
                // supplied: built by this machinery from the compiled scheme,
                // the compiled host and the same request id the redirect used.
                // There is no parameter a caller could pass a target through,
                // which is what the fifth case exists to guarantee.
                guard let target = ceremony?.ceremony?.ceremonyReturnTarget else {
                    throw VaultageError.unsupported("This exchange body compiles a ceremony return target with no ceremony to derive one from.")
                }
                try builder.appendFormValue(target)
            }
        }
        return builder.finish()
    }

    /// The field names a produced form body actually carries, in order, parsed
    /// from the bytes rather than from the spec.
    ///
    /// This is the *other* half of the contract: the suite builds a body from a
    /// synthetic secret containing `& = + % ' '` and asserts that what comes
    /// back out of this parse is exactly `fieldNames` — same names, same order,
    /// same count. A percent-encoding bug that let a secret split the body into
    /// extra parameters shows up here as a longer list, with no attacker
    /// involved.
    ///
    /// It splits on the *structural* separators only, which is correct because
    /// the builder percent-encodes every `&` and `=` inside a name or a value.
    public static func fieldNames(inProducedBody body: SecretPayload) -> [String] {
        var text = ""
        body.withBytes { raw in text = String(decoding: raw, as: UTF8.self) }
        guard !text.isEmpty else { return [] }
        return text.components(separatedBy: "&").map { pair in
            guard let separator = pair.firstIndex(of: "=") else { return pair }
            return String(pair[pair.startIndex ..< separator])
        }
    }
}

public extension SecretPayloadBuilder {

    /// §2.4 / CC-M2. The bytes that may appear in a form value **unencoded**.
    ///
    /// RFC 3986's *unreserved* set — `ALPHA / DIGIT / "-" / "." / "_" / "~"` —
    /// compiled as a byte set rather than expressed as a character class, so
    /// there is no locale, no Unicode folding and no regular expression between
    /// the rule and the bytes. Everything else is percent-encoded, **including
    /// the space**, which is emitted as `%20` rather than `+`: `+` is
    /// `application/x-www-form-urlencoded`'s own spelling and it is one more
    /// thing a reader has to know is not a literal plus.
    ///
    /// The reason this is a compiled set rather than `addingPercentEncoding` is
    /// the reason CC-M2 exists: a secret containing `&` or `=` would otherwise
    /// split the body into extra parameters and defeat the no-extra-field
    /// property **with no attacker involved**, and Foundation's character sets
    /// are a poor place to state a security property — `.urlQueryAllowed`
    /// permits both `&` and `=`.
    static let formUnreservedBytes: Set<UInt8> = {
        var allowed = Set<UInt8>()
        for byte in UInt8(ascii: "A") ... UInt8(ascii: "Z") { allowed.insert(byte) }
        for byte in UInt8(ascii: "a") ... UInt8(ascii: "z") { allowed.insert(byte) }
        for byte in UInt8(ascii: "0") ... UInt8(ascii: "9") { allowed.insert(byte) }
        for byte in [UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~")] { allowed.insert(byte) }
        return allowed
    }()

    /// Appends a compiled parameter **name**, percent-encoded against the same
    /// set. A name is always a compiled literal, so this can never encode
    /// anything surprising; it exists so that the name and the value go through
    /// one rule rather than two.
    func appendFormName(_ name: String) throws {
        try appendFormValue(name)
    }

    /// Appends non-secret text as a form value, percent-encoded against the
    /// compiled unreserved set.
    func appendFormValue(_ text: String) throws {
        for byte in Array(text.utf8) {
            try appendBytes(Self.percentEncoded(byte))
        }
    }

    /// Appends **one typed field of a credential** as a form value, without
    /// ever materializing the credential as a `String`.
    ///
    /// This is the form-encoded sibling of `appendJSONString(of:)`, and it is
    /// deliberately the same shape: the bytes come out of the credential's own
    /// scoped borrow, one at a time, and go straight into the fixed-capacity
    /// buffer this builder zeroes. There is no intermediate `Data`, no
    /// `String`, and no way to pass in an already-encoded value.
    ///
    /// Taking a `CompositeCredentialField` rather than a whole `VaultSecret` is
    /// the CC-H6 lesson applied one seam earlier: an exchange body carries the
    /// client **secret** and never the envelope that also holds the client id,
    /// so the selector is on the call rather than left to the caller to slice.
    func appendFormValue(of credential: VaultSecret, field: CompositeCredentialField) throws {
        var failure: Error?
        try credential.withCompositeField(field) { raw in
            guard VaultSecret.bytesAreValidUTF8(raw) else {
                failure = VaultageError.invalidInput("The protected credential is not valid UTF-8.")
                return
            }
            for byte in raw {
                do {
                    try self.appendBytes(Self.percentEncoded(byte))
                } catch {
                    failure = error
                    return
                }
            }
        }
        if let failure { throw failure }
    }

    /// One byte, unencoded when it is unreserved and `%XX` in uppercase hex
    /// otherwise.
    static func percentEncoded(_ byte: UInt8) -> [UInt8] {
        if formUnreservedBytes.contains(byte) { return [byte] }
        let digits = Array("0123456789ABCDEF".utf8)
        return [UInt8(ascii: "%"), digits[Int(byte >> 4)], digits[Int(byte & 0x0F)]]
    }
}
