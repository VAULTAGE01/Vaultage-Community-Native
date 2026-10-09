import Foundation

// BL-117 (D51) — the one thing that reads a token endpoint's reply.
//
// `blueprint/design/credential-classes-spec.md` version 2 §2.5 is the normative
// page, and this is the sharpest rule in §2:
//
// > An exchange reply is read by **`TokenExchangeReader` and by nothing else**.
// > It lifts the token bytes out of the raw body **before any JSON parse**,
// > byte-by-byte into a `VaultSecret`, overwrites the span it occupied so the
// > document stays well-formed, and only then parses the redacted document for
// > the value-free fields (`token_type`, `expires_in`, `scope`).
//
// Two wrong answers it exists to refuse, both of which look reasonable:
//
//   * running `ValueFree.withoutForeignSecrets` on the reply — it strips
//     forbidden keys and refuses what survives, and `access_token` is a
//     forbidden key, so it would strip **the answer**;
//   * running nothing — which puts a live token through `JSONSerialization`
//     and produces an unzeroable Swift `String` for it.
//
// **This is the third hand-written scanner, so it is hoisted rather than
// written again.** `AccountAPITokens.swift` already records that
// `CloudflareResourceCreation.extractTokenValue` is the second and that the
// hoist is the right answer. One shared scanner, parameterised by key name,
// alphabet and length bounds.
//
// **And it is not "exactly what `AccountClient` does", which is the safety.**
// That scanner is safe because a `vlt_` value has a fixed 56-byte length and a
// compiled alphabet. An `access_token` has neither *across providers* — so the
// alphabet and the length range are compiled **per provider** and a value
// outside them refuses. That is strictly stronger than "no backslash escape",
// which it also does: `\` is in no provider's alphabet.

/// The compiled shape of one provider's access token: which bytes may appear in
/// it and how long it may be.
///
/// Runbook §10 item 2 territory: this is a compiled vocabulary and an
/// onboarding change may not add to it.
public struct TokenExchangeAlphabet: Sendable, Hashable {
    /// A short, value-free name for the shape, used only in this type's own
    /// diagnostics. Never provider text and never near a token.
    public let label: String
    public let allowed: Set<UInt8>
    public let minimumBytes: Int
    public let maximumBytes: Int

    public init(label: String, allowed: Set<UInt8>, minimumBytes: Int, maximumBytes: Int) {
        self.label = label
        self.allowed = allowed
        self.minimumBytes = minimumBytes
        self.maximumBytes = maximumBytes
    }

    /// base64url — `A-Z a-z 0-9 - _` — plus the two `.` separators a JWT has.
    ///
    /// This is Microsoft's and Google's shape. It deliberately does **not**
    /// include `=`: a JWT is base64url **without** padding, and admitting `=`
    /// would admit a value that could not be one.
    public static let jsonWebToken = TokenExchangeAlphabet(
        label: "jwt",
        allowed: {
            var allowed = Set<UInt8>()
            for byte in UInt8(ascii: "A") ... UInt8(ascii: "Z") { allowed.insert(byte) }
            for byte in UInt8(ascii: "a") ... UInt8(ascii: "z") { allowed.insert(byte) }
            for byte in UInt8(ascii: "0") ... UInt8(ascii: "9") { allowed.insert(byte) }
            for byte in [UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: ".")] { allowed.insert(byte) }
            return allowed
        }(),
        // A Microsoft Graph app-only token is a few hundred bytes of header,
        // payload and signature. The floor rules out an empty or stub value and
        // the ceiling rules out a body-sized one; neither is a guess about the
        // exact length, which Microsoft does not document and which varies with
        // the claims in the token.
        minimumBytes: 64,
        maximumBytes: 8 * 1024
    )

    /// BL-117's Google Cloud slot (§7.3, §2.5) — **the second alphabet
    /// decision, made explicitly.**
    ///
    /// The Azure slot's evidence note asked this slot to state which alphabet
    /// it picked and why, *"rather than reusing Microsoft's by default because
    /// it happens to pass"*. It does not reuse it, and here is the reason,
    /// which is not the obvious one:
    ///
    ///   * **A Google service-account access token is not a JWT.** The **JWT is
    ///     the assertion Vaultage sends**; what comes back is an opaque bearer
    ///     token with no documented internal structure. Compiling
    ///     `.jsonWebToken` for it would have been a claim about Google's token
    ///     format that Google does not make, and it would have quietly broken
    ///     the day that format changed.
    ///   * **Google's own documented example would have been refused.** The
    ///     service-account page's successful response prints
    ///     `"access_token": "1/8xbJqaOZXSUZbHLl5EOtu1pxz3fmmetKx9W8CV4t79M"`
    ///     (read 2026-09-13) — a `/` in the first two characters, which
    ///     base64url does not admit. An alphabet that refuses the provider's
    ///     own documented reply is not a stricter alphabet, it is a bug.
    ///   * **The ceiling is Google's, not a headroom guess.** *"Access tokens
    ///     2048 bytes"* is a documented limit, alongside *"Google reserves the
    ///     right to change token size within these limits, and your application
    ///     must support variable token sizes accordingly"* (read 2026-09-13).
    ///     So 2048 is the compiled maximum and it is a fact rather than the
    ///     three-orders-of-magnitude headroom Microsoft's needed.
    ///
    /// What it still refuses is what the rule is for: `\` is outside it, so a
    /// value carrying a JSON escape is refused before it is unescaped; so are
    /// the quotation mark, whitespace, every control character, `&` and `=`.
    /// `=` in particular is excluded even though `/` and `+` differ between
    /// base64 and base64url, because no Google access token is padded and
    /// admitting padding would admit a value that cannot be one.
    public static let googleAccessToken = TokenExchangeAlphabet(
        label: "google",
        allowed: {
            var allowed = Set<UInt8>()
            for byte in UInt8(ascii: "A") ... UInt8(ascii: "Z") { allowed.insert(byte) }
            for byte in UInt8(ascii: "a") ... UInt8(ascii: "z") { allowed.insert(byte) }
            for byte in UInt8(ascii: "0") ... UInt8(ascii: "9") { allowed.insert(byte) }
            // base64url's two, the `.` a `ya29.`-prefixed token carries, and the
            // `/` Google's own documented example carries.
            for byte in [UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: "."), UInt8(ascii: "/")] { allowed.insert(byte) }
            return allowed
        }(),
        // Google's documented example is 45 bytes; a `ya29.` token is a few
        // hundred. The floor rules out an empty or stub value without refusing
        // the shortest token Google has ever printed.
        minimumBytes: 32,
        maximumBytes: 2048
    )

    /// BL-117's GitHub slot (§2.5, §7.4) — **the third alphabet decision, made
    /// explicitly, because the Google slot's note asked this slot to make it.**
    ///
    /// *"GitHub's token is `ghu_` plus alphanumerics, which is neither compiled
    /// shape, so it needs a third — and it should say so rather than stretching
    /// one of the two."* It is a third, and here is why neither of the two fits:
    ///
    ///   * **`.jsonWebToken` is wrong twice.** A GitHub user access token is
    ///     opaque, not a JWT, so compiling the JWT alphabet would be a claim
    ///     about GitHub's format that GitHub does not make — the same mistake
    ///     the Google slot refused one slot earlier. And the JWT alphabet admits
    ///     `.`, which a `ghu_` token does not carry, so it would be **laxer**
    ///     than the shape it is describing.
    ///   * **`.googleAccessToken` is wrong once, and it is the sharper miss.**
    ///     It admits `/` — because Google's own documented example carries one —
    ///     and `/` in a GitHub token would be a value that cannot be one. An
    ///     alphabet borrowed because it happens to pass is an alphabet that
    ///     admits the union of two providers' shapes and the intersection of
    ///     neither's guarantees.
    ///
    /// So: uppercase, lowercase, digits and the single `_` that separates the
    /// prefix from the body. **`-` is deliberately absent**, which is what makes
    /// this stricter than both of the others rather than merely different.
    ///
    /// **What this alphabet is cited from, stated plainly.** `credential-classes
    /// -spec.md` §2.5 — *"`ghu_` plus alphanumerics for GitHub"* — written from
    /// a first-hand read of GitHub's user-access-token page on 2026-09-14.
    /// **No GitHub page was read from this lane** and no live GitHub call was
    /// made, so the *bounds* below are Vaultage's own rather than GitHub's
    /// documented ones, and saying so is more honest than presenting them as
    /// cited: the floor rules out an empty or stub value, the ceiling rules out
    /// a body-sized one, and neither is a claim about a length GitHub publishes.
    /// Confirming them against a real token is part of this adapter's live
    /// certification, which is owner-owed.
    public static let githubUserToken = TokenExchangeAlphabet(
        label: "github",
        allowed: {
            var allowed = Set<UInt8>()
            for byte in UInt8(ascii: "A") ... UInt8(ascii: "Z") { allowed.insert(byte) }
            for byte in UInt8(ascii: "a") ... UInt8(ascii: "z") { allowed.insert(byte) }
            for byte in UInt8(ascii: "0") ... UInt8(ascii: "9") { allowed.insert(byte) }
            // The one separator, and nothing else. Not `-`, not `.`, not `/`.
            allowed.insert(UInt8(ascii: "_"))
            return allowed
        }(),
        minimumBytes: 32,
        maximumBytes: 512
    )

    func admits(_ raw: UnsafeRawBufferPointer) -> Bool {
        guard raw.count >= minimumBytes, raw.count <= maximumBytes else { return false }
        for byte in raw where !allowed.contains(byte) { return false }
        return true
    }
}

/// What one provider's token reply must look like, compiled beside its routes.
public struct TokenExchangeSpec: Sendable, Hashable {
    /// The documented `token_type`, compared **case-insensitively** (CC-L6).
    /// Microsoft documents `Bearer` and GitHub documents lowercase `bearer`, and
    /// a literal comparison would refuse one documented reply or the other.
    public let tokenType: String
    public let alphabet: TokenExchangeAlphabet
    /// The scope this connection asked for, recorded so §2.5's scope rules have
    /// something to compare a granted set against. Azure's reply carries no
    /// `scope` field at all, which is the concrete reason version 1's
    /// superset refusal was not implementable.
    public let requestedScopes: Set<String>

    public init(tokenType: String, alphabet: TokenExchangeAlphabet, requestedScopes: Set<String>) {
        self.tokenType = tokenType
        self.alphabet = alphabet
        self.requestedScopes = requestedScopes
    }
}

/// What an exchange reply yields: one token that is a `VaultSecret`, and the
/// value-free metadata §2.5 permits to be projected.
///
/// Deliberately not `Codable`, for the reason `VaultSecret` is not: nothing may
/// serialise this, and `SecretExposureContracts`'s type-surface test asserts it.
public struct ExchangedToken: Sendable {
    /// The minted token. It is a `VaultSecret` from the moment it leaves the
    /// raw body and it never becomes a `String` outside the one header
    /// placement, which is the same rule every stored credential already
    /// follows.
    public let token: VaultSecret
    /// The **compiled** token type, not the provider's spelling of it. The
    /// reply's own bytes are compared and then discarded, so no provider text
    /// reaches a surface through this field.
    public let tokenType: String
    /// §2.5: *"`expires_in` is projected as a duration and `expiresAt` as a
    /// timestamp; neither is a secret."*
    public let expiresIn: Int
    /// CC-M4. Microsoft returns `ext_expires_in` beside `expires_in`, and the
    /// reader **accepts** it rather than refusing the reply for carrying it.
    /// It is never used to lengthen a cache entry: Rule C's ceiling is a
    /// compiled constant and no provider field can move it.
    public let extendedExpiresIn: Int?
    /// The granted scope strings, or empty when the provider returns none —
    /// which is Azure's documented case.
    public let grantedScopes: Set<String>
    /// BL-117's GitHub slot (§3.3a, §5.1). The OIDC `id_token`, where the
    /// provider issues one, lifted by the same pre-parse byte scan as the access
    /// token and for the same reason.
    ///
    /// It is a `VaultSecret` although it is not, strictly, a credential: it is a
    /// signed assertion about *who authorised this*, and §3.3a is about to check
    /// a `nonce` inside it. Two things follow and both are why it is not a
    /// `String`. It is long — a Microsoft Graph JWT can exceed eight kilobytes —
    /// so §5.1's *"or any prefix or length"* prohibition needs the partial-echo
    /// scan, which takes a `VaultSecret`. And it is a bearer of identity at the
    /// provider for its lifetime, so the one place it may not end up is
    /// unzeroable storage that a receipt writer could reach.
    ///
    /// Nil for every provider that issues none — **GitHub among them**, which is
    /// exactly why §3.3a's second arm (the confirmed principal, shown to the
    /// owner before commit) exists for this slot.
    public let idToken: VaultSecret?

    public init(
        token: VaultSecret,
        tokenType: String,
        expiresIn: Int,
        extendedExpiresIn: Int?,
        grantedScopes: Set<String>,
        idToken: VaultSecret? = nil
    ) {
        self.token = token
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.extendedExpiresIn = extendedExpiresIn
        self.grantedScopes = grantedScopes
        self.idToken = idToken
    }
}

public enum TokenExchangeReader {

    /// A token reply is a handful of fields and one token. Microsoft's own
    /// example is under a kilobyte; 64 KiB is three orders of magnitude of
    /// headroom, and the transport's 512 KiB cap is the outer bound.
    public static let maximumBodyBytes = 64 * 1024
    /// The key, and the only key, whose value is lifted.
    public static let tokenKey = "access_token"
    /// BL-117's GitHub slot (§3.3a). The second key whose value is lifted, when
    /// the provider issues one. Optional in a way `access_token` is not: a reply
    /// carrying none is the documented shape for GitHub, Slack and Linear.
    public static let idTokenKey = "id_token"
    /// A scope string is a URL; anything longer is not one.
    public static let maximumScopeBytes = 512
    /// A day. `expires_in` outside this is not a lifetime any of these grants
    /// documents, and a negative or zero one is a reply that has already
    /// expired.
    public static let maximumExpiresIn = 24 * 60 * 60

    /// Reads one exchange reply.
    ///
    /// - Throws: `VaultageError.providerResultInvalid` for **every** shape it
    ///   cannot read. There is no fallback, no partial read and no default: a
    ///   reply this cannot read is a refused operation (§2.5 fail-closed (a)).
    public static func read(_ body: Data, spec: TokenExchangeSpec) throws -> ExchangedToken {
        guard !body.isEmpty, body.count <= maximumBodyBytes else { throw VaultageError.providerResultInvalid }
        var raw = Array(body)
        defer { raw.withUnsafeMutableBytes { SecretMemory.zero($0) } }

        // --- The byte lift, before any JSON parse ---
        //
        // The key is searched for in its JSON-quoted form, so a *value* that
        // happens to contain the words `access_token` cannot be mistaken for
        // the key. Exactly one occurrence anywhere in the document: a second
        // one — top-level or nested — refuses. §2.5 settles version 1's
        // contradiction this way, and the reason it can is §8.2: Slack is
        // requested with bot scopes only, so its reply is pinned in one fixture
        // without `authed_user` and a nested `access_token` anywhere is a
        // refusal.
        guard let token = try lift(tokenKey, from: &raw, alphabet: spec.alphabet, required: true) else {
            throw VaultageError.providerResultInvalid
        }

        // BL-117's GitHub slot (§3.3a). The **second** lift, by the same
        // pre-parse byte scan and with the same overwrite, for the `id_token` a
        // provider issues when the ceremony asked for `openid`.
        //
        // It is lifted rather than left in the document for the reason the
        // access token is: what follows this function is a JSON parse, and a
        // parse produces unzeroable Swift `String`s. §5.1 lists the `id_token`
        // among the things a receipt may never carry, and §3.3a is about to read
        // a `nonce` out of it — so it has to exist as a value, and the only
        // shape this product has for "a value nothing may copy" is
        // `VaultSecret`.
        //
        // The alphabet is `.jsonWebToken` and it is **not** the per-provider
        // one: an `id_token` is an OIDC JWT by definition wherever it appears,
        // which is a claim OIDC itself makes, unlike the claim about an
        // `access_token`'s format that no provider makes. A reply whose
        // `id_token` is not base64url-with-dots is not an OIDC reply.
        let idToken = try lift(idTokenKey, from: &raw, alphabet: .jsonWebToken, required: false)

        // --- Only now, the parse ---
        guard let object = try? JSONSerialization.jsonObject(with: Data(raw)) as? [String: Any] else {
            throw VaultageError.providerResultInvalid
        }
        // The one occurrence lifted above must have been the **top-level** one.
        // If it was nested, the top-level object does not carry the key and
        // this refuses — which is how "exactly one top-level `access_token`"
        // is checked rather than assumed.
        guard let redacted = object[tokenKey] as? String, redacted.allSatisfy({ $0 == "#" }), !redacted.isEmpty else {
            throw VaultageError.providerResultInvalid
        }
        // The same test for the `id_token`, when one was lifted: it too must
        // have been the **top-level** occurrence. A nested `id_token` — inside
        // an `authed_user`, say — would have been lifted by the scan above and
        // then found missing here, which is the refusal §2.5's nesting rule asks
        // for, applied to the second key.
        if idToken != nil {
            guard let redactedID = object[idTokenKey] as? String, redactedID.allSatisfy({ $0 == "#" }), !redactedID.isEmpty else {
                throw VaultageError.providerResultInvalid
            }
        }

        // `token_type`, case-insensitively against the compiled per-provider
        // value (CC-L6). The provider's own spelling is compared and discarded;
        // what the caller gets back is the compiled value.
        guard let declaredType = object["token_type"] as? String,
              declaredType.caseInsensitiveCompare(spec.tokenType) == .orderedSame else {
            throw VaultageError.providerResultInvalid
        }

        guard let expiresIn = integer(object["expires_in"]), expiresIn > 0, expiresIn <= maximumExpiresIn else {
            throw VaultageError.providerResultInvalid
        }
        // CC-M4. Accepted, not refused — and bounded like its sibling, because
        // accepting a field is not the same as trusting it. A malformed one is
        // a refusal rather than a silent nil: the reply is not the shape the
        // provider documents.
        var extended: Int?
        if let present = object["ext_expires_in"] {
            guard let value = integer(present), value > 0, value <= maximumExpiresIn else {
                throw VaultageError.providerResultInvalid
            }
            extended = value
        }

        // §2.5's scope rules, in the two that apply to a *reply*: record the
        // granted set, and refuse an unknown scope string. Azure's reply
        // carries no `scope` field at all, which is the case the third rule —
        // "surface anything granted beyond the requested set" — has nothing to
        // say about, and which version 1's superset refusal could not express.
        var granted: Set<String> = []
        if let scope = object["scope"] {
            guard let text = scope as? String, text.utf8.count <= maximumScopeBytes else {
                throw VaultageError.providerResultInvalid
            }
            granted = Set(text.split(separator: " ").map(String.init))
            for entry in granted where !spec.requestedScopes.contains(entry) {
                // Refuse only an **unknown** scope string — one this manifest
                // never asked for. A granted set that is a superset of the
                // requested one is legitimate on Google and Slack and is
                // surfaced rather than refused; this refuses a string that is
                // in neither set, which is a reply about a different grant.
                throw VaultageError.providerResultInvalid
            }
        }

        return ExchangedToken(
            token: token,
            tokenType: spec.tokenType,
            expiresIn: expiresIn,
            extendedExpiresIn: extended,
            grantedScopes: granted,
            idToken: idToken
        )
    }

    /// BL-117's GitHub slot. The byte lift, factored out so the access token and
    /// the `id_token` go through **one** implementation rather than two.
    ///
    /// Everything the access-token lift did, unchanged, and each rule is here
    /// rather than duplicated:
    ///
    ///   * the key is searched for in its **JSON-quoted** form, so a *value*
    ///     containing the words `access_token` cannot be mistaken for the key;
    ///   * **exactly one** occurrence anywhere in the document — a second one,
    ///     top-level or nested, refuses. §2.5 settles version 1's contradiction
    ///     this way, and §8.2 is why it is safe: Slack is requested with bot
    ///     scopes only, so its reply is pinned without `authed_user`;
    ///   * the value must be a **string**: `"key"` optional whitespace `:`
    ///     optional whitespace `"` … `"`. Not a number, not null, not an object;
    ///   * the alphabet and the length are checked **on the raw bytes**, before
    ///     anything copies them anywhere. A `\` is in no alphabet, so a value
    ///     carrying a JSON escape is refused here rather than unescaped — which
    ///     is what makes "scan to the next quotation mark" correct rather than
    ///     merely convenient;
    ///   * the span is then overwritten with a filler of the **same length**
    ///     inside the same quotation marks, so the parse that follows sees a
    ///     syntactically identical document with the answer removed. The filler
    ///     is a byte no alphabet admits, so a reader that somehow read the
    ///     redacted value would get something that refuses.
    ///
    /// - Parameter required: `false` for a key a documented reply may omit. An
    ///   absent optional key yields nil; a **present but malformed** one still
    ///   refuses, because accepting a field is not the same as trusting it — the
    ///   rule CC-M4 set for `ext_expires_in` one slot earlier, applied to a key
    ///   that carries a secret rather than a number.
    private static func lift(
        _ key: String,
        from raw: inout [UInt8],
        alphabet: TokenExchangeAlphabet,
        required: Bool
    ) throws -> VaultSecret? {
        let quoted = Array("\"\(key)\"".utf8)
        let occurrences = occurrences(of: quoted, in: raw)
        if occurrences.isEmpty, !required { return nil }
        guard occurrences.count == 1, let keyStart = occurrences.first else { throw VaultageError.providerResultInvalid }

        var cursor = keyStart + quoted.count
        cursor = skipWhitespace(raw, from: cursor)
        guard cursor < raw.count, raw[cursor] == UInt8(ascii: ":") else { throw VaultageError.providerResultInvalid }
        cursor = skipWhitespace(raw, from: cursor + 1)
        guard cursor < raw.count, raw[cursor] == UInt8(ascii: "\"") else { throw VaultageError.providerResultInvalid }
        let valueStart = cursor + 1
        var valueEnd = valueStart
        while valueEnd < raw.count, raw[valueEnd] != UInt8(ascii: "\"") { valueEnd += 1 }
        guard valueEnd < raw.count else { throw VaultageError.providerResultInvalid }

        var lifted: VaultSecret?
        raw.withUnsafeBytes { whole in
            let slice = UnsafeRawBufferPointer(
                start: whole.baseAddress!.advanced(by: valueStart),
                count: valueEnd - valueStart
            )
            guard alphabet.admits(slice) else { return }
            lifted = VaultSecret(bytes: slice)
        }
        guard let lifted else { throw VaultageError.providerResultInvalid }
        for index in valueStart ..< valueEnd { raw[index] = UInt8(ascii: "#") }
        return lifted
    }

    /// §2.5 fail-closed **(f)**, as a classification rather than as a comment:
    /// **an exchange whose result is *unknown* never retries the same code.**
    ///
    /// The first five fail-closed cases all cover *refusals* — the exchange
    /// definitely did not happen, so the operation is refused and that is the
    /// whole story. The sixth is different because it is **ambiguous**:
    /// `BoundedResponseReceiver` maps `timedOut`, `networkConnectionLost`,
    /// `cannotConnectToHost` and `cannotFindHost` to
    /// `VaultageError.resultUnknown`, and in that state the token endpoint may
    /// have burned a single-use code and minted a grant that now exists at the
    /// provider. So the outcome is marked unknown, the owner is told a grant
    /// may exist, and **the same request is never sent again**. The Cloudflare
    /// `resultUnknown` discipline is the precedent and
    /// `ProviderEgressContracts.ambiguousPutOutcomesUseExactlyOnePut` is the
    /// shape of the test.
    ///
    /// Client credentials has no code to burn, which is exactly why this is the
    /// slot that should compile the rule: it can be asserted where getting it
    /// wrong costs nothing, and §7.4's ceremony inherits a rule that already
    /// exists rather than writing one under pressure.
    public enum ExchangeOutcome: Sendable, Equatable {
        /// Cases (a) to (e). The exchange did not happen; refuse the operation.
        case refused
        /// Case (f). The exchange may or may not have happened. Never retried,
        /// and the owner is told a grant may exist at the provider.
        case unknown
    }

    /// Which of the two an exchange failure is.
    public static func outcome(of error: VaultageError) -> ExchangeOutcome {
        if case .resultUnknown = error { return .unknown }
        return .refused
    }

    // MARK: - Byte helpers

    /// Every start index at which `needle` occurs in `haystack`. No `String`
    /// copy of either, and the whole document is scanned rather than the first
    /// hit being taken — which is what makes "exactly one" checkable.
    public static func occurrences(of needle: [UInt8], in haystack: [UInt8]) -> [Int] {
        guard !needle.isEmpty, haystack.count >= needle.count else { return [] }
        var found: [Int] = []
        var offset = 0
        let limit = haystack.count - needle.count
        while offset <= limit {
            var matched = true
            for index in 0 ..< needle.count where haystack[offset + index] != needle[index] {
                matched = false
                break
            }
            if matched {
                found.append(offset)
                offset += needle.count
            } else {
                offset += 1
            }
        }
        return found
    }

    private static func skipWhitespace(_ raw: [UInt8], from index: Int) -> Int {
        var cursor = index
        while cursor < raw.count, raw[cursor] == 0x20 || raw[cursor] == 0x09 || raw[cursor] == 0x0A || raw[cursor] == 0x0D {
            cursor += 1
        }
        return cursor
    }

    /// An integer JSON field, accepted only as a whole number. A string, a
    /// fraction or a boolean is a reply that is not the documented shape.
    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber else { return nil }
        guard CFNumberIsFloatType(number) == false else { return nil }
        return number.intValue
    }
}
