import Foundation

/// BL-085 / D30 — the personal API token contract, on the Mac's side of the
/// wire.
///
/// The authoritative document is
/// the control plane's `docs/account-api-tokens.md`; this file is the
/// typed transcription of it, and `DeviceAccountClient` in `AccountClient.swift`
/// is the only thing that speaks it. Three properties are the reason these
/// types exist at all rather than the client returning dictionaries:
///
/// 1. **Every record here is value-free.** `APITokenRecord` carries what
///    `GET /api/tokens` carries — id, name, prefix, scopes, timestamps, status
///    — and there is no member on it, and no initialiser reachable from outside
///    this module, through which a token value could travel.
/// 2. **The one value that does exist is in a handle, not a `String`.**
///    `POST /api/tokens` returns the token once. It arrives in
///    `OneTimeTokenValue`, which holds it in a `VaultSecret` — one owned,
///    `mlock`ed, `memset_s`-zeroed allocation — and spends it exactly once.
/// 3. **The failures are the route's own.** `APITokenError` is a transcription
///    of the contract's status table, so a caller can tell "this Mac's session
///    is not accepted by this route yet" apart from "your session is bad" apart
///    from "you are at your plan's cap", and say so.

// MARK: - Scopes, expiry, status

/// The seven fixed scopes. There is no eighth, and no free-form string: a scope
/// this Mac cannot name is a scope it cannot ask for.
public enum APITokenScope: String, Codable, Sendable, CaseIterable, Comparable {
    case accountRead = "account:read"
    case devicesRead = "devices:read"
    case devicesRevoke = "devices:revoke"
    case connectionsRead = "connections:read"
    case billingRead = "billing:read"
    case requestsWrite = "requests:write"
    case tokensManage = "tokens:manage"

    /// The routes the scope grants, from the contract's table — the routes
    /// themselves, not a paraphrase, because a consent surface that understates
    /// what it grants is a consent failure.
    public var grants: String {
        switch self {
        case .accountRead: "GET /api/account, GET /api/activity, GET /api/referrals/me"
        case .devicesRead: "GET /api/devices"
        case .devicesRevoke: "POST /api/device-sessions/revoke"
        case .connectionsRead: "GET /api/account/connections"
        case .billingRead: "GET /api/entitlement, GET /api/billing/invoices"
        case .requestsWrite: "GET /api/provider-requests, POST /api/provider-requests"
        case .tokensManage: "GET /api/tokens, POST /api/tokens, DELETE /api/tokens/:id"
        }
    }

    public static func < (lhs: APITokenScope, rhs: APITokenScope) -> Bool {
        allCases.firstIndex(of: lhs)! < allCases.firstIndex(of: rhs)!
    }
}

/// `expiresInDays`: `30`, `90`, `365`, or omitted. A closed enum rather than an
/// `Int?` so an unrepresentable expiry cannot be assembled locally and refused
/// remotely.
public enum APITokenExpiry: Int, Codable, Sendable, CaseIterable {
    case days30 = 30
    case days90 = 90
    case days365 = 365
    /// The contract's omitted / `null` `expiresInDays`.
    case never = 0

    public var days: Int? { self == .never ? nil : rawValue }
}

public enum APITokenStatus: String, Codable, Sendable { case active, expired, revoked }

// MARK: - Value-free records

/// One row of `GET /api/tokens`, and the metadata half of `POST /api/tokens`.
///
/// There is no `value` here and there can never be one: the memberwise
/// initialiser is `internal`, so outside `VaultageCore` this type is read-only
/// and is only ever produced by the response decoder below, which builds it from
/// a body the token value has already been lifted out of.
public struct APITokenRecord: Sendable, Equatable {
    public let id: String
    public let name: String
    public let prefix: String
    public let scopes: [APITokenScope]
    public let createdAt: Date
    public let expiresAt: Date?
    public let lastUsedAt: Date?
    public let revokedAt: Date?
    /// `desktop` for a device session, `web` for a browser session. It names
    /// where the token came from and grants nothing.
    public let createdBy: String
    public let status: APITokenStatus
    /// BL-076 / MF-H1. **This token was created before the account enabled
    /// two-factor, so every request it makes is refused
    /// `401 token_predates_mfa`** — while `status` still reads `active`,
    /// because nothing revoked it and nothing here revokes it.
    ///
    /// It is its own field rather than a fourth status on purpose. A revoked
    /// token is gone and an expired one is over; this one is intact and one
    /// re-mint away from working, and telling the account holder to look for
    /// a revocation would send them after something that did not happen.
    public let predatesMfa: Bool
    /// AS-H2. **Which token minted this one**, or `nil` for a browser session or
    /// a linked Mac — which is every row written before migration `0013`.
    ///
    /// It is what lets a list show a lineage rather than a flat one in which "a
    /// successor minted by a leaked value is indistinguishable from one the
    /// owner made". It is also the thread `DELETE /api/tokens/:id` walks: a
    /// child's expiry is capped at its parent's, revoking a parent revokes its
    /// whole transitive closure, and a token may revoke only itself and its own
    /// descendants.
    public let parentTokenId: String?

    init(id: String, name: String, prefix: String, scopes: [APITokenScope], createdAt: Date, expiresAt: Date?, lastUsedAt: Date?, revokedAt: Date?, createdBy: String, status: APITokenStatus, predatesMfa: Bool, parentTokenId: String? = nil) {
        self.id = id; self.name = name; self.prefix = prefix; self.scopes = scopes
        self.createdAt = createdAt; self.expiresAt = expiresAt; self.lastUsedAt = lastUsedAt; self.revokedAt = revokedAt
        self.createdBy = createdBy; self.status = status; self.predatesMfa = predatesMfa
        self.parentTokenId = parentTokenId
    }
}

/// `GET /api/tokens`: the rows, plus the plan's allowance so a settings sheet
/// can disable "+ New token" with an honest reason rather than letting the call
/// fail, and the scope list the account plane itself publishes.
public struct APITokenListing: Sendable, Equatable {
    public let tokens: [APITokenRecord]
    public let cap: Int
    public let active: Int
    public let scopes: [APITokenScope]
    /// BL-076 / MF-H1. When this account enabled two-factor, or `nil` when it
    /// has none. It is the stamp every row's `predatesMfa` was computed
    /// against, and it is what lets a list say *why* a row is marked without a
    /// second request.
    public let mfaEnabledAt: Date?

    public var isAtCap: Bool { active >= cap }

    /// The rows that will be refused on their next request. **Marked before
    /// anything fails**, which is why MF-H1 put this on the list rather than
    /// only in a refusal: the difference between a credential that mysteriously
    /// stopped working and one the account holder can see and re-create.
    public var predatingTokens: [APITokenRecord] { tokens.filter(\.predatesMfa) }

    init(tokens: [APITokenRecord], cap: Int, active: Int, scopes: [APITokenScope], mfaEnabledAt: Date?) {
        self.tokens = tokens; self.cap = cap; self.active = active; self.scopes = scopes
        self.mfaEnabledAt = mfaEnabledAt
    }
}

/// One token a revoke's transitive closure also took — its id **and its
/// name**, so a settings sheet can say what went rather than leaving the
/// owner to recognise a bare id.
///
/// The name is the token row had at the moment of revocation, read by the
/// Worker in the same recursive query that walked the closure, not a second
/// lookup — moot in any case, since the row is already gone from
/// `GET /api/tokens` by the time a client could otherwise ask
/// (`docs/account-api-tokens.md`, the account-surface rows' §7 item 4, closed
/// by the contract follow-ups on 2026-09-14).
public struct RevokedTokenSummary: Sendable, Equatable, Hashable {
    public let id: String
    public let name: String

    public init(id: String, name: String) { self.id = id; self.name = name }
}

/// `DELETE /api/tokens/:id`: what the route confirms, and nothing more.
public struct RevokedAPIToken: Sendable, Equatable {
    public let id: String
    public let status: APITokenStatus
    public let revokedAt: Date
    /// AS-H2 — **the tokens this one had minted that went with it**,
    /// transitively, and usually empty.
    ///
    /// Revoking a value has to end what that value created, or a leaked
    /// `tokens:manage` token is a persistence primitive: mint a successor, wait
    /// to be revoked, carry on. The route revokes the whole closure in one batch
    /// and names the rest here so a surface "can say 'and the 2 tokens it
    /// created' instead of leaving the owner to notice an unfamiliar row".
    ///
    /// Each entry is `{ id, name }` since the contract follow-ups
    /// (2026-09-14): a bare id left the owner to recognise an unfamiliar
    /// prefix, and by the time a client could ask what an id belonged to,
    /// `GET /api/tokens` had already stopped listing it.
    public let alsoRevoked: [RevokedTokenSummary]

    init(id: String, status: APITokenStatus, revokedAt: Date, alsoRevoked: [RevokedTokenSummary] = []) {
        self.id = id; self.status = status; self.revokedAt = revokedAt; self.alsoRevoked = alsoRevoked
    }
}

// MARK: - The one-time value

/// The created token's value, held exactly the way a vault credential is held
/// and spendable exactly once.
///
/// `POST /api/tokens` is the only moment this value exists outside the control
/// plane's SHA-256 of it — it can never be shown again, re-derived or recovered
/// — and the contract's Mac-side rules are: show it once, put it on the
/// pasteboard only under the concealed 45-second copy lease, never store it,
/// zero the in-memory copy when the sheet closes.
///
/// So this is deliberately **not** a `String` property on a struct. It is an
/// actor holding one `VaultSecret`: one manually managed allocation, pinned with
/// `mlock` where the OS allows, zeroed with `memset_s` before release, not
/// `Codable`, with a redacted `description` and an empty mirror. The single
/// consumption is the same discipline `RevealHandle` applies to a revealed vault
/// value, for the same reason — a handle that can be spent twice is a handle
/// whose bytes outlive the one sheet that was allowed to see them.
public actor OneTimeTokenValue {
    /// The non-secret half of the value, which is also `APITokenRecord.prefix`.
    /// It is here so a caller can label or match the handle without touching it.
    public nonisolated let prefix: String

    private var secret: VaultSecret?

    init(secret: VaultSecret, prefix: String) { self.secret = secret; self.prefix = prefix }

    /// True until the value has been consumed or discarded. It never goes back.
    public func isLive() -> Bool { secret != nil }

    /// The narrow scoped borrow, in `VaultSecret`'s own shape: the closure
    /// returns `Void`, so the only way to move the value out of this call is a
    /// deliberate, reviewable copy the reader can see. The handle is spent
    /// whether or not the body throws — a failed pasteboard write does not earn
    /// a second look at the value.
    ///
    /// This is the call a copy lease uses:
    /// `try await issued.value.withValue { try pasteboard.writeConcealed($0) }`.
    public func withValue(_ body: (VaultSecret) throws -> Void) throws {
        guard let held = secret else { throw APITokenError.valueAlreadyConsumed }
        secret = nil
        try body(held)
    }

    /// The same single consumption, for a surface that must hold the value while
    /// a sheet is on screen and cannot do its work inside a synchronous closure.
    ///
    /// It is the deliberate copy `withValue` is shaped to force, and it hands
    /// back a `VaultSecret` rather than a `String`, so the value stays in a
    /// self-zeroing allocation for as long as the sheet holds it. The caller
    /// derives text from it through `withDisclosureText` and drops it when the
    /// sheet closes.
    public func consumedOnce() throws -> VaultSecret {
        guard let held = secret else { throw APITokenError.valueAlreadyConsumed }
        secret = nil
        return held
    }

    /// The explicit close — the sheet dismissing without a copy. Idempotent, and
    /// the only other way the handle is spent.
    public func discard() { secret = nil }
}

/// What `POST /api/tokens` returns: a value-free record, and the value in a
/// handle that can be spent once.
public struct IssuedAPIToken: Sendable {
    public let token: APITokenRecord
    public let value: OneTimeTokenValue

    init(token: APITokenRecord, value: OneTimeTokenValue) { self.token = token; self.value = value }
}

// MARK: - Failures

/// The contract's status table, transcribed.
///
/// The distinction that matters most on this Mac today is between
/// `deviceSessionNotAccepted` — the route exists, it is simply not one of the
/// routes that take an `Authorization: Device` credential yet — and
/// `sessionRejected`, which means this Mac's own session or proof was refused
/// and has been cleared. Collapsing the two would make a missing route look like
/// a broken link, and send a human to re-link a Mac that is linked.
public enum APITokenError: Error, LocalizedError, Sendable, Equatable {
    /// This Mac is not linked, or its session has expired.
    case notLinked
    /// Refused locally, before a request was sent, by the same rule the route
    /// applies. The string is the reason, for a human.
    case invalidRequest(String)
    /// `400 invalid_token_name`.
    case invalidName
    /// `400 invalid_scopes`.
    case invalidScopes
    /// `400 invalid_expiry`.
    case invalidExpiry
    /// `400 invalid_token_id`.
    case invalidTokenID
    /// `401` with a device error code. The session and the cached lease have
    /// been cleared; the Mac must link again.
    case sessionRejected
    /// The route does not accept this Mac's device session — `401` from the
    /// browser-session verifier, or `403 origin_forbidden`. Nothing is wrong
    /// with this Mac.
    case deviceSessionNotAccepted
    /// `403 insufficient_scope`.
    case insufficientScope
    /// BL-076 / MF-H1 — `401 token_predates_mfa`. The token was created before
    /// the account enabled two-factor. It is **not** revoked and **not**
    /// expired: it is intact, refused on every route, and one re-mint from
    /// working. The sentence is the control plane's own, held once in
    /// `MfaRefusalCopy` so no screen re-types it.
    case tokenPredatesMfa
    /// AS-H1 — the **same** `401 token_predates_mfa`, on `POST /api/tokens`
    /// only, and a different fact: it is the **Mac** that was linked before the
    /// account enabled two-factor, not the token that was created before it.
    ///
    /// Its own case because its remedy is its own — re-link this Mac, or mint on
    /// the web — and because "create a new one" is the exact wrong advice here:
    /// creating a new one is what just failed.
    case deviceLinkPredatesMfa
    /// AS-H2 — `403 insufficient_scope` on `POST /api/tokens` from this Mac's
    /// device session: a scope no device session may mint, whatever the
    /// account's plan or the caller's intent.
    ///
    /// Separate from `insufficientScope`, which is a credential reaching a route
    /// its scopes do not cover. This one is a *mint* that was refused, nothing
    /// was issued, and the remedy is narrower scopes or the web.
    case scopeNotMintableFromThisMac
    /// AS-H2 — `403 token_not_issued_by_caller` on `DELETE /api/tokens/:id`.
    /// The named token is live on this account and this credential did not mint
    /// it. **Not a 404**: an unknown id, another account's id and an
    /// already-revoked token all stay indistinguishable.
    case tokenNotIssuedByCaller
    /// AS-H3 — `401 account_deletion_pending`. A 72-hour closure is pending, so
    /// every credential on this account is **suspended, not revoked**, and
    /// cancelling restores each of them exactly.
    case accountDeletionPending
    /// `404 token_not_found`: an unknown id, another account's id, or one that
    /// is already revoked.
    case tokenNotFound
    /// A `404` that is not `token_not_found`: the route is not deployed here.
    case routeNotDeployed
    /// `409 token_limit_reached`. Nothing was issued.
    case limitReached
    /// `429 rate_limited`.
    case rateLimited
    /// `503`, or any other 5xx. Fail closed; nothing was issued.
    case serviceUnavailable
    case networkUnavailable
    case invalidResponse
    /// The one-time value has already been spent or discarded.
    case valueAlreadyConsumed
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .notLinked: "This Mac is not linked to an account."
        case .invalidRequest(let reason): reason
        case .invalidName: "That name was refused. A token name is 1 to 64 characters and may not itself be a credential."
        case .invalidScopes: "Those scopes were refused. Choose at least one, with no repeats."
        case .invalidExpiry: "That expiry was refused. Choose 30, 90 or 365 days, or no expiry."
        case .invalidTokenID: "That is not a token id."
        case .sessionRejected: "This device session is no longer active. Link this Mac again."
        case .deviceSessionNotAccepted: "This route does not accept this Mac's device session yet. Manage these tokens on the web."
        case .insufficientScope: "That credential does not carry the scope this route needs."
        case .tokenPredatesMfa: MfaRefusalCopy.tokenPredatesMfa
        case .deviceLinkPredatesMfa: MfaRefusalCopy.deviceLinkPredatesMfa
        case .scopeNotMintableFromThisMac: AccountRefusalCopy.scopeNotMintableFromThisMac
        case .tokenNotIssuedByCaller: AccountRefusalCopy.tokenNotIssuedByCaller
        case .accountDeletionPending: AccountRefusalCopy.accountDeletionPending
        case .tokenNotFound: "That token no longer exists, or was already revoked."
        case .routeNotDeployed: "This route is not deployed on the account service yet."
        case .limitReached: "Your plan's active-token allowance is full. Revoke one first; nothing was issued."
        case .rateLimited: "Too many requests. Try again in a minute."
        case .serviceUnavailable: "Account service is not configured or is unavailable. Nothing was issued."
        case .networkUnavailable: "Could not reach the account service."
        case .invalidResponse: "The account service returned an invalid response."
        case .valueAlreadyConsumed: "This token's value has already been shown. It cannot be shown again."
        case .cancelled: "The request was cancelled."
        }
    }
}

// MARK: - Local validation, mirroring the route

/// The Worker's own request validation, applied before the request is sent, so
/// a refusal names the same reason the route would and costs no round trip.
///
/// This is a transcription of `tokenName`, `requestedScopes` and `expiresAt` in
/// `src/tokens.ts` and of `secretLike` / `hasControlCharacters` in
/// `src/intake.ts`. It is deliberately not the last line of defence: the Worker
/// applies all of it again to whatever actually arrives.
enum APITokenRequestValidation {
    static let maximumNameLength = 64

    /// Returns the trimmed name, or throws with the human reason.
    static func name(_ value: String) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw APITokenError.invalidRequest("Give the token a name so you can recognise it later.")
        }
        guard trimmed.count <= maximumNameLength else {
            throw APITokenError.invalidRequest("A token name is at most \(maximumNameLength) characters.")
        }
        guard !hasControlCharacters(trimmed) else {
            throw APITokenError.invalidRequest("A token name cannot contain control characters.")
        }
        // A token may be *named* "API key" — that is what it is. What may never
        // land here is an actual credential.
        guard !looksLikeASecret(trimmed) else {
            throw APITokenError.invalidRequest("That looks like a credential rather than a name. Name the token after what will use it.")
        }
        return trimmed
    }

    /// Returns the scopes in the contract's own order, or throws. Order is
    /// normalised here so two equivalent requests produce one byte-identical
    /// body.
    static func scopes(_ value: [APITokenScope]) throws -> [APITokenScope] {
        guard !value.isEmpty else {
            throw APITokenError.invalidRequest("Choose at least one scope. A token with no scope can reach nothing.")
        }
        guard Set(value).count == value.count else {
            throw APITokenError.invalidRequest("A scope may only be chosen once.")
        }
        return value.sorted()
    }

    static func hasControlCharacters(_ value: String) -> Bool {
        value.unicodeScalars.contains { $0.value <= 0x1f || ($0.value >= 0x7f && $0.value <= 0x9f) }
    }

    /// `secretLike` from `src/intake.ts`: the named credential shapes, or a long
    /// high-entropy run.
    ///
    /// BL-101: the private-key pattern used to be written against the
    /// uncompacted alphabet — a literal space in `PRIVATE KEY` — so it could
    /// never match `compact`, which has already had every whitespace
    /// character removed. A bare PEM header line was accepted as a token
    /// name. Fixed alongside the Worker's `secretLike` in the same change;
    /// see `blueprint/evidence/web-lane-secretlike-fix-2026-09-12.md`.
    static func looksLikeASecret(_ value: String) -> Bool {
        let compact = value.components(separatedBy: .whitespacesAndNewlines).joined()
        let patterns = [
            "-----BEGIN(?:[A-Z]*)PRIVATEKEY-----",
            "gh[pousr]_[A-Za-z0-9_]{20,}",
            "github_pat_[A-Za-z0-9_]{20,}",
            "sk(?:-proj)?-[A-Za-z0-9_-]{16,}",
            "cf-[A-Za-z0-9_-]{20,}",
            "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
        ]
        for pattern in patterns where compact.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil {
            return true
        }
        guard let run = compact.range(of: "[A-Za-z0-9_=-]{32,}", options: .regularExpression) else { return false }
        return Set(compact[run]).count >= 12
    }

    /// `TOKEN_ID_PATTERN` from `src/tokens.ts`. Checked here because the id goes
    /// into a URL path and into a DPoP proof's `htu`.
    static func tokenID(_ value: String) throws -> String {
        guard value.utf8.count == 8,
              value.range(of: "^[A-Za-z0-9_-]{8}$", options: .regularExpression) != nil
        else { throw APITokenError.invalidTokenID }
        return value
    }
}

// MARK: - Response decoding

/// Turns a token response body into value-free records.
///
/// Everything in here runs on a body the value has already been lifted out of
/// (`APITokenValueExtraction`), so `JSONSerialization` — which produces Swift
/// `String`s that cannot be zeroed — never sees a token value.
enum APITokenResponseDecoding {
    static func record(_ object: [String: Any]) throws -> APITokenRecord {
        guard let id = object["id"] as? String, (try? APITokenRequestValidation.tokenID(id)) != nil,
              let name = object["name"] as? String, name.utf8.count <= 256,
              let prefix = object["prefix"] as? String, prefix == "vlt_\(id)",
              let rawScopes = object["scopes"] as? [Any],
              let createdBy = object["createdBy"] as? String, createdBy == "desktop" || createdBy == "web",
              let rawStatus = object["status"] as? String, let status = APITokenStatus(rawValue: rawStatus),
              let createdAt = milliseconds(object["createdAt"])
        else { throw APITokenError.invalidResponse }
        // An unknown scope is refused rather than dropped: a row that renders
        // fewer scopes than the token actually carries understates it.
        var scopes: [APITokenScope] = []
        for entry in rawScopes {
            guard let raw = entry as? String, let scope = APITokenScope(rawValue: raw), !scopes.contains(scope) else {
                throw APITokenError.invalidResponse
            }
            scopes.append(scope)
        }
        guard !scopes.isEmpty else { throw APITokenError.invalidResponse }
        let expiresAt = try optionalMilliseconds(object["expiresAt"])
        let lastUsedAt = try optionalMilliseconds(object["lastUsedAt"])
        let revokedAt = try optionalMilliseconds(object["revokedAt"])
        // BL-076 / MF-H1. Absent on a Worker that predates the flag, which is
        // "no account on this deployment has two-factor" and therefore false —
        // not a refusal. A present value must be a real boolean.
        let predates: Bool
        switch object["predatesMfa"] {
        case nil, is NSNull: predates = false
        case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID(): predates = number.boolValue
        default: throw APITokenError.invalidResponse
        }
        // AS-H2. Absent on a Worker that predates migration `0013`, and null on
        // every row a browser session or a linked Mac minted — both of which
        // are "no parent" and neither of which is a refusal. A **present**
        // value must be a real token id, because the row renders it as one.
        let parent: String?
        switch object["parentTokenId"] {
        case nil, is NSNull: parent = nil
        case let raw as String:
            guard (try? APITokenRequestValidation.tokenID(raw)) != nil, raw != id else { throw APITokenError.invalidResponse }
            parent = raw
        default: throw APITokenError.invalidResponse
        }
        return APITokenRecord(id: id, name: name, prefix: prefix, scopes: scopes.sorted(), createdAt: createdAt, expiresAt: expiresAt, lastUsedAt: lastUsedAt, revokedAt: revokedAt, createdBy: createdBy, status: status, predatesMfa: predates, parentTokenId: parent)
    }

    static func listing(_ body: Data) throws -> APITokenListing {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let rows = root["tokens"] as? [Any],
              let plan = root["plan"] as? [String: Any],
              let cap = integer(plan["cap"]), cap >= 0, cap <= 1000,
              let active = integer(plan["active"]), active >= 0, active <= 1000,
              rows.count <= 100
        else { throw APITokenError.invalidResponse }
        var tokens: [APITokenRecord] = []
        for row in rows {
            guard let object = row as? [String: Any] else { throw APITokenError.invalidResponse }
            tokens.append(try record(object))
        }
        var scopes: [APITokenScope] = []
        for entry in (root["scopes"] as? [Any]) ?? [] {
            guard let raw = entry as? String, let scope = APITokenScope(rawValue: raw) else { throw APITokenError.invalidResponse }
            if !scopes.contains(scope) { scopes.append(scope) }
        }
        return APITokenListing(tokens: tokens, cap: cap, active: active, scopes: scopes.sorted(), mfaEnabledAt: try optionalMilliseconds(root["mfaEnabledAt"]))
    }

    static func revocation(_ body: Data, expecting id: String) throws -> RevokedAPIToken {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let object = root["token"] as? [String: Any],
              object["id"] as? String == id,
              let rawStatus = object["status"] as? String, let status = APITokenStatus(rawValue: rawStatus), status == .revoked,
              let revokedAt = milliseconds(object["revokedAt"])
        else { throw APITokenError.invalidResponse }
        // AS-H2. Absent on a Worker that predates the lineage column, which is
        // "nothing else went" and not a refusal. Since the contract follow-ups
        // (2026-09-14) a present entry is `{ id, name }`, not a bare id: the
        // route now reads the name in the same recursive query that walked the
        // closure, and a body still carrying only ids is a Worker this build
        // predates and fails closed rather than rendering a summary with
        // nothing to call the token. No entry may restate the head, which
        // would overstate what the call took, and no id may repeat.
        var alsoRevoked: [RevokedTokenSummary] = []
        switch root["alsoRevoked"] {
        case nil, is NSNull: break
        case let rows as [Any]:
            guard rows.count <= 100 else { throw APITokenError.invalidResponse }
            for row in rows {
                guard let entry = row as? [String: Any],
                      let rawId = entry["id"] as? String, (try? APITokenRequestValidation.tokenID(rawId)) != nil,
                      rawId != id, !alsoRevoked.contains(where: { $0.id == rawId }),
                      let name = entry["name"] as? String, !name.isEmpty, name.utf8.count <= 256,
                      !APITokenRequestValidation.hasControlCharacters(name)
                else { throw APITokenError.invalidResponse }
                alsoRevoked.append(RevokedTokenSummary(id: rawId, name: name))
            }
        default: throw APITokenError.invalidResponse
        }
        return RevokedAPIToken(id: id, status: status, revokedAt: revokedAt, alsoRevoked: alsoRevoked)
    }

    /// Epoch **milliseconds**, as every timestamp in this contract is.
    static func milliseconds(_ value: Any?) -> Date? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let value = number.doubleValue
        guard value > 0, value < 4_102_444_800_000 else { return nil }
        return Date(timeIntervalSince1970: value / 1000)
    }

    static func optionalMilliseconds(_ value: Any?) throws -> Date? {
        if value == nil || value is NSNull { return nil }
        guard let date = milliseconds(value) else { throw APITokenError.invalidResponse }
        return date
    }

    static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        return number.intValue
    }
}

// MARK: - Lifting the value out of the body before anything parses it

/// The byte-level `"value":"…"` scanner for `POST /api/tokens`.
///
/// It exists for one reason: `JSONSerialization` would materialise the token
/// value as a Swift `String`, and Swift `String` storage has no zeroing API, so
/// parsing the 201 the ordinary way would leave an unzeroable plaintext copy of
/// a live credential in freed heap memory on every issue. So the value is lifted
/// out byte by byte into a `VaultSecret` first, the span it occupied is
/// overwritten in place with `x`, and only the redacted document is handed to
/// the parser.
///
/// It accepts only the exact documented shape — `vlt_` + an 8-character id + `_`
/// + 43 base64url characters, with no backslash escape anywhere in it — so it
/// never needs an escape decoder, which is the part of a hand-written scanner
/// that goes wrong. Two `"value"` keys, or a value of any other shape, refuse
/// the whole response rather than guessing.
///
/// The same technique, for the same reason, is `CloudflareResourceCreation`'s
/// `extractTokenValue` in `VaultageProviders` (BL-074). The two are deliberately
/// separate: they accept different alphabets, and `VaultageProviders` cannot be
/// imported from here. Hoisting one shared scanner into this module is a
/// follow-up, and is noted in the evidence.
///
/// Residual, unchanged from BL-074: the `Data` the transport hands back still
/// contains the value in a buffer Vaultage does not own and cannot zero. See
/// IMPLEMENTATION.md, "Secret material in memory".
enum APITokenValueExtraction {
    struct Extracted {
        let secret: VaultSecret
        /// The id half of the value, which is not secret: it is also the
        /// record's `id` and the non-secret half of its `prefix`.
        let id: String
        /// The same document with the value's bytes replaced by `x`, so it is
        /// still well-formed JSON and the parser never sees the real bytes.
        let redactedBody: Data
    }

    /// `vlt_` (4) + id (8) + `_` (1) + secret (43).
    static let valueByteCount = 56

    static func extract(from body: Data) -> Extracted? {
        let needle = Array("\"value\"".utf8)
        var bytes = [UInt8](body)
        guard bytes.count > needle.count else { return nil }
        var found: Int?
        var index = 0
        while index <= bytes.count - needle.count {
            if Array(bytes[index ..< index + needle.count]) == needle {
                // More than one `value` key: this is not the reviewed shape.
                guard found == nil else { return nil }
                found = index
            }
            index += 1
        }
        guard var cursor = found.map({ $0 + needle.count }) else { return nil }
        while cursor < bytes.count, isSpace(bytes[cursor]) { cursor += 1 }
        guard cursor < bytes.count, bytes[cursor] == 0x3A else { return nil }        // ':'
        cursor += 1
        while cursor < bytes.count, isSpace(bytes[cursor]) { cursor += 1 }
        guard cursor < bytes.count, bytes[cursor] == 0x22 else { return nil }        // '"'
        let start = cursor + 1
        var end = start
        while end < bytes.count, bytes[end] != 0x22 {
            guard isBase64URLOrUnderscore(bytes[end]) else { return nil }
            end += 1
        }
        guard end < bytes.count, end - start == valueByteCount else { return nil }

        // The shape, checked on the bytes rather than on a `String`.
        let prefixBytes = Array("vlt_".utf8)
        guard Array(bytes[start ..< start + 4]) == prefixBytes, bytes[start + 12] == 0x5F else { return nil }
        let idBytes = Array(bytes[start + 4 ..< start + 12])
        guard let id = String(bytes: idBytes, encoding: .utf8), id.utf8.count == 8 else { return nil }

        let secret = bytes.withUnsafeBytes { raw -> VaultSecret in
            VaultSecret(bytes: UnsafeRawBufferPointer(start: raw.baseAddress!.advanced(by: start), count: valueByteCount))
        }
        // The array is this function's own allocation, so overwriting the span
        // both redacts the document and clears the only copy of the value that
        // is not inside the `VaultSecret`.
        for position in start ..< end { bytes[position] = 0x78 }
        return Extracted(secret: secret, id: id, redactedBody: Data(bytes))
    }

    private static func isSpace(_ byte: UInt8) -> Bool { byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D }
    private static func isBase64URLOrUnderscore(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x30 && byte <= 0x39) || byte == 0x5F || byte == 0x2D
    }
}
