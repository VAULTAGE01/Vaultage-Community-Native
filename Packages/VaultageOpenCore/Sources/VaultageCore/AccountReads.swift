import Foundation

/// The nine account reads a linked Mac may perform, as **value-free record
/// types**.
///
/// ## Why this file exists
///
/// `blueprint/evidence/ui-lane-settings-live-rows-2026-09-12.md` §3 is the
/// finding: the Worker opened nine routes to a device session and
/// `DeviceAccountClient` vended methods for three of them, so six sections of
/// the desktop settings modal had to render "manage it on the web" about
/// something the Mac was entitled to ask for. The obvious fix — an extension in
/// a new file — **does not compile**: `authenticatedRequest`, `requireSession`,
/// `dpop`, `endpoint`, `store`, `transport`, `origin` and `now` are `private`
/// members of an actor, and a `private` member is reachable only from the
/// enclosing declaration and from extensions **in the same file**. The evidence
/// note wrote the extension, compiled it, quoted the two errors and removed it.
///
/// So the methods live in `AccountClient.swift`, beside the key they sign with,
/// and **this file holds only the types**. The signing stays inside the type
/// that holds the key: nothing here can reach a credential, and the one
/// alternative — a parallel path that reads the device private key and the
/// session token out of the Keychain by their raw account names and
/// re-implements DPoP — was refused for the same reason BL-086 refused to put
/// the device key in the app target.
///
/// ## What these records may carry
///
/// Display facts, and nothing else. No token, no key, no session, no email
/// belonging to anyone but the account holder, and no identity of a referred
/// person — `GET /api/referrals/me` is counts only, because who took up a
/// referral is the referred person's business. Every string is bounded and
/// every unknown key is a refusal rather than an ignore, so a Worker that
/// starts sending a new field fails loudly instead of quietly rendering
/// something nobody reviewed.
///
/// ## Timestamps
///
/// The Worker's two units are both present and the difference is real, so each
/// field below says which it is and where that was established:
/// `Date.now()` writes **milliseconds** (`billing.ts:291` for `app_users`,
/// `device.ts` for devices, `connections.ts`' own `EARLIEST_VERIFIED_AT`
/// sentinel), while Stripe's `created` and `current_period_end` are **seconds**
/// (`billing.ts:311` compares `paid_through` against
/// `Math.floor(Date.now() / 1000)`). Decoding one as the other silently puts a
/// date in 1970 or in the year 56,000, which is exactly the kind of thing a
/// screenshot review does not catch.

// MARK: - Errors

/// The failure table for the nine reads.
///
/// Deliberately its own enum rather than `APITokenError`: these routes have a
/// different `400`/`404`/`409` vocabulary and borrowing a token error to
/// describe an invoice list would be a lie in a type. **The two cases that
/// matter to a screen carry exactly the same meaning and the same names**, so a
/// caller's 401-versus-403 mapping is the same mapping.
public enum AccountReadError: Error, LocalizedError, Sendable, Equatable {
    /// This Mac is not linked, or its session has expired.
    case notLinked
    /// `401` with a device error code. The session and the cached lease have
    /// **already been cleared**; the Mac must link again.
    case sessionRejected
    /// The route does not accept this Mac's device session — `401` from the
    /// browser-session verifier, or `403 origin_forbidden`. **Nothing is wrong
    /// with this Mac and it is still linked.**
    case deviceSessionNotAccepted
    /// `403 insufficient_scope`.
    case insufficientScope
    /// BL-076 / MF-H1 — `401 token_predates_mfa`. **A personal API token
    /// created before the account enabled two-factor**, refused on every route
    /// it presents itself to.
    ///
    /// It is here as well as on `APITokenError` because it is a refusal of a
    /// *credential*, not of a route, and the Mac must never render it as a
    /// generic authentication failure or as a revocation. The remedy is
    /// specific and cheap — re-create the token — and the sentence says so.
    ///
    /// **Nothing about the Mac's device session produces this.** A device
    /// session is not an API token: all ten allowlisted account routes answer
    /// exactly as they did however old the link is (`docs/mfa.md`, "What is
    /// *not* a new refusal"). This case exists so that if a build ever puts a
    /// token behind one of these reads, the refusal is explicable rather than
    /// mysterious.
    case tokenPredatesMfa
    /// AS-H3 — `401 account_deletion_pending`. **A 72-hour closure is pending
    /// on this account, so every credential it has is suspended.**
    ///
    /// Its own case for the reason the Worker gave it its own code: it is the
    /// one refusal on these routes that **undoes itself**. A client told
    /// `token_revoked` would go and re-mint a credential it never lost; this one
    /// is restored exactly — same value, same scopes, same expiry — by
    /// cancelling the request, because nothing about any credential is written
    /// while it is pending.
    ///
    /// It is separated **before** the device codes for the same reason
    /// `tokenPredatesMfa` is: it is a refusal about the *account's state*, never
    /// about this Mac's session or its proof, and it must never sign a linked
    /// Mac out. `GET /api/account/deletion-request` is exempt from the
    /// suspension, so the one read that can explain this still answers.
    case accountDeletionPending
    /// `404`: the route is not deployed on this Worker version.
    case routeNotDeployed
    /// `429 rate_limited`.
    case rateLimited
    /// `503`, or any other 5xx. Fail closed.
    case serviceUnavailable
    case networkUnavailable
    case invalidResponse
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .notLinked: "This Mac is not linked to an account."
        case .sessionRejected: "This Mac was signed out. Link it again under Security."
        case .deviceSessionNotAccepted: "That route does not accept this Mac's session. Nothing is wrong with this Mac and it is still linked."
        case .insufficientScope: "This Mac's session is not allowed to read that."
        case .tokenPredatesMfa: MfaRefusalCopy.tokenPredatesMfa
        case .accountDeletionPending: AccountRefusalCopy.accountDeletionPending
        case .routeNotDeployed: "This account service does not offer that yet."
        case .rateLimited: "Too many requests. Try again shortly."
        case .serviceUnavailable: "The account service is unavailable."
        case .networkUnavailable: "Could not reach the account service."
        case .invalidResponse: "The account service returned an invalid response."
        case .cancelled: "Cancelled."
        }
    }

    /// The one distinction a settings screen has to keep: an **absence** is not
    /// a **refusal**, and a refusal of the route is not a sign-out.
    public var isRouteRefusal: Bool { self == .deviceSessionNotAccepted || self == .insufficientScope }
}

// MARK: - GET /api/account

public struct AccountProfile: Codable, Hashable, Sendable {
    public let id: String
    /// The account holder's own address. Optional because the Worker's
    /// `auth.email` can be absent for a token-authenticated call.
    public let email: String?
    public let plan: String
    /// `nil` on a paid plan, which is how "no cap" is spelled everywhere in this
    /// product.
    public let maxProviderConnections: Int?
    /// `app_users.created_at`, **milliseconds** (`billing.ts:291`).
    public let createdAt: Date

    public init(id: String, email: String?, plan: String, maxProviderConnections: Int?, createdAt: Date) {
        self.id = id
        self.email = email
        self.plan = plan
        self.maxProviderConnections = maxProviderConnections
        self.createdAt = createdAt
    }
}

// MARK: - GET /api/entitlement

/// **Distinct from `GET /api/device-entitlement`.** That one returns a *signed
/// lease* this Mac verifies offline and treats as authority; this one is the
/// account's own view of its plan, for display. `refreshEntitlement()` calls the
/// first; this type is never an authorization input, and the Free allowance
/// still comes from the verified lease.
public struct AccountEntitlementSummary: Codable, Hashable, Sendable {
    public let plan: String
    public let maxProviderConnections: Int?
    /// Stripe's `current_period_end`, **seconds** (`billing.ts:311`).
    public let paidThrough: Date?
    /// `entitlements.updated_at`, **milliseconds** (`billing.ts:300`).
    public let updatedAt: Date?

    public init(plan: String, maxProviderConnections: Int?, paidThrough: Date?, updatedAt: Date?) {
        self.plan = plan
        self.maxProviderConnections = maxProviderConnections
        self.paidThrough = paidThrough
        self.updatedAt = updatedAt
    }
}

// MARK: - GET /api/billing/invoices

public struct AccountInvoice: Codable, Hashable, Sendable {
    public let id: String
    /// Stripe's `created`, **seconds**.
    public let created: Date
    public let description: String
    /// The smallest currency unit, as Stripe reports it. Never formatted here:
    /// a currency is a locale decision and this is a record.
    public let amountPaid: Int
    public let currency: String
    public let status: String

    public init(id: String, created: Date, description: String, amountPaid: Int, currency: String, status: String) {
        self.id = id
        self.created = created
        self.description = description
        self.amountPaid = amountPaid
        self.currency = currency
        self.status = status
    }
}

/// `available == false` means billing is not configured, or Stripe could not be
/// reached. It is **not** "no invoices": an account with no invoices is
/// `available == true` and an empty list, and collapsing the two would tell a
/// paying customer they had never been charged.
public struct AccountInvoiceListing: Codable, Hashable, Sendable {
    public let invoices: [AccountInvoice]
    public let available: Bool

    public init(invoices: [AccountInvoice], available: Bool) {
        self.invoices = invoices
        self.available = available
    }
}

// MARK: - GET /api/devices

public struct AccountDevice: Codable, Hashable, Sendable {
    public let id: String
    public let name: String
    /// `hash(jwk).slice(0,16)` — the sixteen characters the browser showed at
    /// approval time, not an RFC 7638 thumbprint.
    public let fingerprint: String
    public let status: String
    /// `devices.created_at`, **milliseconds**.
    public let createdAt: Date
    public let revokedAt: Date?

    public init(id: String, name: String, fingerprint: String, status: String, createdAt: Date, revokedAt: Date?) {
        self.id = id
        self.name = name
        self.fingerprint = fingerprint
        self.status = status
        self.createdAt = createdAt
        self.revokedAt = revokedAt
    }

    public var isActive: Bool { status == "active" && revokedAt == nil }
}

public struct AccountDeviceListing: Codable, Hashable, Sendable {
    public let devices: [AccountDevice]
    /// The Worker's opaque page cursor, passed back verbatim and never parsed.
    public let nextCursor: String?

    public init(devices: [AccountDevice], nextCursor: String?) {
        self.devices = devices
        self.nextCursor = nextCursor
    }
}

// MARK: - GET /api/account/connections

public struct AccountConnection: Codable, Hashable, Sendable {
    public let provider: String
    public let label: String?
    public let principalHint: String?
    /// **Milliseconds** (`connections.ts`' `EARLIEST_VERIFIED_AT` is
    /// `946_684_800_000`).
    public let verifiedAt: Date?
    public let paused: Bool
    public let updatedAt: Date?

    public init(provider: String, label: String?, principalHint: String?, verifiedAt: Date?, paused: Bool, updatedAt: Date?) {
        self.provider = provider
        self.label = label
        self.principalHint = principalHint
        self.verifiedAt = verifiedAt
        self.paused = paused
        self.updatedAt = updatedAt
    }
}

public struct AccountConnectionDevice: Codable, Hashable, Sendable {
    public let deviceId: String
    public let deviceName: String
    public let connections: [AccountConnection]

    public init(deviceId: String, deviceName: String, connections: [AccountConnection]) {
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.connections = connections
    }
}

public struct AccountConnectionListing: Codable, Hashable, Sendable {
    public let devices: [AccountConnectionDevice]
    public let total: Int

    public init(devices: [AccountConnectionDevice], total: Int) {
        self.devices = devices
        self.total = total
    }
}

// MARK: - GET /api/referrals/me

/// **Counts only, never the referred accounts.** A list of the addresses a user
/// recruited is exactly the kind of by-product this product does not build, and
/// this type has nowhere to put one.
public struct AccountReferralSummary: Codable, Hashable, Sendable {
    public let code: String
    public let link: String
    public let attributed: Int
    public let converted: Int
    public let capped: Int
    public let credited: Int
    public let total: Int
    public let creditsEnabled: Bool
    public let monthlyCap: Int
    public let creditCents: Int

    public init(code: String, link: String, attributed: Int, converted: Int, capped: Int, credited: Int, total: Int, creditsEnabled: Bool, monthlyCap: Int, creditCents: Int) {
        self.code = code
        self.link = link
        self.attributed = attributed
        self.converted = converted
        self.capped = capped
        self.credited = credited
        self.total = total
        self.creditsEnabled = creditsEnabled
        self.monthlyCap = monthlyCap
        self.creditCents = creditCents
    }
}

// MARK: - GET /api/activity

public struct AccountActivityEvent: Codable, Hashable, Sendable {
    public let type: String
    /// **Milliseconds** for every producer the Worker composes this list from —
    /// devices, tokens, provider requests and subscriptions all stamp
    /// `Date.now()`.
    public let at: Date
    /// The one free-text field, and it is the account holder's own: a device
    /// name, a token name, a provider name or a subscription status. **Never a
    /// credential, never a hash, and not even a token prefix**, and referral
    /// events carry none at all.
    public let detail: String?

    public init(type: String, at: Date, detail: String?) {
        self.type = type
        self.at = at
        self.detail = detail
    }
}

// MARK: - GET /api/mfa/status

/// BL-076 / D43 — what the Mac's Security section may say about two-factor.
///
/// The contract is the control plane's `docs/mfa.md`, section "For the UI
/// lane: what the Mac's Security section must show". The route is on the
/// device-session allowlist (`DEVICE_ACCOUNT_ROUTES` in `src/device.ts`) under
/// `account:read`, on the same footing as the other nine account routes.
///
/// ## What this type deliberately cannot hold
///
/// The payload carries `stepUp` and `lockedUntil`, and both are **always null
/// over a device session** — they are facts about a *browser* session's
/// step-up, keyed on the Clerk `sid`, and a Mac has no Clerk session. The
/// contract says plainly: do not render a step-up state on the Mac. So this
/// type has nowhere to put one. The decoder reads neither field, and a future
/// edit cannot quietly start rendering a step-up the Mac cannot have, for the
/// same reason `AccountReferralSummary` has nowhere to put a referred person.
///
/// `accountLockedUntil` **is** an account fact and is populated, so it is here.
///
/// ## `ready` is not `enabled`
///
/// `ready == false` means this deployment cannot hold a factor at all — the
/// Worker has no `MFA_SECRET_KEY`. Saying "off" there would tell the account
/// holder their account has no second factor when the truth is that the service
/// cannot give them one. They are two different sentences and this is two
/// fields.
public struct AccountMfaStatus: Codable, Hashable, Sendable {
    /// The deployment can hold a factor (`mfa.ready`). False is **not** "off".
    public let ready: Bool
    public let enabled: Bool
    /// A secret was minted and never confirmed. Not enabled; not nothing.
    public let pendingEnrolment: Bool
    /// `mfa_totp.enabled_at`, **milliseconds**. Also the stamp a token or a
    /// device link is compared against (MF-H1).
    public let enabledAt: Date?
    /// How many backup codes are left — **`nil` means withheld or off, never
    /// zero**.
    ///
    /// AS-L2: `GET /api/mfa/status` answers `null` here for a *delegated*
    /// credential — an API token and **a device session** — whenever a factor
    /// exists to have codes for. MF-L1's reasoning applied to the Mac: "two
    /// codes left" is a different proposition from "ten" to anybody holding a
    /// stolen credential, and the count is the one field the Mac's Security
    /// card can do without. `enabled`, `enabledAt` and the receipts, which are
    /// what that card is actually built from, are unchanged.
    ///
    /// So on a real deployment with two-factor **on**, this is always `nil` over
    /// this Mac's device session. Since the contract follow-ups (2026-09-14),
    /// `0` is no longer a value the route ever sends for a **disabled** factor
    /// either — `backupCodesRemaining` is `null`, on every credential, whenever
    /// `enabled` is `false`, full stop. `0` therefore means exactly one thing —
    /// a live factor with its codes genuinely spent — so the card's "run out"
    /// state is read from this value alone, with nothing left to derive from
    /// `enabled`.
    public let backupCodesRemaining: Int?
    /// An **account** fact, unlike `lockedUntil`, which is a session fact and
    /// is always null here.
    public let accountLockedUntil: Date?
    /// MF-H3 — the last twenty receipts, an event name and a time each.
    public let recentEvents: [AccountMfaEvent]

    public init(ready: Bool, enabled: Bool, pendingEnrolment: Bool, enabledAt: Date?, backupCodesRemaining: Int?, accountLockedUntil: Date?, recentEvents: [AccountMfaEvent]) {
        self.ready = ready
        self.enabled = enabled
        self.pendingEnrolment = pendingEnrolment
        self.enabledAt = enabledAt
        self.backupCodesRemaining = backupCodesRemaining
        self.accountLockedUntil = accountLockedUntil
        self.recentEvents = recentEvents
    }
}

/// One two-factor receipt (MF-H3): an event name and a time, and **nothing
/// else**.
///
/// Deliberately not `AccountActivityEvent`, which carries a `detail`. The
/// Worker sets `detail` to null on every one of these on purpose — "the event
/// name and its time are the whole of what a receipt says here, and anything
/// else would be a fact about a code" (`src/mfa.ts`) — and a type with a field
/// for it is a place for a later edit to put one.
public struct AccountMfaEvent: Codable, Hashable, Sendable {
    /// `mfa_enabled`, `mfa_disabled`, `mfa_backup_code_used`,
    /// `mfa_backup_codes_regenerated`, `mfa_locked_out`. An unknown name is
    /// kept as itself rather than dropped: this is the account's own record.
    public let type: String
    /// `mfa_receipts.created_at`, **milliseconds**.
    public let at: Date

    public init(type: String, at: Date) {
        self.type = type
        self.at = at
    }
}

/// The two sentences the control plane's own docs write for the Mac, kept as
/// constants so a screen quotes them rather than paraphrasing them.
public enum MfaRefusalCopy {
    /// MF-H1, `docs/mfa.md`: the desktop settings sheet "should render that
    /// code as 'this token was created before two-factor was enabled — create a
    /// new one', not as a generic authentication failure or a revocation".
    public static let tokenPredatesMfa = "This token was created before two-factor was enabled — create a new one."

    /// AS-H1, the **same code on `POST /api/tokens` from a device session** and
    /// a different sentence, because it is a different fact and a different
    /// remedy. `docs/account-api-tokens.md`'s failure table writes both: the one
    /// above is about the token presented, this one is about "the *device
    /// session minting* it" — "this Mac was linked before two-factor — re-link
    /// it, or create the token on the web".
    ///
    /// A Mac linked before the stamp is never re-attested, because a device
    /// session refreshes into a fresh thirty days for as long as it is used, so
    /// it could otherwise mint a successor stamped *after* the moment two-factor
    /// was turned on and buy the refusal above back for one request. Reading is
    /// untouched: every allowlisted account route answers such a Mac exactly as
    /// before, which is D43's call and the independent pass's.
    public static let deviceLinkPredatesMfa = "This Mac was linked before two-factor was enabled, so it cannot create a token. Re-link this Mac, or create the token on the web. Nothing was issued, and everything else this Mac reads is unaffected."
}

/// The sentences AS-H2 and AS-H3 added, held once for the same reason
/// `MfaRefusalCopy` is: a screen quotes the control plane rather than
/// paraphrasing it, and a self-test asserts the quotation **by identity** so a
/// re-typed literal that matches today cannot drift tomorrow.
public enum AccountRefusalCopy {
    /// AS-H3 — `401 account_deletion_pending`, on every device session and every
    /// API token, on every route but `GET /api/account/deletion-request`.
    ///
    /// `docs/account-api-tokens.md`: "It is a **suspension**, not a revocation:
    /// cancelling the request restores this exact token, with the same value,
    /// scopes and expiry. A client should say so rather than tell the owner to
    /// create a new one." The same is true of this Mac's own device session,
    /// which is why one sentence serves both surfaces.
    public static let accountDeletionPending = "This account has a pending deletion request, so every credential on it is suspended until the request is cancelled or the account closes. Nothing has been revoked: cancelling in the web dashboard, behind a two-factor check, restores this Mac and every API token exactly as they were."

    /// AS-H2 — `403 token_not_issued_by_caller` on `DELETE /api/tokens/:id`.
    ///
    /// "A token may revoke only itself and what it minted." It is not a 404: the
    /// token named is live on this account, and the caller simply did not mint
    /// it. A browser session and a linked Mac are the account holder and are
    /// unbounded within the account, so this cannot be reached by this Mac's own
    /// device session — it exists so a build that ever revokes through a token
    /// produces an explicable refusal rather than a mysterious one.
    public static let tokenNotIssuedByCaller = "That token is live on this account and this credential did not create it, so it cannot revoke it. A credential may revoke only itself and the tokens it minted. Revoke it from this Mac or from the web dashboard instead."

    /// AS-H2 — `403 insufficient_scope` on `POST /api/tokens` from a device
    /// session, which is a different refusal from a token asking for more than
    /// it holds.
    ///
    /// A device session mints only the scopes whose routes it may itself reach
    /// (`account:read`, `devices:read`, `connections:read`, `billing:read` and
    /// `tokens:manage`). `devices:revoke` and `requests:write` are not among
    /// them, because "one Mac must not revoke another" cost one request to step
    /// around while they were.
    public static let scopeNotMintableFromThisMac = "This Mac cannot create a token carrying that scope. A Mac mints only the scopes it may itself use, so revoking another Mac and sending provider requests are web-only. Nothing was issued; choose narrower scopes, or create this token on the web."
}

// MARK: - GET /api/account/deletion-request

/// A pending account deletion, as the status route reports it
/// (`src/account.ts`'s `readDeletionRequest`).
///
/// **Six fields, and `GET` and `POST` answer the same six.** The UI lane's
/// second contract gap was that they did not: `POST` answered `status` and
/// `credentialsRevoked`, the `GET` answered `receiptId`, `requestedAt` and
/// `completesAt`, and a client that read the clock could not read the state. The
/// Worker's `PendingDeletion` is now one interface both verbs return, read back
/// from the row rather than assembled twice, so this record is the whole of it.
/// `completesNoLaterThan` joined the other five on 2026-09-14 (the contract
/// follow-ups §3), so both verbs still answer one shape.
///
/// **`credentialsSuspended` is a suspension, not a revocation** (AS-H3). While
/// this row exists, every device session and every API token on the account is
/// refused `401 account_deletion_pending`; when it does not, none of them is.
/// Cancelling deletes the row and every credential is live again **with the same
/// value, the same scopes and the same expiry**, because nothing about any of
/// them was ever written. That is the difference the Mac's card has to carry:
/// before AS-H3 the request really did revoke, monotonically, and the cancel
/// restored nothing.
public struct AccountDeletionRequest: Codable, Hashable, Sendable {
    /// `"pending"` — the only status this route sends today. It is decoded as
    /// itself rather than matched against a literal, so a Worker that grows a
    /// second status renders it instead of failing the whole card.
    public let status: String
    public let receiptId: String
    /// **Milliseconds.**
    public let requestedAt: Date
    /// The **earliest** moment the deletion completes — 72 hours after the
    /// request, and the cron runs every six hours, so the account closes on the
    /// first tick at or after it. **Milliseconds.**
    public let completesAt: Date
    /// The **latest** tick that could pick the request up —
    /// `completesAt + DELETION_SWEEP_INTERVAL_MS`, the sweep's own six-hour
    /// period, read by the Worker from its own cron schedule rather
    /// than assumed by this client. `completesAt` is the honest floor and this
    /// is the honest ceiling, so the card can state a window instead of only a
    /// floor (the UI lane's account-surface rows, §7 item 3, closed by the
    /// contract follow-ups on 2026-09-14). **Milliseconds.**
    public let completesNoLaterThan: Date
    /// AS-H3. True while the row exists: every device session and every API
    /// token on this account is suspended, and cancelling restores each of them
    /// exactly.
    public let credentialsSuspended: Bool

    public init(status: String, receiptId: String, requestedAt: Date, completesAt: Date, completesNoLaterThan: Date, credentialsSuspended: Bool) {
        self.status = status
        self.receiptId = receiptId
        self.requestedAt = requestedAt
        self.completesAt = completesAt
        self.completesNoLaterThan = completesNoLaterThan
        self.credentialsSuspended = credentialsSuspended
    }
}

// MARK: - Decoding

/// The nine decoders, in the shape `APITokenResponseDecoding` already has:
/// strict about what it accepts, bounded about how much, and refusing rather
/// than dropping. A row that renders less than the route sent understates the
/// account to the person who owns it.
enum AccountReadDecoding {
    static let maximumStringBytes = 512
    static let maximumRows = 200
    /// `MFA_STATUS_EVENT_LIMIT` in `src/mfa.ts`.
    static let maximumMfaEvents = 20

    static func profile(_ body: Data) throws -> AccountProfile {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let object = root["account"] as? [String: Any],
              let id = try? text(object["id"], maximum: 128),
              let plan = try? text(object["plan"], maximum: 32),
              let createdAt = milliseconds(object["createdAt"])
        else { throw AccountReadError.invalidResponse }
        let email = try optionalText(object["email"], maximum: 254)
        let cap = try optionalInteger(object["maxProviderConnections"], upperBound: 10_000)
        return AccountProfile(id: id, email: email, plan: plan, maxProviderConnections: cap, createdAt: createdAt)
    }

    static func entitlement(_ body: Data) throws -> AccountEntitlementSummary {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let object = root["entitlement"] as? [String: Any],
              let plan = try? text(object["plan"], maximum: 32)
        else { throw AccountReadError.invalidResponse }
        return AccountEntitlementSummary(
            plan: plan,
            maxProviderConnections: try optionalInteger(object["maxProviderConnections"], upperBound: 10_000),
            paidThrough: try optionalSeconds(object["paidThrough"]),
            updatedAt: try optionalMilliseconds(object["updatedAt"])
        )
    }

    static func invoices(_ body: Data) throws -> AccountInvoiceListing {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let rows = root["invoices"] as? [Any], rows.count <= maximumRows,
              let available = root["available"] as? NSNumber, CFGetTypeID(available) == CFBooleanGetTypeID()
        else { throw AccountReadError.invalidResponse }
        var invoices: [AccountInvoice] = []
        for row in rows {
            guard let object = row as? [String: Any],
                  let id = try? text(object["id"], maximum: 128),
                  let created = seconds(object["created"]),
                  let description = try? text(object["description"], maximum: 120),
                  let amount = integer(object["amountPaid"]), amount >= 0,
                  let currency = try? text(object["currency"], maximum: 8),
                  let status = try? text(object["status"], maximum: 24)
            else { throw AccountReadError.invalidResponse }
            invoices.append(AccountInvoice(id: id, created: created, description: description, amountPaid: amount, currency: currency, status: status))
        }
        return AccountInvoiceListing(invoices: invoices, available: available.boolValue)
    }

    static func devices(_ body: Data) throws -> AccountDeviceListing {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let rows = root["devices"] as? [Any], rows.count <= maximumRows
        else { throw AccountReadError.invalidResponse }
        var devices: [AccountDevice] = []
        for row in rows {
            guard let object = row as? [String: Any],
                  let id = try? text(object["id"], maximum: 64),
                  let name = try? text(object["name"], maximum: 96),
                  let fingerprint = try? text(object["fingerprint"], maximum: 64),
                  let status = try? text(object["status"], maximum: 24),
                  let createdAt = milliseconds(object["createdAt"])
            else { throw AccountReadError.invalidResponse }
            devices.append(AccountDevice(id: id, name: name, fingerprint: fingerprint, status: status, createdAt: createdAt, revokedAt: try optionalMilliseconds(object["revokedAt"])))
        }
        return AccountDeviceListing(devices: devices, nextCursor: try optionalText(root["nextCursor"], maximum: 256))
    }

    static func connections(_ body: Data) throws -> AccountConnectionListing {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let rows = root["devices"] as? [Any], rows.count <= maximumRows,
              let total = integer(root["total"]), total >= 0
        else { throw AccountReadError.invalidResponse }
        var devices: [AccountConnectionDevice] = []
        for row in rows {
            guard let object = row as? [String: Any],
                  let deviceID = try? text(object["deviceId"], maximum: 64),
                  let deviceName = try? text(object["deviceName"], maximum: 96),
                  let rawConnections = object["connections"] as? [Any], rawConnections.count <= maximumRows
            else { throw AccountReadError.invalidResponse }
            var connections: [AccountConnection] = []
            for entry in rawConnections {
                guard let connection = entry as? [String: Any],
                      let provider = try? text(connection["provider"], maximum: 40),
                      let paused = connection["paused"] as? NSNumber, CFGetTypeID(paused) == CFBooleanGetTypeID()
                else { throw AccountReadError.invalidResponse }
                connections.append(AccountConnection(
                    provider: provider,
                    label: try optionalText(connection["label"], maximum: 96),
                    principalHint: try optionalText(connection["principalHint"], maximum: 96),
                    verifiedAt: try optionalMilliseconds(connection["verifiedAt"]),
                    paused: paused.boolValue,
                    updatedAt: try optionalMilliseconds(connection["updatedAt"])
                ))
            }
            devices.append(AccountConnectionDevice(deviceId: deviceID, deviceName: deviceName, connections: connections))
        }
        return AccountConnectionListing(devices: devices, total: total)
    }

    static func referral(_ body: Data) throws -> AccountReferralSummary {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let object = root["referral"] as? [String: Any],
              let code = try? text(object["code"], maximum: 64),
              let link = try? text(object["link"], maximum: 256),
              let counts = object["counts"] as? [String: Any],
              let attributed = integer(counts["attributed"]), let converted = integer(counts["converted"]),
              let capped = integer(counts["capped"]), let credited = integer(counts["credited"]),
              let total = integer(counts["total"]),
              let creditsEnabled = object["creditsEnabled"] as? NSNumber, CFGetTypeID(creditsEnabled) == CFBooleanGetTypeID(),
              let monthlyCap = integer(object["monthlyCap"]), let creditCents = integer(object["creditCents"]),
              [attributed, converted, capped, credited, total, monthlyCap, creditCents].allSatisfy({ $0 >= 0 })
        else { throw AccountReadError.invalidResponse }
        // The link must be this account service's own. A referral link is
        // something the owner is invited to share, so a relay that rewrote the
        // origin would be handing them a URL to distribute.
        guard link.hasPrefix("https://") else { throw AccountReadError.invalidResponse }
        return AccountReferralSummary(code: code, link: link, attributed: attributed, converted: converted, capped: capped, credited: credited, total: total, creditsEnabled: creditsEnabled.boolValue, monthlyCap: monthlyCap, creditCents: creditCents)
    }

    static func activity(_ body: Data) throws -> [AccountActivityEvent] {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let rows = root["events"] as? [Any], rows.count <= 100
        else { throw AccountReadError.invalidResponse }
        var events: [AccountActivityEvent] = []
        for row in rows {
            guard let object = row as? [String: Any],
                  let type = try? text(object["type"], maximum: 48),
                  let at = milliseconds(object["at"])
            else { throw AccountReadError.invalidResponse }
            events.append(AccountActivityEvent(type: type, at: at, detail: try optionalText(object["detail"], maximum: 256)))
        }
        return events
    }

    /// `GET /api/mfa/status` — BL-076 / D43.
    ///
    /// **`stepUp` and `lockedUntil` are not read, and that is the contract
    /// rather than an omission.** Both are always null over a device session
    /// (`docs/mfa.md`: "a step-up is a fact about a browser session and a Mac
    /// does not have one"), and the Mac is told not to render a step-up state.
    /// They are *ignored* rather than refused: a Worker that one day populates
    /// them for some other caller must not break the Mac's Security row, and
    /// `AccountMfaStatus` has nowhere to put either value even if it wanted to.
    ///
    /// `recentEvents` is optional on purpose — the contract calls rendering it
    /// optional for the Mac, and a deployment that predates MF-H3 sends no such
    /// key. An absent key is an empty list, not a refusal.
    static func mfaStatus(_ body: Data) throws -> AccountMfaStatus {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let object = root["mfa"] as? [String: Any],
              let ready = boolean(object["ready"]),
              let enabled = boolean(object["enabled"]),
              let pending = boolean(object["pendingEnrolment"]),
              let remaining = try withheldCount(object["backupCodesRemaining"])
        else { throw AccountReadError.invalidResponse }
        var events: [AccountMfaEvent] = []
        if let rows = object["recentEvents"] as? [Any] {
            // `MFA_STATUS_EVENT_LIMIT` in `src/mfa.ts` is twenty. More than
            // that is a Worker this build does not understand, and this file's
            // rule is to fail loudly rather than render part of an answer.
            guard rows.count <= maximumMfaEvents else { throw AccountReadError.invalidResponse }
            for row in rows {
                guard let entry = row as? [String: Any],
                      let type = try? text(entry["type"], maximum: 48),
                      let at = milliseconds(entry["at"])
                else { throw AccountReadError.invalidResponse }
                events.append(AccountMfaEvent(type: type, at: at))
            }
        } else if object["recentEvents"] != nil, !(object["recentEvents"] is NSNull) {
            throw AccountReadError.invalidResponse
        }
        return AccountMfaStatus(
            ready: ready,
            enabled: enabled,
            pendingEnrolment: pending,
            enabledAt: try optionalMilliseconds(object["enabledAt"]),
            backupCodesRemaining: remaining,
            accountLockedUntil: try optionalMilliseconds(object["accountLockedUntil"]),
            recentEvents: events
        )
    }

    /// `GET /api/account/deletion-request` — MF-C1's ungated status verb, now
    /// on `DEVICE_ACCOUNT_ROUTES` under `account:read`.
    ///
    /// `nil` is "no request is pending", which is the ordinary answer and not a
    /// failure. The key must be **present**: a body with no `deletionRequest`
    /// at all is a response this build does not recognise, and silently reading
    /// it as "nothing pending" would be the one mistake that matters here.
    ///
    /// All six fields are required, because one shape for both verbs is the
    /// contract now (`src/account.ts`'s `PendingDeletion`) and the whole point
    /// of it is that a client stops guessing. A body carrying only the old
    /// three, or the five that predate `completesNoLaterThan`, therefore fails
    /// the read — which renders the card's *failure* state, not its absent
    /// one, and a failure state never claims nothing is pending. That cost is
    /// unconditional as of the contract follow-ups (2026-09-14): both verbs
    /// have carried `completesNoLaterThan` since, so there is no Worker left in
    /// the field this build is being newly strict against.
    static func deletionRequest(_ body: Data) throws -> AccountDeletionRequest? {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let raw = root["deletionRequest"]
        else { throw AccountReadError.invalidResponse }
        if raw is NSNull { return nil }
        guard let object = raw as? [String: Any],
              let status = try? text(object["status"], maximum: 32), !status.isEmpty,
              let receiptId = try? text(object["receiptId"], maximum: 128),
              let requestedAt = milliseconds(object["requestedAt"]),
              let completesAt = milliseconds(object["completesAt"]),
              completesAt > requestedAt,
              // `completesAt + DELETION_SWEEP_INTERVAL_MS`, so it can never
              // land before the floor it is the ceiling for.
              let completesNoLaterThan = milliseconds(object["completesNoLaterThan"]),
              completesNoLaterThan >= completesAt,
              // A real JSON boolean, for the same reason `mfa.ready` is: this
              // one decides whether the card says "suspended, and cancelling
              // brings them back" or says nothing at all, and a coerced truthy
              // value is the wrong thing to be generous about.
              let suspended = boolean(object["credentialsSuspended"])
        else { throw AccountReadError.invalidResponse }
        return AccountDeletionRequest(
            status: status,
            receiptId: receiptId,
            requestedAt: requestedAt,
            completesAt: completesAt,
            completesNoLaterThan: completesNoLaterThan,
            credentialsSuspended: suspended
        )
    }

    // MARK: Primitives

    /// A bounded, control-character-free string. The bound is the route's, not a
    /// guess: a value over it is a Worker this build does not understand.
    static func text(_ value: Any?, maximum: Int) throws -> String {
        guard let string = value as? String, string.utf8.count <= min(maximum, maximumStringBytes),
              !APITokenRequestValidation.hasControlCharacters(string)
        else { throw AccountReadError.invalidResponse }
        return string
    }

    static func optionalText(_ value: Any?, maximum: Int) throws -> String? {
        if value == nil || value is NSNull { return nil }
        return try text(value, maximum: maximum)
    }

    static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        return number.intValue
    }

    /// A real JSON boolean. `1`, `"true"` and a missing key are all refused:
    /// `mfa.ready` and `mfa.enabled` decide what a Security row claims about
    /// someone's account, and a coerced truthy value is the wrong thing to be
    /// generous about.
    static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    static func optionalInteger(_ value: Any?, upperBound: Int) throws -> Int? {
        if value == nil || value is NSNull { return nil }
        guard let number = integer(value), number >= 0, number <= upperBound else { throw AccountReadError.invalidResponse }
        return number
    }

    /// A count the route may **withhold**: an integer in range, or an explicit
    /// `null` meaning "not disclosed to this credential".
    ///
    /// AS-L2 made `backupCodesRemaining` null over a device session whenever a
    /// factor exists, and the shipped decoder required an integer — so the first
    /// deployment of that change would have failed the whole two-factor read on
    /// every linked Mac rather than rendering four true sentences and one
    /// withheld count. `docs/mfa.md` had reasoned the opposite way round ("the
    /// Mac never sees the withheld form, and if that ever changed it would fail
    /// closed rather than render a zero"), which stopped being right the day
    /// AS-L2 shipped.
    ///
    /// So `null` decodes and a **wrong type still fails closed**: a string, a
    /// boolean, a negative number and one over the bound are each a Worker this
    /// build does not understand, and none of them may become a zero. The
    /// double optional is deliberate — the outer one is "the key was
    /// unreadable", the inner one is "the route withheld it" — and a missing key
    /// is unreadable, because the route always sends this one.
    static func withheldCount(_ value: Any?) throws -> Optional<Int?> {
        if value is NSNull { return .some(nil) }
        guard let number = integer(value), number >= 0, number <= 100 else { return nil }
        return .some(number)
    }

    /// Epoch **milliseconds**.
    static func milliseconds(_ value: Any?) -> Date? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let raw = number.doubleValue
        guard raw > 0, raw < 4_102_444_800_000 else { return nil }
        return Date(timeIntervalSince1970: raw / 1000)
    }

    /// Epoch **seconds** — Stripe's unit, and the one `paid_through` is stored
    /// in. Decoding it as milliseconds puts every invoice in January 1970.
    static func seconds(_ value: Any?) -> Date? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let raw = number.doubleValue
        guard raw > 0, raw < 4_102_444_800 else { return nil }
        return Date(timeIntervalSince1970: raw)
    }

    static func optionalMilliseconds(_ value: Any?) throws -> Date? {
        if value == nil || value is NSNull { return nil }
        guard let date = milliseconds(value) else { throw AccountReadError.invalidResponse }
        return date
    }

    static func optionalSeconds(_ value: Any?) throws -> Date? {
        if value == nil || value is NSNull { return nil }
        guard let date = seconds(value) else { throw AccountReadError.invalidResponse }
        return date
    }
}
