import CryptoKit
import Foundation
import Security

/// The public state used by the local connection gate. A missing, expired, or
/// unverifiable lease always resolves to the Free allowance.
public struct AccountEntitlement: Codable, Sendable, Equatable {
    public enum Source: String, Codable, Sendable { case signedLease, free, unavailable, clockRollback }
    public let plan: String
    public let managedConnectionLimit: Int?
    public let leaseExpiresAt: Date?
    public let source: Source

    public init(plan: String, managedConnectionLimit: Int?, leaseExpiresAt: Date? = nil, source: Source = .free) {
        self.plan = plan; self.managedConnectionLimit = managedConnectionLimit; self.leaseExpiresAt = leaseExpiresAt; self.source = source
    }
    public static let free = AccountEntitlement(plan: "free", managedConnectionLimit: 3)
    public var isPaid: Bool { plan == "personal" && managedConnectionLimit == nil && source == .signedLease }
    /// Existing connections remain intact. This only decides whether another managed connection can be added.
    public func allowsAdditionalManagedConnection(existingCount: Int) -> Bool {
        guard existingCount >= 0 else { return false }
        return managedConnectionLimit.map { existingCount < $0 } ?? isPaid
    }
}

public protocol AccountClient: Sendable { func currentEntitlement() async throws -> AccountEntitlement }

public enum AccountClientError: Error, LocalizedError, Sendable, Equatable {
    case accountStorageUnavailable
    case accountNotLinked, authorizationPending, authorizationExpired, authorizationRevoked, serviceUnavailable, networkUnavailable, invalidResponse, invalidEntitlement, clockRollback, cancelled
    /// BL113-M3. The Worker has already completed this authorization: a device
    /// and a session exist for it, and it will never complete again.
    ///
    /// It used to have no case here, so `map` folded it into
    /// `.invalidResponse` and `pollLink`'s clear-on-error did not cover it. A
    /// single lost exchange response — the Worker committed, this Mac never saw
    /// it — therefore stranded the Mac: the pending record stayed, every *Try
    /// again* reused it (BL-113's own follow-up made reuse the default), and
    /// the screen said "That sign-in did not complete" for the rest of the ten
    /// minutes while the account carried a live device nobody held. It is its
    /// own case so that the pending record is cleared and *Try again* mints a
    /// fresh authorization, which is the only thing that can recover it.
    case authorizationConsumed
    /// BL-113 follow-up. The Worker's own per-installation or per-address
    /// creation budget refused this attempt (`rate_limited` or `slow_down`).
    /// Kept distinct from `.networkUnavailable`: this Mac reached the account
    /// service and was answered, so telling a human they are offline would be
    /// dishonest. `retryAfterSeconds` is the Worker's own accounting of what
    /// is left of its window, carried only when the response offered one.
    case rateLimited(retryAfterSeconds: TimeInterval?)
    /// BL-113 (D47). A `vaultage://link/<id>` URL this app was handed that it
    /// did not start: another id, a malformed URL, or no link in flight at all.
    case unexpectedLinkReturn(DeviceLinkReturn.Refusal)
    public var errorDescription: String? {
        switch self {
        case .accountNotLinked: "This Mac is not linked to an account."
        case .authorizationPending: "Waiting for account confirmation."
        case .authorizationExpired: "The linking code expired. Start a new link."
        case .authorizationRevoked: "This device session is no longer active."
        case .serviceUnavailable: "Account service is not configured or is unavailable."
        case .accountStorageUnavailable: "Vaultage could not access this Mac’s account storage. Check the app’s signing and Keychain access, then try again."
        case .networkUnavailable: "Could not reach the account service."
        case .invalidResponse: "The account service returned an invalid response."
        case .invalidEntitlement: "The account lease could not be verified."
        case .clockRollback: "Your Mac clock moved backward. Reconnect after correcting it."
        case .cancelled: "Account linking was cancelled."
        case .authorizationConsumed: "That sign-in was already completed. Start a new one."
        case .rateLimited: "Too many sign-in attempts from this Mac. Wait a few minutes, then try again."
        case .unexpectedLinkReturn(let refusal):
            switch refusal {
            case .malformed: "That link was not a Vaultage sign-in return."
            case .unknownAuthorization: "That sign-in belongs to a different request. Nothing was linked."
            case .noPendingLink: "This Mac is not waiting to be linked. Nothing was linked."
            }
        }
    }
}

/// What the Mac shows and opens while it waits to be approved.
///
/// BL-071 / D15. `approvalURL` is the automatic path: the browser opens straight
/// at the signed-in link page with the one-time user code already in it, so the
/// human clicks Approve and types nothing. `verificationURL` is the manual
/// fallback — the ordinary account page, where the same code is typed by hand —
/// and it is what the app offers when the browser cannot be opened.
///
/// Neither URL ever carries a token, a polling secret, a PKCE verifier or a
/// session: `userCode` is a short-lived, single-use, human-scale code that
/// authorizes nothing on its own. It is only ever consumed by a browser already
/// holding a signed-in account session, which must then approve it explicitly
/// after reading this Mac's name and key fingerprint. `approvalURL` is built
/// locally from the pinned origin and the validated code, never from a string
/// the server sent.
/// D59 (2026-09-16). Which identity step the human chose **in the app**. It
/// travels to the dashboard as the `method` query item so the browser opens on
/// that step — Google's own account chooser, or the email-code form — instead
/// of a second chooser. It is a hint about presentation and grants nothing: the
/// Worker never reads it, and a page reached without it shows the full card.
public enum SignInMethod: String, Sendable, Codable, Equatable {
    case google, email
}

public struct AccountLinkChallenge: Sendable, Equatable {
    public let userCode: String; public let approvalURL: URL; public let verificationURL: URL; public let expiresAt: Date; public let pollingInterval: TimeInterval; public let deviceName: String
    /// BL-113 (D47). The id of the authorization this challenge belongs to. It
    /// is not a credential — it names a row the Worker already refuses to act
    /// on without the polling secret and the PKCE verifier — and it is what the
    /// return URL must equal for this app to accept it.
    public let requestID: String
    /// BL-113 (D47). `vaultage://link/<requestID>`, built from the compiled
    /// scheme, and what `signInURL` asks the browser to come back to.
    public let returnTarget: URL
    /// BL-113 (D47). The page the sign-in screen opens: `approvalURL` plus the
    /// return target, so the dashboard can approve this authorization the
    /// moment the sign-in completes and hand control straight back.
    ///
    /// `approvalURL` stays beside it and is still what the re-link path and the
    /// "open the page again" control use when no automatic return is wanted.
    public let signInURL: URL

    public init(userCode: String, approvalURL: URL, verificationURL: URL, expiresAt: Date, pollingInterval: TimeInterval, deviceName: String, requestID: String, returnTarget: URL, signInURL: URL) {
        self.userCode = userCode
        self.approvalURL = approvalURL
        self.verificationURL = verificationURL
        self.expiresAt = expiresAt
        self.pollingInterval = pollingInterval
        self.deviceName = deviceName
        self.requestID = requestID
        self.returnTarget = returnTarget
        self.signInURL = signInURL
    }
}

/// The linked state, as the Account screen renders it. Non-secret and bounded:
/// a display email, this Mac's chosen name and the public-key fingerprint the
/// browser showed at approval time. No token, no key, no polling secret.
public struct LinkedAccountSummary: Sendable, Equatable {
    public let email: String?
    public let deviceName: String
    public let deviceFingerprint: String
    public init(email: String?, deviceName: String, deviceFingerprint: String) { self.email = email; self.deviceName = deviceName; self.deviceFingerprint = deviceFingerprint }
}
/// Public verification material only. The shipping client always uses `release`;
/// alternative values exist solely for deterministic local test fixtures and are
/// never loaded from a server or user-controlled setting.
public struct AccountEntitlementVerificationKey: Sendable, Equatable {
    public let kid: String; public let x: String; public let y: String
    public init(kid: String, x: String, y: String) { self.kid = kid; self.x = x; self.y = y }
    public static let release = AccountEntitlementVerificationKey(kid: "vaultage-foundation-20260910-01", x: "LQzYPVBCrQAmHK3xh-Rw3FINUR66I-2gvOv6qitvrLc", y: "ZEgdGpbRCdXuMzt-CtvmUGz-5hEN0xYFuJ-lhvlB_JY")
}
public enum AccountLinkPoll: Sendable, Equatable { case pending(nextPollAt: Date), linked }
/// Whether this Mac confirmed remote device revocation before removing its
/// local account state. Local vault data is never part of either outcome.
public enum AccountSignOutOutcome: Sendable, Equatable { case serverRevoked, localOnly }
public struct AccountHTTPResponse: Sendable { public let statusCode: Int; public let body: Data; public init(statusCode: Int, body: Data) { self.statusCode = statusCode; self.body = body } }

/// A narrow transport seam keeps account tests away from the network and keeps provider credentials structurally out of this subsystem.
public protocol AccountHTTPTransport: Sendable { func send(_ request: URLRequest) async throws -> AccountHTTPResponse }
public struct URLSessionAccountTransport: AccountHTTPTransport {
    public init() {}
    public func send(_ request: URLRequest) async throws -> AccountHTTPResponse {
        var request = request; request.timeoutInterval = 15
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false; configuration.urlCredentialStorage = nil; configuration.requestCachePolicy = .reloadIgnoringLocalCacheData; configuration.timeoutIntervalForResource = 20
        let redirectBlocker = AccountRedirectBlocker()
        let session = URLSession(configuration: configuration, delegate: redirectBlocker, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { throw AccountClientError.invalidResponse }
            var data = Data(); data.reserveCapacity(4096)
            for try await byte in bytes {
                data.append(byte)
                if data.count > 64 * 1024 { throw AccountClientError.invalidResponse }
            }
            return AccountHTTPResponse(statusCode: http.statusCode, body: data)
        } catch is AccountClientError { throw AccountClientError.invalidResponse }
        catch is CancellationError { throw AccountClientError.cancelled }
        catch { throw AccountClientError.networkUnavailable }
    }
}

private final class AccountRedirectBlocker: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/// Account state uses its own Keychain service. It is never stored in UserDefaults or a provider credential record.
public protocol AccountSecureStore: Sendable { func data(for account: String) throws -> Data?; func save(_ data: Data, account: String) throws; func remove(account: String) throws }
public struct AccountKeychainStore: AccountSecureStore {
    private let service = "com.vaultage.foundation20260910.desktop-account.v1"
    /// BL-101. The access-group decision for this process, resolved once at
    /// `KeychainAccessGroup.current`, exactly as `KeychainVault` resolves it.
    /// Injectable only so the self-tests can drive §11.4.2's table without
    /// re-signing a binary; nothing in the product passes it.
    ///
    /// These four call sites were BL-101's one named exemption — the device
    /// session record carries the same ordering hazard as a credential, because
    /// an item saved with no `kSecAttrAccessGroup` lands in the *first* group of
    /// the signing entitlement and would move the day a second group is added.
    /// The exemption is closed; no implicit call site remains in `VaultageCore`.
    private let accessGroupDecision: KeychainAccessGroup.LaunchDecision
    public init() { self.init(accessGroupDecision: KeychainAccessGroup.current) }
    public init(accessGroupDecision: KeychainAccessGroup.LaunchDecision) { self.accessGroupDecision = accessGroupDecision }
    /// A build that must name its group and cannot throws before it touches the
    /// Keychain; an unsigned build gets `nil` and the attribute is omitted,
    /// which is exactly the behaviour before this change.
    private func accessGroup() throws -> String? { try KeychainAccessGroup.resolvedForCustody(accessGroupDecision) }
    private func storageFailure(_ status: OSStatus, operation: String) -> AccountClientError {
        // Operation names are constants; never log account identifiers or values.
        NSLog("Vaultage account storage %@ failed (OSStatus %d)", operation, status)
        return .accountStorageUnavailable
    }
    public func data(for account: String) throws -> Data? {
        let query = KeychainAccessGroup.sessionReadAttributes(service: service, account: account, accessGroup: try accessGroup())
        var item: CFTypeRef?; let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw storageFailure(status, operation: "read") }
        return data
    }
    public func save(_ data: Data, account: String) throws {
        let group = try accessGroup()
        let key = KeychainAccessGroup.sessionUpdateQueryAttributes(service: service, account: account, accessGroup: group)
        let update = SecItemUpdate(key as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw storageFailure(update, operation: "update") }
        var add = KeychainAccessGroup.sessionAddAttributes(service: service, account: account, accessGroup: group)
        add[kSecValueData as String] = data
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw storageFailure(status, operation: "add") }
    }
    public func remove(account: String) throws {
        let query = KeychainAccessGroup.sessionDeleteAttributes(service: service, account: account, accessGroup: try accessGroup())
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw storageFailure(status, operation: "remove") }
    }
}

public actor DeviceAccountClient: AccountClient, DeviceConnectionReporting {
    /// Release-time bundle configuration. This is intentionally not read from
    /// preferences, the environment, a redirect, or a downloaded document.
    /// Change it only as part of a reviewed signed build when the production
    /// account domain is provisioned.
    private static let bundledOriginString = "https://vaultage.dev"
    public static let origin = URL(string: bundledOriginString)!
    public static let accountURL = URL(string: bundledOriginString + "/account")!
    /// BL-071 / BL-113. The page the control plane names as `verificationUri`
    /// on every minted authorization since 2026-09-11: the dashboard's device
    /// link page. `safeVerificationURL` accepts exactly this path. Build 9's
    /// sign-in failed right after a successful mint because the validator
    /// still pinned `/account`, the pre-dashboard page — found in the owner's
    /// QA on 2026-09-16 and the third distinct cause of the same symptom.
    public static let linkURL = URL(string: bundledOriginString + "/app/link")!
    /// BL-071. The signed-in browser page that shows this Mac and one Approve
    /// button. The path is fixed here rather than taken from the server, so a
    /// compromised or spoofed response cannot send the human anywhere else.
    public static let linkPath = "/app/link"
    private let origin: URL; private let store: any AccountSecureStore; private let transport: any AccountHTTPTransport; private let now: @Sendable () -> Date; private let entitlementKey: AccountEntitlementVerificationKey
    /// Deliberately in-memory: this only avoids repeated offline network waits;
    /// it never lengthens a signed entitlement lease across app launches.
    private var entitlementTransportFailureAt: Date?

    public init(origin: URL = DeviceAccountClient.origin, store: any AccountSecureStore = AccountKeychainStore(), transport: any AccountHTTPTransport = URLSessionAccountTransport(), now: @escaping @Sendable () -> Date = Date.init, entitlementVerificationKey: AccountEntitlementVerificationKey = .release) {
        self.origin = origin; self.store = store; self.transport = transport; self.now = now; self.entitlementKey = entitlementVerificationKey
    }

    public func startLink(deviceName requestedName: String? = nil, method: SignInMethod? = nil) async throws -> AccountLinkChallenge {
        try requireSupportedOrigin()
        let identity = try loadOrCreateIdentity(deviceName: requestedName)
        // BL-113 follow-up (owner-reported after build 7). The sign-in screen
        // used to mint a fresh authorization on every click and on every "Try
        // again" with this same installation id, which is what exhausted the
        // Worker's five-per-hour creation budget across builds 5, 6 and 7 and
        // got the owner told they were offline when they were not. A pending
        // link this Mac already minted and has not exhausted — not expired,
        // not yet consumed by a completed link — is reused instead: the human
        // gets the same code and the same browser page back, and the Worker
        // sees no second request at all. `try?` is deliberate: a pending
        // record from before this change, or a Keychain read that failed for
        // any other reason, must fall through to an ordinary fresh mint rather
        // than surface as an error here.
        if let pending: PendingLink = try? load(.pending), pending.expiresAt > now() {
            return try reusedChallenge(pending)
        }
        let pollingSecret = try randomBase64URL(bytes: 32), verifier = try randomBase64URL(bytes: 48)
        let body: [String: Any] = ["installationId": identity.installationID, "deviceName": identity.deviceName, "devicePublicJwk": ["kty": "OKP", "crv": "Ed25519", "x": identity.publicJWK.x], "pollingSecret": pollingSecret, "pkceVerifier": verifier]
        let response = try await sendJSON(path: "/api/device-authorizations", body: body)
        guard response.statusCode == 201 else { throw map(response) }
        let authorization = try object(response.body, key: "authorization")
        let requestID = try requiredString(authorization, "requestId", matching: "^[0-9a-fA-F-]{36}$")
        let code = try requiredString(authorization, "userCode", matching: "^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$")
        let verificationURL = try safeVerificationURL(requiredString(authorization, "verificationUri"))
        let approvalURL = try Self.approvalURL(origin: origin, userCode: code)
        let expiresAt = try date(requiredString(authorization, "expiresAt")), interval = try requiredNumber(authorization, "intervalSeconds")
        guard expiresAt > now(), interval >= 5, interval <= 60 else { throw AccountClientError.invalidResponse }
        // BL-113 (D47). The return target and the page that carries it. Both
        // are built here, from the compiled scheme and the request id the
        // Worker just minted, and both are re-checked by the same parsers that
        // will read them back; a Worker response cannot influence either.
        guard let returnTarget = DeviceLinkReturn.url(authorizationID: requestID) else { throw AccountClientError.invalidResponse }
        let signInURL = try Self.signInURL(origin: origin, userCode: code, returnTarget: returnTarget, method: method)
        try save(PendingLink(requestID: requestID, pollingSecret: pollingSecret, pkceVerifier: verifier, expiresAt: expiresAt, interval: interval, nextPollAt: now(), deviceName: identity.deviceName, userCode: code, verificationURL: verificationURL, method: method?.rawValue), as: .pending)
        return AccountLinkChallenge(userCode: code, approvalURL: approvalURL, verificationURL: verificationURL, expiresAt: expiresAt, pollingInterval: interval, deviceName: identity.deviceName, requestID: requestID, returnTarget: returnTarget, signInURL: signInURL)
    }

    /// BL-113 follow-up. Rebuilds the exact `AccountLinkChallenge` the pending
    /// link's own mint returned: `approvalURL`, `returnTarget` and `signInURL`
    /// are deterministic functions of the pinned origin and the stored user
    /// code and request id, so nothing here is re-derived from anything the
    /// Worker could have said since. This is what makes "Try again" reopen the
    /// browser at the same authorization instead of spending another mint.
    private func reusedChallenge(_ pending: PendingLink) throws -> AccountLinkChallenge {
        let approvalURL = try Self.approvalURL(origin: origin, userCode: pending.userCode)
        guard let returnTarget = DeviceLinkReturn.url(authorizationID: pending.requestID) else { throw AccountClientError.invalidResponse }
        let signInURL = try Self.signInURL(origin: origin, userCode: pending.userCode, returnTarget: returnTarget, method: pending.method.flatMap(SignInMethod.init(rawValue:)))
        return AccountLinkChallenge(userCode: pending.userCode, approvalURL: approvalURL, verificationURL: pending.verificationURL, expiresAt: pending.expiresAt, pollingInterval: pending.interval, deviceName: pending.deviceName, requestID: pending.requestID, returnTarget: returnTarget, signInURL: signInURL)
    }

    /// BL-113 (D47). The authorization this Mac is currently waiting on, or nil.
    ///
    /// It is the id and nothing else: the pending record also holds the polling
    /// secret and the PKCE verifier, and neither leaves this actor. The URL
    /// handler needs exactly this much to decide whether a `vaultage://link/…`
    /// it was handed is the one it started.
    public func pendingLinkRequestID() throws -> String? {
        guard let pending: PendingLink = try load(.pending) else { return nil }
        guard pending.expiresAt > now() else { return nil }
        return pending.requestID
    }

    /// BL-113 (D47) — the browser coming back.
    ///
    /// The URL must name the authorization this app minted and is still waiting
    /// on; anything else throws `unexpectedLinkReturn`, which the caller turns
    /// into a receipt. A URL that passes is a **wake-up and nothing more**: the
    /// device session still comes only from `pollLink()`, which proves the
    /// polling secret and the PKCE verifier that never left this Mac. So this
    /// clears the poll delay and polls once, and the caller's `waitForLink()`
    /// carries on exactly as it would have if the browser had never returned.
    public func acceptLinkReturn(_ url: URL) async throws -> AccountLinkPoll {
        guard var pending: PendingLink = try load(.pending) else {
            throw AccountClientError.unexpectedLinkReturn(.noPendingLink)
        }
        let accepted: DeviceLinkReturn.Accepted
        switch DeviceLinkReturn.resolve(url, pendingRequestID: pending.requestID) {
        case .failure(let refusal): throw AccountClientError.unexpectedLinkReturn(refusal)
        case .success(let value): accepted = value
        }
        // BL113-C1. The one-time proof an automatic approval put in the return,
        // kept beside the two secrets this link already holds and presented to
        // the exchange below. It is the half of the binding that could only have
        // arrived on *this* machine, because Launch Services resolved the URL
        // here. It is never logged, never written to a receipt and never shown:
        // the only place it goes from here is the exchange request body.
        //
        // A manual approval's return carries none, and none is needed: the
        // Worker distinguishes the two by whether it minted a proof for that
        // authorization at all.
        if let proof = accepted.proof { pending.returnProof = proof }
        // The browser says it is approved, so there is no reason to sit out the
        // rest of the five-second interval. The Worker's own `slow_down` is
        // still the authority on how often this Mac may ask.
        pending.nextPollAt = now()
        try save(pending, as: .pending)
        return try await pollLink()
    }

    /// Calls before the required interval return pending without sending a request.
    public func pollLink() async throws -> AccountLinkPoll {
        try Task.checkCancellation()
        guard let pending: PendingLink = try load(.pending) else { throw AccountClientError.accountNotLinked }
        let current = now(); guard current < pending.expiresAt else { try clear(.pending); throw AccountClientError.authorizationExpired }
        guard current >= pending.nextPollAt else { return .pending(nextPollAt: pending.nextPollAt) }
        // BL113-C1. The proof is present only after the browser came back with
        // one, and only for an authorization the Worker approved automatically.
        // Until then this is the same three-field body it has always been, and
        // a Mac that is polling an authorization it was never handed a return
        // for is told `authorization_pending` for as long as it asks.
        var exchangeBody: [String: Any] = ["requestId": pending.requestID, "pollingSecret": pending.pollingSecret, "pkceVerifier": pending.pkceVerifier]
        if let proof = pending.returnProof { exchangeBody["returnProof"] = proof }
        let response = try await sendJSON(path: "/api/device-authorizations/exchange", body: exchangeBody)
        if response.statusCode == 428 { return try schedulePending(pending, after: pending.interval) }
        if response.statusCode == 429 { return try schedulePending(pending, after: max(5, retryDelay(response.body) ?? pending.interval + 5)) }
        // BL113-M3. `authorizationConsumed` joins the two terminal refusals that
        // clear the pending record. Without it a lost exchange response left
        // this Mac reusing a link that can never complete, for the rest of the
        // ten minutes, while telling the owner the sign-in had not completed —
        // about a Mac the Worker had in fact already linked.
        guard response.statusCode == 200 else { let error = map(response); if error == .authorizationExpired || error == .authorizationRevoked || error == .authorizationConsumed { try clear(.pending) }; throw error }
        let device = try object(response.body, key: "device"), session = try object(response.body, key: "session")
        let deviceID = try requiredString(device, "id", matching: "^[0-9a-fA-F-]{36}$"), fingerprint = try requiredString(device, "fingerprint", matching: "^[A-Z0-9_-]{8,64}$")
        let token = try requiredString(session, "token", matching: "^[A-Za-z0-9_-]{43,128}$"), expiresAt = try date(requiredString(session, "expiresAt"))
        guard expiresAt > current else { throw AccountClientError.invalidResponse }
        var identity = try requireIdentity()
        // Matches the server's documented display fingerprint exactly:
        // SHA-256(JSON.stringify({kty, crv, x})), base64url first 16, uppercase.
        guard fingerprint == deviceFingerprint(identity.publicJWK) else { throw AccountClientError.invalidResponse }
        identity.deviceID = deviceID; identity.deviceFingerprint = fingerprint; identity.accountSubject = nil
        // BL-071. The account page's own display email, when the control plane
        // sends one. Optional by design: this client links and works without
        // it, and a missing or malformed value is simply not displayed.
        identity.accountEmail = Self.displayEmail(optionalObject(response.body, key: "account")?["email"])
        try save(identity, as: .identity); try save(SessionCredential(token: token, expiresAt: expiresAt), as: .session); try clear(.pending)
        return .linked
    }

    public func waitForLink() async throws {
        while true { try Task.checkCancellation(); switch try await pollLink() { case .linked: return; case .pending(let next): try await Task.sleep(for: .seconds(max(0, next.timeIntervalSince(now())))) } }
    }
    public func cancelLink() throws { try clear(.pending) }

    /// BL-071. What the Account screen shows once this Mac is linked: the
    /// account's display email when the service has provided one, this Mac's
    /// name, and the public-key fingerprint the browser displayed at approval.
    /// Returns nil when this Mac is not linked. Nothing here is a credential.
    public func linkedAccount() throws -> LinkedAccountSummary? {
        guard try isLinked(), let identity: DeviceIdentity = try load(.identity), let fingerprint = identity.deviceFingerprint else { return nil }
        return LinkedAccountSummary(email: identity.accountEmail, deviceName: identity.deviceName, deviceFingerprint: fingerprint)
    }
    public func isLinked() throws -> Bool {
        guard let identity: DeviceIdentity = try load(.identity), identity.deviceID != nil, identity.deviceFingerprint != nil, let session: SessionCredential = try load(.session), session.expiresAt > now() else { return false }; return true
    }
    /// Explicit local sign-out preserves local vault data, projects, and all
    /// provider Keychain items. A failed or unavailable remote unlink never
    /// prevents local removal, but it is never reported as remotely revoked.
    public func signOut() async throws -> AccountSignOutOutcome {
        let remotelyRevoked: Bool
        let existingSession: SessionCredential?
        do { existingSession = try load(.session) }
        catch { existingSession = nil }
        if let session = existingSession, session.expiresAt > now() {
            do {
                let response = try await authenticatedRequest(path: "/api/device-sessions/unlink", method: "POST", token: session.token)
                remotelyRevoked = response.statusCode == 200 && isVerifiedUnlinkResponse(response.body)
            } catch {
                remotelyRevoked = false
            }
        } else {
            remotelyRevoked = false
        }
        // Do not suppress Keychain failures: callers must know when local
        // state could not be removed, even if the server already revoked it.
        try Key.allCases.forEach { try clear($0) }
        return remotelyRevoked ? .serverRevoked : .localOnly
    }

    public func refreshSession() async throws {
        let session = try requireSession(), response = try await authenticatedRequest(path: "/api/device-sessions/refresh", method: "POST", token: session.token)
        guard response.statusCode == 200 else { try handleAuthenticationFailure(response); throw map(response) }
        let payload = try object(response.body, key: "session"), token = try requiredString(payload, "token", matching: "^[A-Za-z0-9_-]{43,128}$"), expiresAt = try date(requiredString(payload, "expiresAt"))
        guard expiresAt > now() else { throw AccountClientError.invalidResponse }; try save(SessionCredential(token: token, expiresAt: expiresAt), as: .session)
    }

    /// Rechecks an otherwise valid signed lease every 15 minutes while online.
    /// A transport failure may reuse it for five minutes; all other failures
    /// resolve to Free and no result can outlive the signed expiry.
    public func currentEntitlement() async throws -> AccountEntitlement {
        if let cache: LeaseCache = try? load(.lease), let cached = try? verifyEntitlement(cache.compactJWS) {
            let current = now()
            if cache.obtainedAt.addingTimeInterval(15 * 60) > current { return cached }
            if let failedAt = entitlementTransportFailureAt, failedAt.addingTimeInterval(5 * 60) > current { return cached }
            do { return try await refreshEntitlement() }
            catch AccountClientError.networkUnavailable { return cached }
            catch AccountClientError.clockRollback { return AccountEntitlement(plan: "free", managedConnectionLimit: 3, source: .clockRollback) }
            catch { return AccountEntitlement(plan: "free", managedConnectionLimit: 3, source: .unavailable) }
        }
        do { return try await refreshEntitlement() }
        catch AccountClientError.clockRollback { return AccountEntitlement(plan: "free", managedConnectionLimit: 3, source: .clockRollback) }
        catch { return AccountEntitlement(plan: "free", managedConnectionLimit: 3, source: .unavailable) }
    }
    /// Bypasses the normal 15-minute cache freshness and five-minute transport
    /// retry pause. Use this for a deliberate user-initiated plan refresh.
    public func refreshEntitlement() async throws -> AccountEntitlement {
        do {
            let session = try requireSession(), response = try await authenticatedRequest(path: "/api/device-entitlement", method: "GET", token: session.token)
            guard response.statusCode == 200 else { try handleAuthenticationFailure(response); throw map(response) }
            let payload = try object(response.body, key: "entitlement"), lease = try requiredString(payload, "lease", matching: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$")
            let entitlement = try verifyEntitlement(lease)
            // A later response may carry the display email for the first time,
            // or a changed one. It is refreshed, never cleared by an absence.
            if let email = Self.displayEmail(optionalObject(response.body, key: "account")?["email"]) {
                var identity = try requireIdentity()
                if identity.accountEmail != email { identity.accountEmail = email; try save(identity, as: .identity) }
            }
            try save(LeaseCache(compactJWS: lease, obtainedAt: now()), as: .lease)
            entitlementTransportFailureAt = nil
            return entitlement
        } catch AccountClientError.networkUnavailable {
            entitlementTransportFailureAt = now()
            throw AccountClientError.networkUnavailable
        }
    }

    /// BL-075 / D20. Reports this Mac's connections so the account dashboard can
    /// list connected providers per device.
    ///
    /// Three properties, in the order they matter:
    ///
    /// 1. **Nothing secret leaves.** The body is built only from
    ///    `DeviceConnectionReport`, whose six fields are argued field by field
    ///    in that type. There is no parameter here through which a credential,
    ///    a Keychain account, a resource id or an environment name could reach
    ///    the wire.
    /// 2. **It never blocks a local operation.** An unlinked Mac returns
    ///    immediately without a request. A 404 — the route is not deployed yet,
    ///    which is the state of the world as this is written — is silent
    ///    success, not an error the human sees. Everything else throws into a
    ///    caller (`DeviceConnectionMetadataReporter`) that discards it.
    /// 3. **It is an ordinary proof-bound device request.** Same
    ///    `Authorization: Device <token>` and same fresh DPoP proof as
    ///    `GET /api/device-entitlement`; a 401 with a session-invalidating error
    ///    code clears the session exactly as the other routes do.
    public func reportConnections(_ connections: [DeviceConnectionReport]) async throws {
        guard let session = try? requireSession() else { return }
        let bounded = Array(connections.prefix(DeviceConnectionReport.maximumConnections))
        let body = try json(["connections": bounded.map(\.payload)])
        let response = try await authenticatedRequest(path: "/api/device-connections", method: "PUT", token: session.token, body: body)
        // 404 is the route not existing yet. The web lane deploys it under
        // BL-075; until then this call is a no-op that costs one request per
        // connection change and tells the human nothing.
        if response.statusCode == 404 { return }
        guard (200...204).contains(response.statusCode) else {
            try handleAuthenticationFailure(response)
            throw map(response)
        }
    }

    // MARK: - Personal API tokens (BL-085, D30)

    /// Issues one personal API token from this Mac, and hands back its value
    /// exactly once.
    ///
    /// This method exists here, on the actor that holds the device session token
    /// and the Ed25519 device key, because that is the only place a DPoP proof
    /// can be signed without either key or token leaving the type. The
    /// alternative the UI lane refused in BL-086 — reading the device key into
    /// the app target so a settings sheet could sign its own proof — would put a
    /// private key in the UI layer to save one method here.
    ///
    /// Custody of the result:
    ///
    /// - The value is lifted out of the response body byte by byte, into a
    ///   `VaultSecret`, **before** anything parses the document, so
    ///   `JSONSerialization` never materialises it as an unzeroable Swift
    ///   `String` (`APITokenValueExtraction`).
    /// - What comes back is `IssuedAPIToken`: a value-free `APITokenRecord`, and
    ///   a `OneTimeTokenValue` handle that can be spent once.
    /// - Nothing is written anywhere. This method touches no Keychain item, no
    ///   metadata file, no receipt and no log line. The Mac does not need the
    ///   value: it authenticates with its device session.
    ///
    /// - Parameter expiry: `30`, `90`, `365` days, or `.never`.
    public func issueAPIToken(name: String, scopes: [APITokenScope], expiry: APITokenExpiry) async throws -> IssuedAPIToken {
        try checkCancellation()
        let name = try APITokenRequestValidation.name(name)
        let scopes = try APITokenRequestValidation.scopes(scopes)
        let session = try requireLinkedSession()
        var payload: [String: Any] = ["name": name, "scopes": scopes.map(\.rawValue)]
        // Omitted rather than null for "no expiry": both are accepted, and an
        // absent key is the smaller claim.
        if let days = expiry.days { payload["expiresInDays"] = days }
        let body = try json(payload)
        let response = try await sendTokenRequest(path: "/api/tokens", method: "POST", token: session.token, body: body)
        guard response.statusCode == 201 else { throw try tokenFailure(response, route: .mint) }
        guard let extracted = APITokenValueExtraction.extract(from: response.body) else { throw APITokenError.invalidResponse }
        guard let root = try? JSONSerialization.jsonObject(with: extracted.redactedBody) as? [String: Any],
              let object = root["token"] as? [String: Any]
        else { throw APITokenError.invalidResponse }
        let record = try APITokenResponseDecoding.record(object)
        // The value's own id half must be the record's id, so a response cannot
        // hand back one token's metadata beside another token's value.
        guard record.id == extracted.id, record.status == .active, record.revokedAt == nil else { throw APITokenError.invalidResponse }
        // The scopes granted are the scopes asked for. A route that quietly
        // widened them would be a consent failure, and one that quietly narrowed
        // them would make the row a lie.
        guard record.scopes == scopes else { throw APITokenError.invalidResponse }
        switch expiry.days {
        case nil: guard record.expiresAt == nil else { throw APITokenError.invalidResponse }
        case .some: guard record.expiresAt != nil else { throw APITokenError.invalidResponse }
        }
        return IssuedAPIToken(token: record, value: OneTimeTokenValue(secret: extracted.secret, prefix: record.prefix))
    }

    /// Lists this account's tokens: name, prefix, scopes, created, last used and
    /// expiry per row, plus the plan's active-token allowance.
    ///
    /// No value and no hash is in this response, by the route's construction —
    /// its `SELECT` names its columns one at a time and `token_hash` is not among
    /// them — and no record this method returns has anywhere to put one.
    ///
    /// `GET /api/tokens` accepts this Mac's device session as of the BL-086
    /// Worker version, alongside a browser session and a `vlt_` bearer, and
    /// answers all three with the same body. A route that does *not* accept a
    /// device session answers `403 device_session_not_accepted`, which maps to
    /// `.deviceSessionNotAccepted` — a missing route, not a broken link, and
    /// the error says which so an owner is never sent to re-link a linked Mac.
    public func listAPITokens() async throws -> APITokenListing {
        try checkCancellation()
        let session = try requireLinkedSession()
        let response = try await sendTokenRequest(path: "/api/tokens", method: "GET", token: session.token)
        guard response.statusCode == 200 else { throw try tokenFailure(response, route: .list) }
        return try APITokenResponseDecoding.listing(response.body)
    }

    /// Revokes one of this account's tokens. Revocation takes effect on the next
    /// request; there is no cache in front of the check.
    ///
    /// `id` is the 8-character id — not the prefix, and never the value. It is
    /// validated against the route's own pattern before it reaches a URL,
    /// because it becomes part of the path and therefore part of the DPoP
    /// proof's `htu`.
    @discardableResult
    public func revokeAPIToken(id: String) async throws -> RevokedAPIToken {
        try checkCancellation()
        let id = try APITokenRequestValidation.tokenID(id)
        let session = try requireLinkedSession()
        let response = try await sendTokenRequest(path: "/api/tokens/\(id)", method: "DELETE", token: session.token)
        guard response.statusCode == 200 else { throw try tokenFailure(response, route: .revoke) }
        return try APITokenResponseDecoding.revocation(response.body, expecting: id)
    }

    /// One ordinary proof-bound device request, through the same
    /// `authenticatedRequest` every other device route uses: the same
    /// `Authorization: Device <token>` header and one fresh DPoP proof signed by
    /// the enrolled key, with `htm` the exact method and `htu` the exact
    /// absolute URL. Transport failures are translated here so no
    /// `AccountClientError` escapes the token API.
    private func sendTokenRequest(path: String, method: String, token: String, body: Data? = nil) async throws -> AccountHTTPResponse {
        do {
            return try await authenticatedRequest(path: path, method: method, token: token, body: body)
        } catch AccountClientError.networkUnavailable {
            throw APITokenError.networkUnavailable
        } catch AccountClientError.cancelled {
            throw APITokenError.cancelled
        } catch is CancellationError {
            throw APITokenError.cancelled
        } catch {
            throw APITokenError.invalidResponse
        }
    }

    private func requireLinkedSession() throws -> SessionCredential {
        do { return try requireSession() }
        catch { throw APITokenError.notLinked }
    }

    private func checkCancellation() throws {
        do { try Task.checkCancellation() } catch { throw APITokenError.cancelled }
    }

    /// Which of the three token routes answered, because **two codes mean two
    /// different things depending on it**.
    ///
    /// `401 token_predates_mfa` is MF-H1's "the token you presented predates the
    /// factor" everywhere except `POST /api/tokens`, where AS-H1 made it "the
    /// *Mac minting* it predates the factor". `403 insufficient_scope` is "this
    /// credential's scopes do not cover this route" everywhere except the mint,
    /// where AS-H2 made it "a Mac may not mint that scope at all". One status
    /// table with no idea which route it is translating would have to pick one
    /// sentence and be wrong on the other.
    enum TokenRoute {
        case mint
        case list
        case revoke

        var name: String {
            switch self {
            case .mint: "POST /api/tokens"
            case .list: "GET /api/tokens"
            case .revoke: "DELETE /api/tokens/:id"
            }
        }
    }

    /// The contract's status table.
    ///
    /// The one place this does more than translate is `401`: a device error code
    /// means this Mac's own session or proof was refused, so the session and the
    /// cached lease are cleared exactly as they are on every other device route,
    /// and the caller is told to link again. A `401` from the browser-session
    /// verifier means the opposite — the session is fine, the route simply does
    /// not accept it — and clearing anything there would sign a linked Mac out
    /// because a route it cannot use said no.
    private func tokenFailure(_ response: AccountHTTPResponse, route: TokenRoute) throws -> APITokenError {
        let code = errorCode(response.body)
        switch response.statusCode {
        case 400:
            switch code {
            case "invalid_token_name": return .invalidName
            case "invalid_scopes": return .invalidScopes
            case "invalid_expiry": return .invalidExpiry
            case "invalid_token_id": return .invalidTokenID
            default: return .invalidResponse
            }
        case 401:
            // AS-H3. A pending 72-hour closure suspends every credential on the
            // account. Matched **first**, and before the device codes, because
            // it is a fact about the account rather than about this Mac: it must
            // never clear a session that a cancel would bring straight back.
            if code == "account_deletion_pending" { return .accountDeletionPending }
            // BL-076 / MF-H1, and AS-H1 on the mint. A token minted before the
            // account enabled two-factor is refused on every route with a code
            // of its own, because the remedy is specific and cheap: re-create
            // it. On `POST /api/tokens` the same code says the opposite thing
            // about the opposite credential — the Mac was linked first — and
            // "create a new one" would name the act that just failed.
            if code == "token_predates_mfa" { return route == .mint ? .deviceLinkPredatesMfa : .tokenPredatesMfa }
            let deviceCodes = ["invalid_device_session", "device_authentication_required", "dpop_key_mismatch", "invalid_dpop_proof", "dpop_replay_detected"]
            guard let code, deviceCodes.contains(code) else { return .deviceSessionNotAccepted }
            try handleAuthenticationFailure(response)
            return .sessionRejected
        case 403:
            // AS-H2, both halves. On the mint, `insufficient_scope` is a scope
            // no device session may mint; everywhere else it is the ordinary
            // "this credential does not carry what this route needs".
            if code == "insufficient_scope" { return route == .mint ? .scopeNotMintableFromThisMac : .insufficientScope }
            if code == "token_not_issued_by_caller" { return .tokenNotIssuedByCaller }
            return .deviceSessionNotAccepted
        case 404:
            return code == "token_not_found" ? .tokenNotFound : .routeNotDeployed
        case 409:
            return .limitReached
        case 429:
            return .rateLimited
        case 500 ... 599:
            return .serviceUnavailable
        default:
            return .invalidResponse
        }
    }

    private func verifyEntitlement(_ lease: String) throws -> AccountEntitlement {
        let parts = lease.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let headerData = base64URLDecode(String(parts[0])), let payloadData = base64URLDecode(String(parts[1])), let signatureData = base64URLDecode(String(parts[2])), signatureData.count == 64, let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any], header["alg"] as? String == "ES256", header["typ"] as? String == "JWT", header["kid"] as? String == entitlementKey.kid, let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureData) else { throw AccountClientError.invalidEntitlement }
        let input = Data("\(parts[0]).\(parts[1])".utf8)
        guard try pinnedPublicKey().isValidSignature(signature, for: input), let claims = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else { throw AccountClientError.invalidEntitlement }
        let identity = try requireIdentity()
        guard let deviceID = identity.deviceID, let fingerprint = identity.deviceFingerprint, claims["iss"] as? String == origin.absoluteString, audience(claims["aud"]), let subject = claims["sub"] as? String, !subject.isEmpty, let issuedAt = integer(claims["iat"]), let expiresAt = integer(claims["exp"]), let version = integer(claims["entitlement_version"]), version == 1, claims["device_id"] as? String == deviceID, claims["device_fingerprint"] as? String == fingerprint, let plan = claims["plan"] as? String, expiresAt > issuedAt, expiresAt - issuedAt <= 30 * 24 * 60 * 60, issuedAt <= Int(now().timeIntervalSince1970) + 60, identity.accountSubject == nil || identity.accountSubject == subject else { throw AccountClientError.invalidEntitlement }
        let current = Int(now().timeIntervalSince1970)
        if let highWater: ClockWatermark = try load(.clock), current + 300 < highWater.latestEpochSeconds { throw AccountClientError.clockRollback }
        guard expiresAt > current else { throw AccountClientError.invalidEntitlement }
        let paidThrough = claims["paid_through"].flatMap(integer); let limit: Int?
        switch plan {
        case "free": guard claims["max_provider_connections"] as? Int == 3, claims["paid_through"] is NSNull else { throw AccountClientError.invalidEntitlement }; limit = 3
        case "personal": guard claims["max_provider_connections"] is NSNull, let paidThrough, paidThrough >= expiresAt, paidThrough > current else { throw AccountClientError.invalidEntitlement }; limit = nil
        default: throw AccountClientError.invalidEntitlement
        }
        if identity.accountSubject == nil {
            var pinnedIdentity = identity; pinnedIdentity.accountSubject = subject
            try save(pinnedIdentity, as: .identity)
        }
        let retainedWatermark = (try load(.clock) as ClockWatermark?)?.latestEpochSeconds ?? Int.min
        try save(ClockWatermark(latestEpochSeconds: max(retainedWatermark, current, issuedAt)), as: .clock)
        return AccountEntitlement(plan: plan, managedConnectionLimit: limit, leaseExpiresAt: Date(timeIntervalSince1970: TimeInterval(expiresAt)), source: .signedLease)
    }

    private func authenticatedRequest(path: String, method: String, token: String, body: Data? = nil) async throws -> AccountHTTPResponse {
        try await authenticatedRequest(url: try endpoint(path), method: method, token: token, body: body, contentType: "application/json")
    }

    /// **The one place a device request is built and signed.** Every route —
    /// the account reads, the token routes, the twenty remote-approval routes
    /// and BL-102's sixteen vault routes — reaches the network through here, so
    /// there is exactly one construction of the proof to get right.
    private func authenticatedRequest(url: URL, method: String, token: String, body: Data?, contentType: String) async throws -> AccountHTTPResponse {
        var request = URLRequest(url: url); request.httpMethod = method
        request.setValue("Device \(token)", forHTTPHeaderField: "Authorization"); request.setValue(try dpop(url: url, method: method, token: token), forHTTPHeaderField: "DPoP")
        if let body {
            // The DPoP proof binds the method, the absolute URL and the session
            // token hash — not the body. That is the same profile the fixed-body
            // endpoints use, and it is the reason this route may only ever carry
            // facts the server is free to disbelieve. See
            // `blueprint/evidence/core-lane-bl075-contract-2026-09-11.md`.
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        return try await transport.send(request)
    }
    // MARK: - The nine account reads (BL-085 / BL-086, plus BL-076's two)

    /// `GET /api/account` — the account holder's own email, plan and creation
    /// date.
    ///
    /// These nine methods live **here**, in the file that declares the actor,
    /// for a reason that is Swift's rather than a judgement call:
    /// `authenticatedRequest`, `requireSession` and `handleAuthenticationFailure`
    /// are `private`, and a `private` member is reachable only from the
    /// enclosing declaration and from extensions **in the same file**. The UI
    /// lane wrote the extension in a new file, compiled it, quoted the two
    /// errors and removed it
    /// (`blueprint/evidence/ui-lane-settings-live-rows-2026-09-12.md` §3.2). The
    /// alternative — a second credential path that reads the device private key
    /// and the session token out of the Keychain by their raw account names and
    /// re-implements DPoP signing — was refused, because it would duplicate the
    /// signing, duplicate the `401` session-clearing rule, and key on private
    /// implementation details of a file another lane is actively changing. **The
    /// signing stays inside the type that holds the key.**
    ///
    /// Each is the shape `listAPITokens()` already has: require the session, one
    /// `authenticatedRequest`, the status table, a value-free decoded result.
    /// The record types are in `AccountReads.swift`, which holds types only.
    public func fetchAccount() async throws -> AccountProfile {
        try AccountReadDecoding.profile(try await accountRead(path: "/api/account"))
    }

    /// `GET /api/entitlement` — **distinct from `/api/device-entitlement`**,
    /// which is the signed lease this Mac verifies offline and treats as
    /// authority. This one is the account's own view of its plan, for display,
    /// and it is never an authorization input: `refreshEntitlement()` and
    /// `currentEntitlement()` are unchanged and still decide the Free allowance
    /// from the verified lease.
    public func fetchEntitlementSummary() async throws -> AccountEntitlementSummary {
        try AccountReadDecoding.entitlement(try await accountRead(path: "/api/entitlement"))
    }

    /// `GET /api/billing/invoices` — the four most recent live-mode invoices.
    ///
    /// `available == false` is "billing is not configured, or Stripe could not
    /// be reached", **not** "no invoices". Collapsing the two would tell a
    /// paying customer they had never been charged.
    public func listInvoices() async throws -> AccountInvoiceListing {
        try AccountReadDecoding.invoices(try await accountRead(path: "/api/billing/invoices"))
    }

    /// `GET /api/devices` — the first page of the account's devices, this Mac
    /// included.
    ///
    /// **Deliberately not paginated.** The route accepts `cursor` and `limit`
    /// query parameters and this method passes neither, because `endpoint(_:)`
    /// refuses any URL carrying a query — a hardening this file already relies
    /// on, and one worth more than a second page. The route's default page is
    /// twenty; `nextCursor` is decoded and returned so a screen can say plainly
    /// that there are more and send the owner to the web for them, rather than
    /// showing a truncated list as if it were the whole account.
    public func listDevices() async throws -> AccountDeviceListing {
        try AccountReadDecoding.devices(try await accountRead(path: "/api/devices"))
    }

    /// `GET /api/account/connections` — which providers each active device
    /// reports. Value-free display metadata (BL-075); a revoked device keeps no
    /// connections, so this answers "what is connected right now".
    public func listAccountConnections() async throws -> AccountConnectionListing {
        try AccountReadDecoding.connections(try await accountRead(path: "/api/account/connections"))
    }

    /// `GET /api/referrals/me` — **counts only, never the referred accounts.**
    public func fetchReferrals() async throws -> AccountReferralSummary {
        try AccountReadDecoding.referral(try await accountRead(path: "/api/referrals/me"))
    }

    /// `GET /api/activity` — the account's own event list, newest first, capped
    /// at 100 by the route.
    public func listActivity() async throws -> [AccountActivityEvent] {
        try AccountReadDecoding.activity(try await accountRead(path: "/api/activity"))
    }

    /// `GET /api/mfa/status` — BL-076 / D43. **One more path on the profile the
    /// nine reads above already use**, which is the whole of what the contract
    /// asks the Mac to implement: the route is on `DEVICE_ACCOUNT_ROUTES` under
    /// `account:read`, reachable with the same `Authorization: Device <token>`
    /// and the same fresh DPoP proof.
    ///
    /// What the Mac may do with the answer is narrow and is written into
    /// `AccountMfaStatus` rather than left to a caller: show enabled or
    /// disabled, the date, the backup codes left, and the honest
    /// `ready == false` state. It may **not** enrol, verify, disable or
    /// regenerate — all four are browser-session routes that answer
    /// `403 device_session_not_accepted` to a device credential — and it may
    /// not render a step-up, because `stepUp` is always null here and the type
    /// cannot hold one.
    public func fetchMfaStatus() async throws -> AccountMfaStatus {
        try AccountReadDecoding.mfaStatus(try await accountRead(path: "/api/mfa/status"))
    }

    /// `GET /api/account/deletion-request` — MF-C1's ungated status verb, and
    /// **the twelfth route on the device-session allowlist**.
    ///
    /// The UI lane reported it as a contract gap on 2026-09-13: it was
    /// dispatched through `browserAccount`, absent from `DEVICE_ACCOUNT_ROUTES`,
    /// and the Advanced card therefore shipped the honest refusal rather than a
    /// silent "no deletion is pending". The cloud lane put it on the allowlist
    /// under `account:read` for the same reason `GET /api/mfa/status` is there,
    /// so the card is a real read now and the refusal state is back to being
    /// what it always was elsewhere: the generic one, for a Worker that has not
    /// deployed this.
    ///
    /// It is also the **one** route a device credential suspended by AS-H3 may
    /// still reach (`SUSPENSION_EXEMPT_ROUTES` in `src/device.ts`), which is
    /// what lets a Mac whose every other read answers
    /// `401 account_deletion_pending` say *why* instead of looking unlinked.
    ///
    /// `nil` is "nothing pending", which is the ordinary answer.
    public func fetchDeletionRequest() async throws -> AccountDeletionRequest? {
        try AccountReadDecoding.deletionRequest(try await accountRead(path: "/api/account/deletion-request"))
    }

    /// One `authenticatedRequest`, the same status table, and the same
    /// `401`-versus-`403` rule the token routes use.
    ///
    /// **The one place this does more than translate is `401`.** A device error
    /// code means this Mac's own session or proof was refused, so the session
    /// and the cached lease are cleared exactly as they are on every other
    /// device route, and the caller is told to link again. A `401` from the
    /// browser-session verifier means the opposite — the session is fine, the
    /// route simply does not accept it — and clearing anything there would sign
    /// a linked Mac out because a route it cannot use said no.
    private func accountRead(path: String) async throws -> Data {
        do { try Task.checkCancellation() } catch { throw AccountReadError.cancelled }
        let session: SessionCredential
        do { session = try requireSession() } catch { throw AccountReadError.notLinked }
        let response: AccountHTTPResponse
        do {
            response = try await authenticatedRequest(path: path, method: "GET", token: session.token)
        } catch AccountClientError.networkUnavailable {
            throw AccountReadError.networkUnavailable
        } catch AccountClientError.cancelled {
            throw AccountReadError.cancelled
        } catch is CancellationError {
            throw AccountReadError.cancelled
        } catch {
            throw AccountReadError.invalidResponse
        }
        guard response.statusCode == 200 else { throw try accountReadFailure(response) }
        return response.body
    }

    private func accountReadFailure(_ response: AccountHTTPResponse) throws -> AccountReadError {
        let code = errorCode(response.body)
        switch response.statusCode {
        case 401:
            // AS-H3. A pending 72-hour closure suspends every device session and
            // every API token on the account. It is a fact about the *account*,
            // it undoes itself the moment the request is cancelled, and this Mac
            // is still linked — so it is matched first and clears nothing.
            // `GET /api/account/deletion-request` is exempt from the suspension,
            // which is what lets the one read that can explain this still
            // answer while every other read is refused.
            if code == "account_deletion_pending" { return .accountDeletionPending }
            // BL-076 / MF-H1. A refusal of a *credential*, not of a route and
            // not of this Mac's session, so it is separated before the device
            // codes are consulted: it clears nothing, signs nothing out, and
            // must never read as "the route does not accept this Mac".
            if code == "token_predates_mfa" { return .tokenPredatesMfa }
            let deviceCodes = ["invalid_device_session", "device_authentication_required", "dpop_key_mismatch", "invalid_dpop_proof", "dpop_replay_detected"]
            guard let code, deviceCodes.contains(code) else { return .deviceSessionNotAccepted }
            try handleAuthenticationFailure(response)
            return .sessionRejected
        case 403:
            return code == "insufficient_scope" ? .insufficientScope : .deviceSessionNotAccepted
        case 404:
            return .routeNotDeployed
        case 429:
            return .rateLimited
        case 500 ... 599:
            return .serviceUnavailable
        default:
            return .invalidResponse
        }
    }

    /// BL-099 / §6.2. One internal seam for the remote-approval routes.
    ///
    /// It exists so `RemoteApprovalTransport`'s conformance can live beside the
    /// rest of the remote-approval code without loosening four `private`
    /// members of the authentication path. Every remote-approval call goes
    /// through the same `Authorization: Device <token>` header, the same fresh
    /// DPoP proof bound to the exact method and absolute URL, the same pinned
    /// origin, and the same `401` handling that clears a rejected session and
    /// its cached lease — because it goes through the same two functions every
    /// other device route uses.
    func deviceRouteRequest(path: String, method: String, body: Data?, accepting: Set<Int>) async throws -> AccountHTTPResponse {
        try await deviceRouteRequest(path: path, query: [], method: method, body: body, contentType: "application/json", accepting: accepting)
    }

    /// BL-100 slice A / BL-102's sixteen routes. **The same seam, widened by
    /// exactly two things and by nothing else.**
    ///
    /// The vault routes are device routes like every other: same session, same
    /// fresh DPoP proof bound to the exact method and absolute URL, same pinned
    /// origin, same `401` handling. Two of their shapes had no precedent here
    /// and each is deliberately narrow:
    ///
    ///  - **A query string.** Three vault routes take one — `…/heads?from=`,
    ///    `…/records?generation=&after=`, `…/recovery-envelope?generation=` —
    ///    and `endpoint(_:)` refuses a URL that has one, because every route
    ///    before this one carried its arguments in the path or the body. The
    ///    query becomes part of `htu` and therefore part of the signed proof,
    ///    so it is built here from validated items rather than pasted into a
    ///    path, and `queriedEndpoint` re-checks the result the way
    ///    `approvalURL` re-checks its own.
    ///  - **A non-JSON body.** §8 item 3: *"the blob uploads as-is, it is
    ///    already ciphertext"*, so the blob put sends raw octets. The header is
    ///    a parameter rather than a second request builder, because a second
    ///    builder is a second place for the proof to be got wrong.
    func deviceRouteRequest(
        path: String,
        query: [URLQueryItem],
        method: String,
        body: Data?,
        contentType: String,
        accepting: Set<Int>
    ) async throws -> AccountHTTPResponse {
        try Task.checkCancellation()
        let session = try requireSession()
        let url = try queriedEndpoint(path, query: query)
        let response = try await authenticatedRequest(url: url, method: method, token: session.token, body: body, contentType: contentType)
        try handleAuthenticationFailure(response)
        guard accepting.contains(response.statusCode) else { throw map(response) }
        return response
    }

    /// `endpoint(_:)` when there is no query, and a re-checked `URLComponents`
    /// build when there is.
    ///
    /// The names are ASCII letters and the values are lowercase hex, digits and
    /// the hyphen — which is every value a vault route takes: a 64-hex digest, a
    /// 32-hex `wireID`, a generation counter, a canonical lowercase UUID.
    /// Nothing in that set percent-encodes, and that is the point: a value that
    /// would need encoding is refused instead, so the signed `htu` and the sent
    /// URL cannot differ.
    private func queriedEndpoint(_ path: String, query: [URLQueryItem]) throws -> URL {
        guard !query.isEmpty else { return try endpoint(path) }
        try requireSupportedOrigin()
        guard path.hasPrefix("/api/"), !path.contains("?"), !path.contains("#"), query.count <= 4, let host = origin.host else {
            throw AccountClientError.invalidResponse
        }
        for item in query {
            guard item.name.range(of: "^[a-zA-Z]{1,32}$", options: .regularExpression) != nil,
                  let value = item.value, value.range(of: "^[0-9a-z-]{1,64}$", options: .regularExpression) != nil
            else { throw AccountClientError.invalidResponse }
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.path = path
        components.queryItems = query
        guard let url = components.url, url.scheme == "https", url.host == host, url.path == path,
              url.fragment == nil, url.user == nil, url.password == nil,
              URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems == query
        else { throw AccountClientError.invalidResponse }
        return url
    }

    private func dpop(url: URL, method: String, token: String) throws -> String {
        let identity = try requireIdentity(), privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: identity.privateKey)
        let header: [String: Any] = ["typ": "dpop+jwt", "alg": "EdDSA", "jwk": ["kty": "OKP", "crv": "Ed25519", "x": identity.publicJWK.x]]
        let payload: [String: Any] = ["jti": try randomBase64URL(bytes: 16), "htm": method, "htu": Self.htu(url), "iat": Int(now().timeIntervalSince1970), "ath": base64URL(SHA256.hash(data: Data(token.utf8)))]
        let protected = base64URL(try json(header)), claims = base64URL(try json(payload)), message = Data("\(protected).\(claims)".utf8)
        return "\(protected).\(claims).\(base64URL(try privateKey.signature(for: message)))"
    }
    /// **RFC 9449 §4.2: `htu` is the target URI without its query and its
    /// fragment**, which is exactly what the Worker's own `normalizedHtu`
    /// computes — `url.search = ""; url.hash = ""`.
    ///
    /// This used to be `url.absoluteString`, and it agreed with the Worker for
    /// every route that existed: `endpoint(_:)` refuses a URL with a query, so
    /// no device request had ever carried one. BL-100 slice A's transport is the
    /// first to send three that do, and recording them against the shipped
    /// dispatcher is what found it — a `401 invalid_dpop_proof` on
    /// `GET …/heads?from=`.
    ///
    /// **What the query is therefore not bound by** is stated rather than
    /// glossed: the three vault routes that take one carry a cursor, a
    /// generation counter and a recipient id — selectors, never authorizations —
    /// and what authorizes is the session, the `kind` gate and the route table.
    /// A party that could rewrite a query in flight is the relay, which chooses
    /// what to serve anyway.
    static func htu(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return url.absoluteString }
        components.query = nil
        components.fragment = nil
        return components.url?.absoluteString ?? url.absoluteString
    }

    private func sendJSON(path: String, body: [String: Any]) async throws -> AccountHTTPResponse { var request = URLRequest(url: try endpoint(path)); request.httpMethod = "POST"; request.setValue("application/json", forHTTPHeaderField: "Content-Type"); request.httpBody = try json(body); return try await transport.send(request) }
    private func endpoint(_ path: String) throws -> URL { try requireSupportedOrigin(); guard path.hasPrefix("/api/"), let url = URL(string: path, relativeTo: origin)?.absoluteURL, url.scheme == "https", url.host == origin.host, url.query == nil, url.fragment == nil else { throw AccountClientError.invalidResponse }; return url }
    /// Built here, from the pinned origin and a code that has already been
    /// matched against the server's own alphabet, so the only variable part of
    /// the URL is eight characters from a 32-symbol set. The result is
    /// re-checked afterwards: https, the pinned host, the fixed path, exactly
    /// one `code` query item and no fragment. A code that fails the charset
    /// check never reaches a URL at all.
    ///
    /// BL-096 slice 2c. **Public**, because the phone's enrolment needs the
    /// same URL under the same re-checks: it is the one-click BL-075 card, the
    /// fallback an automatic approval falls back *to* when the
    /// `vaultage://link/<id>?proof=…` return never lands on the device that
    /// started the sign-in. A second builder on the phone would be a second
    /// place the card's origin, path and code alphabet could drift.
    public static func approvalURL(origin: URL, userCode: String) throws -> URL {
        guard let host = origin.host, origin.scheme == "https",
              userCode.range(of: "^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$", options: .regularExpression) != nil
        else { throw AccountClientError.invalidResponse }
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.path = Self.linkPath
        components.queryItems = [URLQueryItem(name: "code", value: userCode)]
        guard let url = components.url, url.scheme == "https", url.host == host, url.path == Self.linkPath,
              url.fragment == nil, url.user == nil, url.password == nil,
              URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems == [URLQueryItem(name: "code", value: userCode)]
        else { throw AccountClientError.invalidResponse }
        return url
    }

    /// BL-113 (D47) — the page the sign-in screen opens.
    ///
    /// `approvalURL` plus one more query item, `next`, carrying the
    /// `vaultage://link/<id>` target so the dashboard can hand control back to
    /// this app the moment the sign-in it started is approved. Built the way
    /// `approvalURL` is built — from the pinned origin, a code already matched
    /// against the server's alphabet, and a target already re-checked by
    /// `DeviceLinkReturn` — and re-checked afterwards: https, the pinned host,
    /// the fixed path, exactly these two query items in this order, no
    /// fragment. Nothing a server said reaches it.
    public static func signInURL(origin: URL, userCode: String, returnTarget: URL, method: SignInMethod? = nil) throws -> URL {
        let approval = try approvalURL(origin: origin, userCode: userCode)
        guard let host = approval.host,
              DeviceLinkReturn.authorizationID(in: returnTarget) != nil
        else { throw AccountClientError.invalidResponse }
        // D59: `method` is the third item, present only when the app chose one;
        // its value is one of two compiled words, never text from anywhere else.
        var expected = [URLQueryItem(name: "code", value: userCode), URLQueryItem(name: "next", value: returnTarget.absoluteString)]
        if let method { expected.append(URLQueryItem(name: "method", value: method.rawValue)) }
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.path = Self.linkPath
        components.queryItems = expected
        guard let url = components.url, url.scheme == "https", url.host == host, url.path == Self.linkPath,
              url.fragment == nil, url.user == nil, url.password == nil, url.port == nil,
              URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems == expected
        else { throw AccountClientError.invalidResponse }
        return url
    }

    /// A display email is optional, bounded, and never trusted as identity: the
    /// pinned account subject in the signed entitlement lease is what decides
    /// whether this Mac still belongs to the same account. An absent, oversized
    /// or malformed value is simply not shown.
    static func displayEmail(_ value: Any?) -> String? {
        guard let value = value as? String else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.utf8.count <= 254,
              trimmed.range(of: "^[^@\\s]{1,64}@[^@\\s.]+(\\.[^@\\s.]+)+$", options: .regularExpression) != nil
        else { return nil }
        return trimmed
    }

    private func safeVerificationURL(_ string: String) throws -> URL { guard let url = URL(string: string), url.scheme == "https", url.host == origin.host, url.path == Self.linkURL.path, url.query == nil, url.fragment == nil else { throw AccountClientError.invalidResponse }; return url }
    private func requireSupportedOrigin() throws { guard origin.scheme == "https", origin.host == Self.origin.host, origin.path.isEmpty, origin.query == nil, origin.fragment == nil else { throw AccountClientError.invalidResponse } }
    private func requireIdentity() throws -> DeviceIdentity { guard let value: DeviceIdentity = try load(.identity) else { throw AccountClientError.accountNotLinked }; return value }

    /// BL-099 / §2.2. This Mac's `sig` role, as the remote-approval protocol
    /// names it: the shipped Ed25519 device key, unchanged, projected as its
    /// **RFC 7638 thumbprint** and the control-plane device id.
    ///
    /// This is deliberately not `deviceFingerprint`, which is the first sixteen
    /// characters of a SHA-256 over the same JWK (`device.ts:224`) and exists to
    /// be read aloud during linking. The pairing ceremony and every pin record
    /// use the full thumbprint, because the pin is the authority and a truncated
    /// identifier is a weaker one for no benefit.
    ///
    /// Nothing here exposes the private key: `DeviceIdentity` stays private and
    /// the projection is a hash of a public point.
    public func remoteApprovalSigIdentity() throws -> MacSigIdentity {
        let identity = try requireIdentity()
        guard let x = RemoteBase64URL.decode(identity.publicJWK.x) else { throw AccountClientError.invalidResponse }
        return MacSigIdentity(
            deviceID: identity.deviceID,
            deviceName: identity.deviceName,
            accountSubject: identity.accountSubject,
            sigThumbprint: RemoteDeviceKeyThumbprint.ed25519(x: x)
        )
    }
    private func requireSession() throws -> SessionCredential { guard let value: SessionCredential = try load(.session), value.expiresAt > now() else { throw AccountClientError.accountNotLinked }; return value }
    private func loadOrCreateIdentity(deviceName: String?) throws -> DeviceIdentity {
        if let existing: DeviceIdentity = try load(.identity) { return existing }
        let key = Curve25519.Signing.PrivateKey(), name = normalizedName(deviceName)
        let result = DeviceIdentity(installationID: "mac-\(UUID().uuidString.lowercased())", deviceName: name, privateKey: key.rawRepresentation, publicJWK: DevicePublicJWK(x: base64URL(key.publicKey.rawRepresentation)), deviceID: nil, deviceFingerprint: nil)
        try save(result, as: .identity); return result
    }
    /// **BL-096 slice 1.** `Host` is macOS-only Foundation. It is a *default* —
    /// every caller that has a name passes one, and the phone always does
    /// (§3.7's enrolment screen asks for it) — so a platform with no `Host`
    /// takes the same fallback an unnamed Mac already takes. No macOS
    /// behaviour changes.
    private func defaultDeviceName() -> String? {
        #if canImport(AppKit)
        return Host.current().localizedName
        #else
        return nil
        #endif
    }
    private func normalizedName(_ requested: String?) -> String { let candidate = (requested ?? defaultDeviceName() ?? "This Mac").trimmingCharacters(in: .whitespacesAndNewlines); return String((candidate.isEmpty ? "This Mac" : candidate).prefix(96)) }
    private func deviceFingerprint(_ key: DevicePublicJWK) -> String {
        // `x` is base64url from the locally generated key, so it contains no
        // JSON-significant characters. Preserve this key order for Worker JS.
        let canonical = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"\(key.x)\"}"
        return String(base64URL(SHA256.hash(data: Data(canonical.utf8))).prefix(16)).uppercased()
    }
    private func schedulePending(_ pending: PendingLink, after delay: TimeInterval) throws -> AccountLinkPoll { var value = pending; value.nextPollAt = now().addingTimeInterval(delay); try save(value, as: .pending); return .pending(nextPollAt: value.nextPollAt) }
    private func handleAuthenticationFailure(_ response: AccountHTTPResponse) throws { guard response.statusCode == 401 else { return }; if ["invalid_device_session", "device_authentication_required", "dpop_key_mismatch", "invalid_dpop_proof", "dpop_replay_detected"].contains(errorCode(response.body)) { try clear(.session); try clear(.lease) } }
    // BL-113 follow-up. `slow_down`/`rate_limited` used to fall into
    // `.networkUnavailable`, which is how a busy creation budget across
    // builds 5, 6 and 7 became "Vaultage could not reach your account" —
    // this Mac was reached and answered, so that was never true. The offline
    // card is left for transport failures and 5xx (`.networkUnavailable` and
    // `.serviceUnavailable`, both handled elsewhere in this function).
    private func map(_ response: AccountHTTPResponse) -> AccountClientError { switch errorCode(response.body) { case "authorization_pending": .authorizationPending; case "authorization_expired": .authorizationExpired; case "authorization_consumed": .authorizationConsumed; case "authorization_revoked", "invalid_device_session", "device_authentication_required", "dpop_key_mismatch": .authorizationRevoked; case "integration_not_configured", "entitlement_unavailable", "authorization_unavailable": .serviceUnavailable; case "slow_down", "rate_limited": .rateLimited(retryAfterSeconds: retryAfterSeconds(response.body)); default: response.statusCode >= 500 ? .serviceUnavailable : .invalidResponse } }
    private func errorCode(_ body: Data) -> String? { (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["error"] as? String }
    private func isVerifiedUnlinkResponse(_ body: Data) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any], object.count == 1,
              let value = object["revoked"] as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return false }
        return value.boolValue
    }
    private func retryDelay(_ body: Data) -> TimeInterval? { (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["intervalSeconds"] as? TimeInterval }
    /// BL-113 follow-up. The creation route's own accounting of what is left
    /// of its window, present only on the `rate_limited`/`slow_down` bodies
    /// that carry it. Read the same defensive way `retryDelay` reads
    /// `intervalSeconds`: absent or malformed simply means "not offered".
    private func retryAfterSeconds(_ body: Data) -> TimeInterval? { (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["retryAfterSeconds"] as? TimeInterval }
    private func audience(_ value: Any?) -> Bool { value as? String == "vaultage-device" }
    private func integer(_ value: Any?) -> Int? { if let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() { return number.intValue }; return nil }
    private func pinnedPublicKey() throws -> P256.Signing.PublicKey { guard let x = base64URLDecode(entitlementKey.x), let y = base64URLDecode(entitlementKey.y), x.count == 32, y.count == 32 else { throw AccountClientError.invalidEntitlement }; return try P256.Signing.PublicKey(x963Representation: Data([0x04]) + x + y) }
    private func optionalObject(_ data: Data, key: String) -> [String: Any]? { (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?[key] as? [String: Any] }
    private func object(_ data: Data, key: String) throws -> [String: Any] { guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], let value = root[key] as? [String: Any] else { throw AccountClientError.invalidResponse }; return value }
    private func requiredString(_ object: [String: Any], _ key: String, matching expression: String? = nil) throws -> String { guard let value = object[key] as? String, !value.isEmpty, value.utf8.count <= 4096 else { throw AccountClientError.invalidResponse }; if let expression, let range = value.range(of: expression, options: .regularExpression), range == value.startIndex..<value.endIndex {} else if expression != nil { throw AccountClientError.invalidResponse }; return value }
    private func requiredNumber(_ object: [String: Any], _ key: String) throws -> TimeInterval { guard let value = object[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { throw AccountClientError.invalidResponse }; return value.doubleValue }
    /// The Worker writes timestamps with JavaScript's `Date.toISOString()`, which
    /// always carries fractional seconds (`2026-09-13T20:37:54.491Z`); the plain
    /// `ISO8601DateFormatter()` refuses those, which made every live link fail
    /// right after the mint with `invalidResponse` (found in the owner's build-6
    /// QA on 2026-09-14). Both shapes are accepted; anything else is refused.
    private func date(_ value: String) throws -> Date {
        let fractional = ISO8601DateFormatter(); fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) { return date }
        if let date = ISO8601DateFormatter().date(from: value) { return date }
        throw AccountClientError.invalidResponse
    }
    private func json(_ value: Any) throws -> Data { guard JSONSerialization.isValidJSONObject(value) else { throw AccountClientError.invalidResponse }; return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
    private func base64URL(_ bytes: some Sequence<UInt8>) -> String { Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    private func base64URLDecode(_ string: String) -> Data? { guard !string.isEmpty, string.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }; return Data(base64Encoded: string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - string.count % 4) % 4)) }
    private func randomBase64URL(bytes: Int) throws -> String {
        var data = Data(count: bytes)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }
        guard status == errSecSuccess else { throw AccountClientError.serviceUnavailable }
        return base64URL(data)
    }
    private func load<T: Decodable>(_ key: Key) throws -> T? { guard let data = try store.data(for: key.rawValue) else { return nil }; do { return try JSONDecoder().decode(T.self, from: data) } catch { throw AccountClientError.invalidResponse } }
    private func save<T: Encodable>(_ value: T, as key: Key) throws { try store.save(try JSONEncoder().encode(value), account: key.rawValue) }
    private func clear(_ key: Key) throws { try store.remove(account: key.rawValue) }

    private enum Key: String, CaseIterable { case identity = "device-identity", session = "device-session", pending = "pending-link", lease = "entitlement-lease", clock = "clock-watermark" }
    private struct DevicePublicJWK: Codable, Sendable {
        let kty: String; let crv: String; let x: String
        init(x: String) { self.kty = "OKP"; self.crv = "Ed25519"; self.x = x }
    }
    private struct DeviceIdentity: Codable, Sendable { let installationID: String; let deviceName: String; let privateKey: Data; let publicJWK: DevicePublicJWK; var deviceID: String?; var deviceFingerprint: String?; var accountSubject: String? = nil; var accountEmail: String? = nil }
    private struct SessionCredential: Codable, Sendable { let token: String; let expiresAt: Date }
    // BL-113 follow-up. `userCode` and `verificationURL` are what let
    // `reusedChallenge` rebuild the exact challenge `startLink` first
    // returned, without asking the Worker again. A record saved by a build
    // before this change decodes to nil (`load` throws, and `startLink`'s
    // `try?` treats that as "no pending link") rather than crashing, so an
    // in-flight link across an app update falls back to one fresh mint.
    // BL113-C1. `returnProof` is optional in every sense: absent on a fresh
    // mint, absent for a manual approval, and absent from a record saved by a
    // build before this change — a synthesized `Codable` decodes a missing
    // optional as nil, so an in-flight link across an app update keeps working
    // and simply falls back to the approval card if it was approved
    // automatically. It is never logged and never leaves this actor except in
    // the exchange request body.
    private struct PendingLink: Codable, Sendable { let requestID: String; let pollingSecret: String; let pkceVerifier: String; let expiresAt: Date; let interval: TimeInterval; var nextPollAt: Date; let deviceName: String; let userCode: String; let verificationURL: URL; var returnProof: String? = nil; var method: String? = nil }
    private struct LeaseCache: Codable, Sendable { let compactJWS: String; let obtainedAt: Date }
    private struct ClockWatermark: Codable, Sendable { let latestEpochSeconds: Int }
}
