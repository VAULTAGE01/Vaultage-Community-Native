import Foundation

/// BL-099 slice 2 step (c) — **`refreshRoster()` and §4.3 check 4's 24-hour
/// rule.**
///
/// The roster is the only part of §4.3 that reaches the network, and it is the
/// part most easily turned into a denial. Version 5 said a decision was accepted
/// only if the refresh "succeeded and was within 300 s", which handed the relay
/// its cheapest attack: answer `503` on the entitlement route and every Mac
/// reads it as **its own** failure and refuses every remote decision. Check 4 is
/// now stated the other way round, and this type is what makes that statement
/// true rather than aspirational:
///
/// > Refuse **only** if (a) none was ever seen, (b) `roster_issued_at` moved
/// > backwards, or (c) the cached one is older than **24 h**. **A
/// > `refreshRoster()` failure is not a refusal.**
public struct RemoteRoster: Codable, Hashable, Sendable {
    /// The server's own issue time. Monotonic per account: it may stand still,
    /// it may move forward, it may never move back.
    public let issuedAt: Date
    public let digest: String
    /// The device ids the account currently lists as active. **Check 2 does not
    /// read this** — a locally-unpaired device is refused against a fresh,
    /// valid roster that still lists it as active — and that is the whole point
    /// of the pin being the control.
    public let activeDeviceIDs: [String]
    /// The full rows, each with §2.3's `keys: [{ role, jwk, thumbprint }]`.
    ///
    /// **The only channel in this protocol that carries key bytes**, and
    /// therefore the only implementable source for what §2.4's pin record must
    /// store — see `RemoteRosterKeys.swift`, which is also where the two
    /// verifications live. Empty for a caller that has only the digest and the
    /// issue time; `RemoteRoster.decode` is what fills it.
    ///
    /// Carrying the keys changes nothing about their authority: §2.3's *"No key
    /// is ever used because the roster contains it"* is enforced by
    /// `RemoteDevicePairingPolicy.pin(fromRoster:)`, which admits an entry only
    /// against the thumbprints the QR and the SAS bound.
    public let devices: [RemoteRosterDevice]

    public init(issuedAt: Date, digest: String, activeDeviceIDs: [String], devices: [RemoteRosterDevice] = []) {
        self.issuedAt = issuedAt
        self.digest = digest
        self.activeDeviceIDs = activeDeviceIDs
        self.devices = devices
    }
}

/// What `refreshRoster()` needs from the network.
public protocol RemoteRosterSource: Sendable {
    /// `GET /api/device-entitlement`, which already carries the roster.
    func fetchRoster() async throws -> RemoteRoster
}

/// What one refresh attempt did. Recorded rather than thrown, because **the
/// caller must not be able to turn a failure into a refusal by mistake**: there
/// is no `throws` on `refreshRoster()` to catch and re-raise.
public enum RemoteRosterRefreshOutcome: Equatable, Sendable {
    /// A newer roster was stored.
    case refreshed
    /// The fetch was skipped because the last one was inside the 300-second
    /// fetch cache. Not a failure and not a refusal.
    case coalesced
    /// The server answered with an `issuedAt` **older** than the watermark.
    /// This is check 4's case (b) and it is the one refresh result that *is*
    /// a refusal — a roster that moves backwards is a rollback, not a hiccup.
    case regressed
    /// The network failed, the body did not parse, or the route answered an
    /// error. **The cached roster stands and nothing is refused.**
    case unavailable(String)
}

/// `refreshRoster()`, its own 300-second fetch cache, and the monotonic
/// `roster_issued_at` watermark.
public actor RemoteRosterRefresher {
    /// Its **own** cache, distinct from the 24-hour staleness rule and from the
    /// entitlement plan cache. Version 5 conflated all three.
    public static let fetchCacheSeconds: TimeInterval = 300

    private let source: RemoteRosterSource
    private var cache: RemoteRosterCache?
    private var watermark: Date?
    private var lastAttemptAt: Date?
    private var consecutiveFailures = 0

    public init(source: RemoteRosterSource, cache: RemoteRosterCache? = nil, watermark: Date? = nil) {
        self.source = source
        self.cache = cache
        self.watermark = watermark
    }

    /// What check 4 reads. Never `nil` because of a failed refresh — only
    /// because none was ever seen.
    public var cached: RemoteRosterCache? { cache }
    public var issuedAtWatermark: Date? { watermark }
    public var failuresSinceLastSuccess: Int { consecutiveFailures }

    /// **Cannot refuse anything.** It returns an outcome and leaves the cache
    /// at least as good as it found it.
    @discardableResult
    public func refreshRoster(now: Date = Date(), force: Bool = false) async -> RemoteRosterRefreshOutcome {
        if !force, let last = lastAttemptAt, now.timeIntervalSince(last) < Self.fetchCacheSeconds {
            return .coalesced
        }
        lastAttemptAt = now
        let roster: RemoteRoster
        do { roster = try await source.fetchRoster() }
        catch {
            consecutiveFailures += 1
            // The cache is **not** cleared and the watermark is **not** moved.
            // A relay that can fail this call can only stop it improving.
            return .unavailable("\(error)")
        }
        consecutiveFailures = 0
        if let watermark, roster.issuedAt < watermark {
            // Check 4 case (b). The cache keeps its previous content — the old
            // roster is still the newest thing this Mac ever legitimately saw —
            // but it is flagged, and check 4 refuses on the flag.
            cache = cache.map { RemoteRosterCache(issuedAt: $0.issuedAt, fetchedAt: $0.fetchedAt, digest: $0.digest, issuedAtRegressed: true) }
                ?? RemoteRosterCache(issuedAt: roster.issuedAt, fetchedAt: now, digest: roster.digest, issuedAtRegressed: true)
            return .regressed
        }
        watermark = max(watermark ?? roster.issuedAt, roster.issuedAt)
        cache = RemoteRosterCache(issuedAt: roster.issuedAt, fetchedAt: now, digest: roster.digest, issuedAtRegressed: cache?.issuedAtRegressed ?? false)
        return .refreshed
    }

    /// Check 4's three conditions, in one place, so nothing else has to restate
    /// them.
    public func rosterRefusal(now: Date = Date()) -> RemoteRefusalReason? {
        guard let cache else { return .rosterUnavailable }              // (a)
        if cache.issuedAtRegressed { return .rosterUnavailable }        // (b)
        if now.timeIntervalSince(cache.fetchedAt) > RemoteRosterCache.stalenessSeconds { return .rosterUnavailable }  // (c)
        return nil
    }
}
