import Foundation

// BL-117 (D51) — Rule C's cache.
//
// `blueprint/design/credential-classes-spec.md` version 2 §2.3 is the normative
// page, and the rule it states is the one thing that bounds this cache:
//
// > **Rule C — a cached token never outlives the presence that produced it.**
// >
// > A cache entry is **keyed on `(connectionID, approvedActionID)`** and expires
// > at the **earliest** of: (a) the provider's own `expires_in`; (b) **30
// > seconds** past the last approved request of the action that minted it,
// > which covers a paginating operation; (c) the expiry **or the revocation**
// > of the D6/D19 grant, when the action ran under one; (d) a Vaultage absolute
// > ceiling of **120 seconds**. It is dropped on screen lock, on sleep, on
// > sign-out, on revoke, on reconnect, on broker restart, and on invalidation
// > of the `OwnerAuthentication` for that account.
//
// **Why the key is a pair.** A cached access token means the second, third and
// hundredth provider call inside its lifetime read no vault value and therefore
// cost no presence proof, and property 6 says *"reading a credential still costs
// a presence proof for that credential, on every path Vaultage itself takes"*.
// Keying on the connection alone would convert one presence proof per action
// into one per hour — Microsoft's own `expires_in` is 3599. Keying on the
// **action** as well is what makes the consequence statable: an owner approving
// each action one at a time pays exactly what they pay today, and an owner who
// granted a seven-day auto-allow already accepted a presence relaxation of that
// size for that agent and those projects (D6). The cache's window is always a
// window the owner already opened.
//
// **(b) and (d) are compiled constants and never manifest fields**, because a
// manifest field is onboarding-editable and runbook §10 item 2 forbids exactly
// that. The numbers are the product's own precedents rather than invented: 120 s
// is twice `OwnerAuthentication.lifetime` and four times the 30 s a
// `BatchToken`'s evaluated context is capped at, so a cached token is never the
// longest-lived presence-derived thing in the product.
//
// **§2.2a rests on clause (b), and says so.** A short-lived access token is not
// in BL-074's creation class because it *cannot be used elsewhere* — and the
// only reason that is true is that the cache will hand it back to the action
// whose id keys it and to nothing else. A builder who loosens (b) has silently
// moved the exchange into BL-074's class, which is a native-only approval in
// front of every ordinary read on Azure and Google Cloud.
//
// **Broker memory only, never persisted.** There is no `Codable` conformance on
// anything here, the token is a `VaultSecret` (which has none either), and the
// cache declares **no path** under the broker's container — which is exactly
// what `13-MULTI-DEVICE-CUSTODY.md` §10's manifest row for the list projection
// says the container walk exists to catch: *"memory only; declaring a path for
// it is the failure the manifest exists to catch."* `TokenExchangeCacheContracts`
// runs that shape against this cache.

/// What one cache entry is keyed on. Both halves are required: a connection
/// without an action is a token any later action could reach, and an action
/// without a connection is a token from the wrong provider.
public struct ExchangedTokenKey: Hashable, Sendable {
    public let connectionID: UUID
    /// The id of the **approved action** the exchange ran inside. It is the
    /// broker's own invocation id, minted per approved request, so it is never
    /// reachable from a second action even within the same connection.
    public let approvedActionID: UUID

    public init(connectionID: UUID, approvedActionID: UUID) {
        self.connectionID = connectionID
        self.approvedActionID = approvedActionID
    }
}

/// Why a cached token was dropped. The list is Rule C's own, enumerated so the
/// contract suite can assert every member drops and none is missing.
public enum ExchangedTokenDropReason: String, Sendable, CaseIterable, Hashable {
    case screenLock
    case sleep
    case signOut
    case revoke
    case reconnect
    case brokerRestart
    /// §2.3's last clause and the one most easily forgotten: the
    /// `OwnerAuthentication` for that account being invalidated. A cached token
    /// derived from a presence proof that no longer exists is exactly what
    /// Rule C is named for.
    case ownerAuthenticationInvalidated
}

/// Rule C's cache. One per broker; there is no second instance and no way to
/// construct one with different numbers.
public actor TokenExchangeCache {

    /// Rule C clause **(d)**. Compiled, never a manifest field.
    public static let absoluteCeiling: TimeInterval = 120
    /// Rule C clause **(b)**. Compiled, never a manifest field.
    public static let graceAfterLastRequest: TimeInterval = 30

    private struct Entry {
        let token: VaultSecret
        /// The earliest of (a), (c) and (d), fixed when the entry was stored.
        let hardExpiry: Date
        /// Clause (b): 30 s past the **last** approved request of this action,
        /// so it moves forward on each use and a paginating operation is
        /// covered without the ceiling ever moving.
        var graceExpiry: Date

        func isLive(at now: Date) -> Bool { now < hardExpiry && now < graceExpiry }
    }

    private var entries: [ExchangedTokenKey: Entry] = [:]

    /// Audit M-07. The most entries the cache holds. An action mints at most
    /// one token, and a token dies with its action (`dropAction`), so a cache
    /// anywhere near this size is a broker with that many actions in flight.
    /// The bound is what keeps a stuck caller from turning the cache into a
    /// retention of minted tokens.
    public static let maximumEntries = 32

    public init() {}

    /// Audit M-07. Removes every entry that is no longer live at `now`. Runs
    /// on every store, so an entry nobody asks for again does not wait for a
    /// same-key lookup to expire.
    @discardableResult
    public func sweep(now: Date = Date()) -> Int {
        let dead = entries.filter { !$0.value.isLive(at: now) }.map(\.key)
        for key in dead { entries[key] = nil }
        return dead.count
    }

    /// The cached token for this key, or nil.
    ///
    /// A hit slides clause (b) forward — *30 seconds past the last approved
    /// request of the action* — and cannot slide (a), (c) or (d), which were
    /// fixed when the entry was stored. That asymmetry is the whole of why a
    /// paginating operation works and an hour-long one does not.
    public func token(for key: ExchangedTokenKey, now: Date = Date()) -> VaultSecret? {
        guard var entry = entries[key] else { return nil }
        guard entry.isLive(at: now) else {
            entries[key] = nil
            return nil
        }
        entry.graceExpiry = now.addingTimeInterval(Self.graceAfterLastRequest)
        entries[key] = entry
        return entry.token
    }

    /// Stores a freshly minted token under Rule C's four clauses.
    ///
    /// - Parameters:
    ///   - providerExpiresIn: clause (a), the provider's own lifetime.
    ///   - grantExpiry: clause (c), the expiry or revocation instant of the
    ///     D6/D19 grant the action ran under, or nil when it ran under a sheet.
    public func store(
        _ token: VaultSecret,
        for key: ExchangedTokenKey,
        providerExpiresIn: Int,
        grantExpiry: Date? = nil,
        now: Date = Date()
    ) {
        // The **earliest** of the three fixed clauses. Written as a reduction
        // over the candidates rather than as nested `min` calls, so adding a
        // clause is adding a row and a reader can see there is no path that
        // takes a maximum by accident.
        var candidates = [
            now.addingTimeInterval(TimeInterval(providerExpiresIn)),
            now.addingTimeInterval(Self.absoluteCeiling)
        ]
        if let grantExpiry { candidates.append(grantExpiry) }
        let hardExpiry = candidates.min() ?? now
        // Audit M-07. Dead entries go first; if the cache is still full, the
        // entry that would have expired soonest goes, so the bound never
        // refuses a store and never keeps a token past a live one's turn.
        sweep(now: now)
        while entries.count >= Self.maximumEntries, let soonest = entries.min(by: { $0.value.hardExpiry < $1.value.hardExpiry }) {
            entries[soonest.key] = nil
        }
        entries[key] = Entry(
            token: token,
            hardExpiry: hardExpiry,
            graceExpiry: now.addingTimeInterval(Self.graceAfterLastRequest)
        )
    }

    /// Rule C's drop list. Every reason drops **everything**: a screen lock, a
    /// sleep, a sign-out or a broker restart is not per-connection, and
    /// narrowing any of them would be a judgement this type is not the place to
    /// make.
    ///
    /// - Returns: how many entries were dropped, so a caller and the suite can
    ///   both see the drop happened rather than trusting that it did.
    @discardableResult
    public func dropAll(_ reason: ExchangedTokenDropReason) -> Int {
        let dropped = entries.count
        entries.removeAll()
        return dropped
    }

    /// The two reasons that **are** per-connection: a revoke and a reconnect
    /// name one connection, and dropping the rest would be a denial of service
    /// the rule does not ask for. `dropAll` still accepts them, because a
    /// caller that does not know which connection is affected must be able to
    /// drop everything.
    @discardableResult
    public func drop(connectionID: UUID, reason: ExchangedTokenDropReason) -> Int {
        let doomed = entries.keys.filter { $0.connectionID == connectionID }
        for key in doomed { entries[key] = nil }
        return doomed.count
    }

    /// **A cached token dies with its approved action.** The broker calls this
    /// when an approved action completes — executed, failed or refused — so an
    /// entry never outlives the one thing it is keyed to.
    ///
    /// This is clause (b)'s upper bound made exact: the 30 s grace covers a
    /// paginating operation whose next page has not been asked for yet, and
    /// this removes the entry the moment there is no next page.
    @discardableResult
    public func dropAction(_ approvedActionID: UUID) -> Int {
        let doomed = entries.keys.filter { $0.approvedActionID == approvedActionID }
        for key in doomed { entries[key] = nil }
        return doomed.count
    }

    /// How many live entries there are at `now`. Read-only, and it counts
    /// rather than lists: nothing outside this actor may enumerate what is
    /// cached, and a count is all a contract needs.
    public func liveCount(now: Date = Date()) -> Int {
        entries.values.filter { $0.isLive(at: now) }.count
    }
}
