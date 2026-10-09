import Foundation

/// The account client is deliberately an injected dependency of policy.  A
/// missing, malformed, expired, or otherwise unavailable account response is
/// treated as Free; policy never grants paid access optimistically.
public struct ManagedConnectionPolicy: Sendable {
    public static let freeLimit = 3

    public init() {}

    public func effectiveLimit(for entitlement: AccountEntitlement) -> Int? {
        // `DeviceAccountClient` verifies the signed lease, its <=30 day
        // lifetime, expiry, and paid-through claim before returning paid.
        // Keep this second check narrow so alternate AccountClient
        // implementations cannot accidentally turn a stale value into Pro.
        guard entitlement.isPaid,
              let expiry = entitlement.leaseExpiresAt,
              expiry > .now,
              expiry.timeIntervalSinceNow <= 30 * 24 * 60 * 60 + 60
        else { return Self.freeLimit }
        return nil
    }

    public func applies(entitlement: AccountEntitlement, to state: inout VaultageMetadata) {
        guard let limit = effectiveLimit(for: entitlement) else {
            for index in state.connections.indices { state.connections[index].pauseReason = nil }
            return
        }

        let allIDs = state.connections.map(\.id)
        let remembered = state.freeActiveConnectionIDs.filter { allIDs.contains($0) }
        let selected: Set<UUID>
        if !remembered.isEmpty && remembered.count <= limit {
            selected = remembered
        } else {
            // UUID ordering is stable across processes and therefore gives a
            // reproducible safe default without inventing timestamps for old
            // records.  The user can later select any three explicitly.
            selected = Set(state.connections.map(\.id).sorted { $0.uuidString < $1.uuidString }.prefix(limit))
        }
        state.freeActiveConnectionIDs = selected
        for index in state.connections.indices {
            state.connections[index].pauseReason = selected.contains(state.connections[index].id) ? nil : .freePlanLimit
        }
    }

    public func canCreateConnection(entitlement: AccountEntitlement, state: VaultageMetadata) -> Bool {
        guard let limit = effectiveLimit(for: entitlement) else { return true }
        return state.connections.filter { $0.pauseReason == nil }.count < limit
    }

    /// Call from inside MetadataStore.update so plan reconciliation, capacity
    /// checking, and adding the record are one locked metadata transaction.
    ///
    /// D44a. This is the one seam every connection creation in the product
    /// passes through, so it is where a region is **validated on create**: a
    /// region that is not one of the provider's documented ids is refused here,
    /// before the record exists, rather than repaired into a connection that
    /// reaches a host the human did not pick. The connect panel is expected to
    /// have refused it already — `ProviderRegionDirectory.validated(_:for:)` is
    /// public for exactly that — and this is the check that does not depend on
    /// the panel having done so.
    public func addConnection(_ connection: Connection, entitlement: AccountEntitlement, to state: inout VaultageMetadata) throws {
        try ProviderRegionDirectory.validated(connection.region, for: connection.provider)
        applies(entitlement: entitlement, to: &state)
        guard canCreateConnection(entitlement: entitlement, state: state) else {
            throw VaultageError.policyDenied("The Free plan permits three active managed connections. Link a paid account or pause one connection before adding another.")
        }
        state.connections.append(connection)
        if effectiveLimit(for: entitlement) != nil { state.freeActiveConnectionIDs.insert(connection.id) }
        applies(entitlement: entitlement, to: &state)
    }

    public func deniedMessage(for connection: Connection) -> String? {
        guard connection.pauseReason == .freePlanLimit else { return nil }
        return "This connection is paused because the Free plan permits three active managed connections. Select it in Services or link a paid account before using its bindings."
    }
}

public struct StaticAccountClient: AccountClient {
    private let entitlement: AccountEntitlement
    public init(_ entitlement: AccountEntitlement = .free) { self.entitlement = entitlement }
    public func currentEntitlement() async throws -> AccountEntitlement { entitlement }
}
