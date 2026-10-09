import Foundation

/// BL-075 / owner decision D20 — **value-free connection metadata.**
///
/// The owner wants the account dashboard to list the providers connected on
/// their devices instead of provider requests. Connections live only on the
/// Mac, so the Mac has to say something. This type is the exact, and only,
/// thing it says.
///
/// The whole design is one sentence: **six fields, all of which the human
/// already chose or already saw, and nothing that identifies a credential, a
/// Keychain record, a provider resource, a project or an environment.**
///
/// What is deliberately *not* here, and why each one would be a different kind
/// of leak:
///
/// | Absent | Why |
/// |---|---|
/// | The credential value | The obvious one. No field on this type can hold bytes. |
/// | `keychainAccount` | It is the exact `kSecAttrAccount` of a user-presence-protected item. Publishing it tells a server which local record to ask for. |
/// | `vaultItemID`, `connection.id`, `credentialVersion` | Local record identifiers. A dashboard that knows them can correlate rotations and deletions it has no business seeing. |
/// | `principalID` | The provider's own account/user identifier. `principalLabel` is the human-readable name the owner saw when they verified; the ID is a cross-service join key. |
/// | Project and environment names, bindings, operations | Connections are reported per device, not per project. D20 asks for "which providers are connected", not for the local graph. |
/// | Provider resource identifiers (BL-074's created tokens) | A resource id names a live object in the owner's provider account. |
///
/// `label` is the one field that carries free text the human typed. Vaultage
/// bounds it and sends nothing else, but it cannot prove a human did not paste
/// a secret into a connection's name — the same honest limit BL-062's evidence
/// records for receipts, which also name labels. It is stated rather than
/// mitigated.
public struct DeviceConnectionReport: Sendable, Equatable {
    /// The exact key set of one reported connection. The self-test asserts
    /// against this constant rather than a literal, so adding a field to the
    /// payload without deciding it is value-free fails the suite.
    public static let payloadKeys: Set<String> = ["provider", "label", "principalHint", "verifiedAt", "paused", "region"]
    /// A device cannot report more than this many connections. The Free plan
    /// allows three and Personal is unbounded locally, so the cap is a bound on
    /// a hostile or corrupted local file rather than a product limit.
    public static let maximumConnections = 64
    /// Human-authored text is truncated rather than refused: a dashboard row
    /// that says less is better than a device that stops reporting.
    public static let maximumTextLength = 96

    /// `Provider.rawValue` — `github`, `openai`, `cloudflare`. A closed set.
    public let provider: String
    /// The connection's human-chosen name, bounded.
    public let label: String
    /// The principal label from the *verified* capability probe, bounded, or
    /// `nil`. Never the principal ID.
    public let principalHint: String?
    /// When the verification evidence was obtained, or `nil` when the
    /// connection is unverified or failed. An unverified connection reports
    /// `nil` rather than a stale timestamp: the dashboard must never show a
    /// "verified" state the Mac no longer holds.
    public let verifiedAt: Date?
    /// Whether the Free-plan gate has this connection paused. Paused preserves
    /// every local record and only stops Vaultage unlocking the credential.
    public let paused: Bool
    /// D44a. Which of the provider's documented regions this connection
    /// reaches — `us`, `eu`, `global` — or `nil` for the provider's primary
    /// region.
    ///
    /// It belongs on the list above's *left* column, not the right one, and the
    /// argument is the same one every other field here had to pass. A region id
    /// is a member of a closed set this build compiles
    /// (`ProviderRegionDirectory.regionIDs`); it is not free text, so unlike
    /// `label` it cannot carry something a human pasted. It is a **choice the
    /// human already made and already saw**, in the connect panel, next to the
    /// provider they were choosing. It names a documented public API host, not
    /// a resource, an account, a principal or a local record — `eu.posthog.com`
    /// is on PostHog's own documentation page. And a dashboard that lists "the
    /// providers connected on this device" without saying which region of a
    /// provider is telling the owner less than they told Vaultage.
    ///
    /// What it is **not**: it is not `principalID`, it does not narrow anything
    /// to an account, and nothing on the control plane may grant, widen, price
    /// or unlock anything from it. It is a display fact, like the other five.
    public let region: String?

    public init(provider: String, label: String, principalHint: String?, verifiedAt: Date?, paused: Bool, region: String? = nil) {
        self.provider = provider
        self.label = label
        self.principalHint = principalHint
        self.verifiedAt = verifiedAt
        self.paused = paused
        self.region = region
    }

    /// The projection from local metadata. This is the only way a report is
    /// built in the app, so it is the only place that could ever widen.
    ///
    /// Ordering is by connection id so the payload is stable across runs and a
    /// server cannot infer local ordering changes from a reordered list. The id
    /// itself is used for sorting only and is not sent.
    public static func reports(in state: VaultageMetadata) -> [DeviceConnectionReport] {
        state.connections
            .sorted { $0.id.uuidString < $1.id.uuidString }
            .prefix(maximumConnections)
            .map { connection in
                let verified = connection.state == .verified
                return DeviceConnectionReport(
                    provider: connection.provider.rawValue,
                    label: bounded(connection.label),
                    // Only a *current* verification contributes a principal
                    // hint. A failed or unverified connection reports neither
                    // a hint nor a timestamp.
                    principalHint: verified ? connection.verification?.principalLabel.map(bounded) : nil,
                    verifiedAt: verified ? (connection.verification?.verifiedAt ?? connection.lastVerifiedAt) : nil,
                    paused: connection.pauseReason != nil,
                    // Reported exactly as stored. `ConnectionRegions.normalize`
                    // has already repaired anything this build does not
                    // document to `nil`, so no undocumented id can reach here.
                    region: connection.region
                )
            }
    }

    /// §5.6 step 9's projection: this device's rows **as they will be** once the
    /// connection a remote connect just verified is committed.
    ///
    /// `PUT /api/device-connections` is an idempotent **full replace** of the
    /// authenticated device's rows, so step 9 cannot send one row — it sends the
    /// list. The consumption path holds the metadata snapshot it was handed, the
    /// `Connection` it verified and the evidence; the snapshot predates the
    /// caller's own write, so the verified connection is applied here rather
    /// than waited for. It is a **projection, not a write**: nothing is
    /// persisted by this function, and a caller that then commits the connection
    /// and reports again sends the same rows.
    ///
    /// Every field still comes from `reports(in:)`, including the sort by
    /// connection id and the 64-row cap, so step 9 cannot widen what BL-075
    /// argued field by field.
    public static func reports(
        in state: VaultageMetadata,
        verifiedByRemoteConnect connection: Connection,
        evidence: ConnectionVerification
    ) -> [DeviceConnectionReport] {
        var applied = connection
        applied.state = .verified
        applied.verification = evidence
        applied.lastVerifiedAt = evidence.verifiedAt
        var projected = state
        projected.connections = state.connections.filter { $0.id != applied.id } + [applied]
        return reports(in: projected)
    }

    /// The JSON object for one connection: exactly `payloadKeys`, with `nil`
    /// carried as JSON `null` rather than omitted, so the server sees a fixed
    /// shape and an absent hint cannot be confused with a missing field.
    public var payload: [String: Any] {
        [
            "provider": provider,
            "label": label,
            "principalHint": principalHint ?? NSNull(),
            "verifiedAt": verifiedAt.map { ISO8601DateFormatter().string(from: $0) } ?? NSNull(),
            "paused": paused,
            "region": region ?? NSNull()
        ]
    }

    private static func bounded(_ value: String) -> String {
        String(value.trimmingCharacters(in: .whitespacesAndNewlines).prefix(maximumTextLength))
    }
}

/// The seam the app reports through, so the self-tests can byte-scan a payload
/// without a network, and so a composition that has no account client simply
/// does not report.
public protocol DeviceConnectionReporting: Sendable {
    func reportConnections(_ connections: [DeviceConnectionReport]) async throws
}

/// Reports this Mac's connections to the control plane, and **never lets that
/// matter locally.**
///
/// BL-075's acceptance criteria say the dashboard must reflect a change within
/// a minute, and say nothing about the Mac waiting for the dashboard. Every
/// failure mode here — not linked, offline, route not deployed, server error,
/// unreadable metadata — is swallowed. A connection is created, verified,
/// paused or removed on this Mac whether or not any of that reaches a server,
/// because the local vault is the product and the dashboard is a view of it.
public struct DeviceConnectionMetadataReporter: Sendable {
    private let metadata: MetadataStore
    private let client: any DeviceConnectionReporting

    public init(metadata: MetadataStore, client: any DeviceConnectionReporting) {
        self.metadata = metadata
        self.client = client
    }

    /// Projects the current local state and sends it. Returns without throwing
    /// whatever happens; callers deliberately have nothing to handle.
    public func report() async {
        guard let state = try? await metadata.load() else { return }
        await report(in: state)
    }

    /// The same, for a caller that already holds freshly loaded state.
    public func report(in state: VaultageMetadata) async {
        try? await client.reportConnections(DeviceConnectionReport.reports(in: state))
    }
}
