import Foundation

/// BL-099 — P5, `offeredCoverageDigest`, and the offer it is computed from.
///
/// `12-REMOTE-APPROVALS-PROTOCOL.md` §3.3.1.1. **This is not
/// `Grant.coveringDigest`**, and checklist 1 (DB-C6, DB-H29, DB-M29) is the
/// whole reason:
///
/// * `GrantPolicy.prepare` is the only producer of a `GrantDisclosure`, and
///   `GrantRequest.includedMutations` is one of its inputs — each binding's
///   operation set is filtered to reads plus only the named mutations and a
///   binding whose filtered set is empty is **dropped** — so bindings,
///   environments, every label list, `includesProduction` and the digest all
///   move with `includedMutations`;
/// * at publication the Mac does not have `includedMutations`: the phone renders
///   the checklist **defaulting to none** and the owner chooses after the seal;
/// * and after §4.6 the committed digest also carries `decidingDeviceID` and
///   `pinGeneration`, which are not known until the decision arrives.
///
/// So the published number and the verified number could not be equal unless the
/// owner ticked exactly the offered set, which the design makes the non-default.
/// Two numbers, named differently: **this** one is a statement about what *may*
/// be covered — what the owner is shown, and what the relay must not be able to
/// grow — and it is hashed over coverage **identity only**.
///
/// **Identity, not record state** (checklist 1, DB-H29). `Grant.coveringDigest`
/// hashes nine live inputs that appear in no label list and on no screen — the
/// client's `credentialHash`, `connection.state`, `pauseReason`, Free-plan
/// membership, `item.credentialVersion`, the evidence's contract revision,
/// principal and credential version, and each environment's production flag. Any
/// of them moving inside the pending's five-minute window would have refused a
/// genuine approval as **tampering**. Record-state drift denies at **commit**
/// instead, through `createGrant`'s existing re-compare.
public enum RemoteOfferedCoverage {
    public static let domainTag = "vaultage.remote.offeredcoverage.v1"

    /// The offer as the summary states it, resolved into the five `prepare`
    /// inputs §3.3.1.1 fixes.
    public struct Offer: Hashable, Sendable {
        public let scopes: Set<RemoteDecisionScope>
        public let durations: Set<RemoteDecisionDuration>
        /// `offeredProjects`. Also `prepare`'s `scopeProjectIds`.
        public let projectIDs: Set<UUID>
        /// Every environment the offer covers. **Every one of them must lie
        /// within `projectIDs`, or publication throws** — which is the invariant
        /// that makes the scope input safe (version 8, NEW-M3).
        public let environmentIDs: Set<UUID>
        public let production: Bool
        public let mutations: Set<Operation>
        /// The enrolled client a `client`-scoped offer names.
        public let agentClientID: UUID?

        public init(scopes: Set<RemoteDecisionScope>, durations: Set<RemoteDecisionDuration>, projectIDs: Set<UUID>, environmentIDs: Set<UUID>, production: Bool, mutations: Set<Operation>, agentClientID: UUID?) {
            self.scopes = scopes
            self.durations = durations
            self.projectIDs = projectIDs
            self.environmentIDs = environmentIDs
            self.production = production
            self.mutations = mutations
            self.agentClientID = agentClientID
        }

        /// The **widest** offered scope: `projects` when both are offered.
        ///
        /// §3.3.1.1's own note, corrected in version 8 (NEW-M3): `scope` reaches
        /// none of the five fields this digest hashes — `prepare` derives
        /// bindings, environments, operations, mutations and production without
        /// reading it — so the choice cannot change the offer digest. What makes
        /// it safe is the invariant above, not a reach argument.
        public var widestScope: GrantScope? {
            if scopes.contains(.projects), !projectIDs.isEmpty { return GrantScope(projects: projectIDs) }
            if scopes.contains(.client), let client = agentClientID { return GrantScope(client: client) }
            return nil
        }
    }

    /// The `GrantRequest` §3.3.1.1's table fixes, so the convention is one
    /// function rather than five call sites that each remember four rows of it.
    public static func offerRequest(_ offer: Offer) throws -> GrantRequest {
        guard let scope = offer.widestScope else {
            throw VaultageError.invalidInput("A grant offer must name at least one usable scope.")
        }
        return GrantRequest(
            scope: scope,
            environmentIDs: offer.environmentIDs,
            // The digest does not hash a duration. `oneDay` is passed because
            // `GrantRequest` requires one, and it is the only duration a
            // production-covering offer may carry (§4.7 layer 4).
            duration: .oneDay,
            includeProduction: offer.production,
            includedMutations: offer.mutations
        )
    }

    /// The coverage the offer resolves to, as `prepare` computes it.
    ///
    /// Throws exactly where `prepare` throws, which is the point of NEW-M3's
    /// assertion `offerPublicationThrowsIfAnOfferedEnvironmentIsOutsideOfferedProjects`:
    /// an internally impossible offer is refused at publication, so §4.3 step 8a
    /// can reserve `digest_mismatch` for that case and give an empty *narrowed*
    /// set the plain refusal it deserves.
    public static func coverage(_ offer: Offer, in state: VaultageMetadata, now: Date = Date()) throws -> GrantDraft {
        try GrantPolicy.prepare(try offerRequest(offer), in: state, now: now)
    }

    // MARK: - Coverage identity, the only thing P5 hashes

    /// What P5 hashes, separated from **where it came from**.
    ///
    /// `GrantPolicy.prepare` is Mac-only, so the Worker cannot resolve a
    /// `VaultageMetadata` into a `GrantDraft` and its copy of the §9.3 fixture
    /// can only pin the **resolved coverage** (protocol §20, fixture decision
    /// 3). Naming that resolved coverage as a type is what lets one function
    /// produce the number from either side — from a draft this Mac prepared, or
    /// from the shared fixture's own `coverage` object — so the cross-check is a
    /// real two-implementation comparison and not two call sites that happen to
    /// look alike.
    public struct Identity: Hashable, Sendable {
        public struct BindingOperations: Hashable, Sendable {
            public let bindingID: String
            public let operations: [String]
            public init(bindingID: String, operations: [String]) {
                self.bindingID = RemoteApprovalDigests.canonicalIdentifier(bindingID)
                self.operations = operations.sorted()
            }
        }

        public let bindingIDs: [String]
        public let environmentIDs: [String]
        public let operations: [BindingOperations]
        public let mutations: [String]
        public let production: Bool

        /// Canonicalises and sorts on the way in, so no caller can hold an
        /// `Identity` that would hash differently from an equal one.
        public init(bindingIDs: [String], environmentIDs: [String], operations: [BindingOperations], mutations: [String], production: Bool) {
            self.bindingIDs = RemoteApprovalDigests.canonicalIdentifiers(bindingIDs)
            self.environmentIDs = RemoteApprovalDigests.canonicalIdentifiers(environmentIDs)
            self.operations = operations.sorted { $0.bindingID < $1.bindingID }
            self.mutations = mutations.sorted()
            self.production = production
        }
    }

    /// The coverage identity a resolved draft carries.
    public static func identity(_ draft: GrantDraft, offeredMutations: Set<Operation>) -> Identity {
        Identity(
            bindingIDs: draft.bindings.map(\.bindingID.uuidString),
            environmentIDs: draft.environmentIDs.map(\.uuidString),
            operations: draft.bindings.map {
                Identity.BindingOperations(bindingID: $0.bindingID.uuidString, operations: $0.allowedOperations.map(\.rawValue))
            },
            mutations: offeredMutations.map(\.rawValue),
            production: draft.includesProduction
        )
    }

    /// P5's field list.
    ///
    /// **`operations` is self-delimiting** — outer count is the number of
    /// **bindings**, and each binding carries **its own** operation count
    /// (protocol §20, fixture decision 2; slice-1 deviation 5):
    ///
    /// ```
    /// "operations", "<bindingCount>",
    ///     <bindingId>, "<opCount>", …sorted op raw values…    // per binding, in bindingId order
    /// ```
    ///
    /// Slice 1 emitted the appendix's literal form, with the outer count as the
    /// number of *fields* that follow, and argued the group was uniquely
    /// decodable because the `bindings` group above it had already fixed the ids
    /// and their order. BL-098 read it the other way, and **BL-098's reading
    /// wins**: it matches `Grant.coveringDigest`'s shipped discipline, and it
    /// decodes on its own rather than because of a group above it. Left
    /// unresolved this is the divergence that would have shipped as "the Mac
    /// refuses every remote grant".
    ///
    /// Every other `"label", "\(n)"` prefix is still followed by exactly `n`
    /// fields, and every identifier is RFC 4122 canonical before it is sorted
    /// (deviation 4).
    public static func fields(_ identity: Identity) -> [String] {
        var operationFields: [String] = ["operations", "\(identity.operations.count)"]
        for binding in identity.operations {
            operationFields.append(binding.bindingID)
            operationFields.append("\(binding.operations.count)")
            operationFields.append(contentsOf: binding.operations)
        }
        var body: [String] = []
        body.append(contentsOf: ["bindings", "\(identity.bindingIDs.count)"] + identity.bindingIDs)
        body.append(contentsOf: ["environments", "\(identity.environmentIDs.count)"] + identity.environmentIDs)
        body.append(contentsOf: operationFields)
        body.append(contentsOf: ["mutations", "\(identity.mutations.count)"] + identity.mutations)
        body.append(contentsOf: ["production", "\(identity.production)"])
        return RemoteApprovalDigests.sealed(domainTag, body)
    }

    public static func fields(_ draft: GrantDraft, offeredMutations: Set<Operation>) -> [String] {
        fields(identity(draft, offeredMutations: offeredMutations))
    }

    public static func digest(_ identity: Identity) -> String {
        CanonicalDigest.hex(fields(identity))
    }

    public static func digest(_ draft: GrantDraft, offeredMutations: Set<Operation>) -> String {
        CanonicalDigest.hex(fields(draft, offeredMutations: offeredMutations))
    }

    /// The whole convention in one call: resolve the offer, then hash its
    /// identity. This is what publication uses and what §4.3 step 9c recomputes,
    /// so there is exactly one way to produce the number.
    public static func digest(_ offer: Offer, in state: VaultageMetadata, now: Date = Date()) throws -> String {
        digest(try coverage(offer, in: state, now: now), offeredMutations: offer.mutations)
    }

    // MARK: - P0, the pre-filter

    /// **Appendix row P0 — the pre-filter, run at check 8 before any coverage
    /// test** (§3.3.1.1, DB-H37; version 8, NEW-H4).
    ///
    /// ```
    /// narrowed = { e ∈ offeredEnvironmentIDs
    ///              : (scope.kind != .projects || e.projectID ∈ scopeProjectIds)
    ///             && (includeProduction        || !e.isProduction) }
    /// ```
    ///
    /// `GrantPolicy.prepare` **throws** rather than filters — at
    /// `Grant.swift:509-511` for projects and `:506-508` for production — so
    /// handing it the offered environment set with a narrowed project set would
    /// throw at commit on the *default* path, which is the owner ticking fewer
    /// projects than were offered. §4.3 step 7 explicitly permits that, so the
    /// Mac narrows first.
    ///
    /// **Checks 8, 8a and 9c and the `GrantRequest` handed to `prepare` all use
    /// the narrowed set, never the offered set.** `scope.kind == .client`
    /// narrows by production only.
    public static func narrowed(
        offeredEnvironmentIDs: Set<UUID>,
        scopeKind: RemoteDecisionScope,
        scopeProjectIDs: Set<UUID>,
        includeProduction: Bool,
        in state: VaultageMetadata
    ) -> Set<UUID> {
        var result: Set<UUID> = []
        for id in offeredEnvironmentIDs {
            guard let environment = state.environments.first(where: { $0.id == id }) else { continue }
            if scopeKind == .projects, !scopeProjectIDs.contains(environment.projectID) { continue }
            // `Environment.isProduction` is the authority everywhere in this
            // protocol, never `EnvironmentSensitivity` (checklist 2, DB-H21).
            if !includeProduction, environment.isProduction { continue }
            result.insert(id)
        }
        return result
    }
}
