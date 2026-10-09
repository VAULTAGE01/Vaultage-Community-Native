import CryptoKit
import Foundation

/// BL-099 — every preimage in `12-APPENDIX-BUILDERS-CONTRACT.md` §1, in one
/// place, as pure functions.
///
/// **This file is written from the appendix, not from the prose.** The appendix
/// is normative and self-contained; where the two differ the appendix says it is
/// the defect and must be reported. Each function below names its P-number.
///
/// **The field-count convention** (§3.3.2, appendix header). There are **two**
/// counts in these preimages and version 9.2 states both, because stating one
/// and letting it read as both is what DB6-H8 reported — and the sentence this
/// header used to carry ("the count … **includes every element of every nested
/// list**") is the exact sentence 9.2 removed from both documents (BM-L4). The
/// *code* was always right; the comment was the stale one, in the file a third
/// implementation would read for the convention.
///
/// > **1 — a preimage's leading arity count.** Field 1 of every preimage,
/// > immediately after the domain tag. The number of encoded fields in the body,
/// > excluding the domain tag and the count itself, counting every encoded field
/// > of every group — the group's own label, the group's own count field, and
/// > each element. It is `body.count`, computed here in `sealed(_:_:)` and never
/// > asserted.
/// >
/// > **2 — a labelled group's own count.** The field that follows a group's
/// > label: **its number of *items*** — one `(id, name)` pair is `"1"`, three
/// > triples are `"3"` — with **`destination`** the sole exception, keeping a
/// > field count as the literal `"0"`/`"5"` because it is a presence-and-arity
/// > sentinel for one fixed record rather than a list.
///
/// They are different numbers over the same bytes and neither is wrong;
/// conflating them is, and it is how BL-098 came to emit
/// `offeredProjects.length * 2`. `summaryFieldListIsWellFormed`'s
/// `group(_:width:)` counts items, which is rule 2.
///
/// **Optionals are literal sentinels, never omissions**, so arity is fixed and
/// `CanonicalDigest`'s injectivity argument holds (Q2).
///
/// **What this file deliberately does not contain.** P11, the key binding
/// statement, is **deleted** (appendix P11, DB-H1): its preimage named an
/// enrolment `request_id` and a server-assigned `enrolledAt`, neither of which a
/// verifying Mac can recover, and even repaired it proved nothing against an
/// invented device. What replaces it is the pair of out-of-band pins: the Mac's
/// `sig` and `kex` thumbprints travel inside P1, both sides fold all seven
/// thumbprints into P2, and the owner compares six words. **The pins are the
/// whole control** (§2.4).
public enum RemoteApprovalDigests {
    /// The domain-tag + count prefix, applied once so no call site can get the
    /// convention wrong.
    ///
    /// `body` is every field after the count. Returns the complete field list.
    public static func sealed(_ domainTag: String, _ body: [String]) -> [String] {
        [domainTag, "\(body.count)"] + body
    }

    /// Lowercase hex SHA-256 over `CanonicalDigest.encode(sealed(tag, body))`.
    static func hex(_ domainTag: String, _ body: [String]) -> String {
        CanonicalDigest.hex(sealed(domainTag, body))
    }

    /// Raw canonical bytes, for the preimages that are signed rather than hashed.
    static func encode(_ domainTag: String, _ body: [String]) -> Data {
        CanonicalDigest.encode(sealed(domainTag, body))
    }

    /// **RFC 4122 canonical spelling, applied before any sort** (appendix
    /// version 9, slice-1 deviation 4).
    ///
    /// `UUID.uuidString` is upper-case and a JSON literal is usually
    /// lower-case, so two implementations that agree on every field can still
    /// produce two digests — and the Mac would refuse a well-formed decision
    /// with tampering copy over the case of a hex digit. Anything that is not a
    /// UUID is returned untouched: this normalises a *spelling*, never a value.
    ///
    /// **Before sorting, not after**: `"A1…" < "a1…"` in ASCII, so lowercasing
    /// a list that was already sorted can leave it out of order.
    public static func canonicalIdentifier(_ raw: String) -> String {
        guard let uuid = UUID(uuidString: raw) else { return raw }
        return uuid.uuidString.lowercased()
    }

    /// The same rule over a list, fixed **before** the sort.
    public static func canonicalIdentifiers(_ raw: [String]) -> [String] {
        raw.map(canonicalIdentifier).sorted()
    }

    // MARK: - The count convention, checkable on a field list alone

    /// Whether a preimage carries the count convention's prefix: at least a
    /// domain tag and a count, and a count equal to the body length.
    ///
    /// True of **every** preimage in the appendix, whatever its shape.
    public static func countPrefixIsWellFormed(_ fields: [String]) -> Bool {
        fields.count >= 2 && fields[1] == "\(fields.count - 2)"
    }

    /// Whether a field list is structurally a **summary preimage**: P4's field
    /// order, walked positionally, consuming every labelled group by its own
    /// stated count and ending exactly at the end of the list.
    ///
    /// This is what makes §9.3's `wrongFieldCount` and `miscountedList` refusal
    /// vectors decidable from a field list alone — the situation a verifier is
    /// in when it is handed a preimage rather than an object. A list whose
    /// `offeredScopes` count says three where two follow does not merely hash
    /// differently: it stops being a summary preimage, because the next label
    /// is no longer where P4 puts it.
    ///
    /// The appendix specifies each group individually rather than by one rule,
    /// and both shapes are present: `"offeredProjects" + count + pairs` and
    /// `"choices" + count + triples` count **items**, while `"destination" +
    /// "5"` and every string list count **fields**. The walk below is written
    /// against the appendix group by group rather than against a rule that does
    /// not exist. On 2026-09-13 this walk is what the Worker's own field-list
    /// refusal was reconciled against, after its emitter and its walker were
    /// wrong together about the two item-counted groups (see the P4 note on
    /// `summaryFields`).
    public static func summaryFieldListIsWellFormed(_ fields: [String]) -> Bool {
        guard countPrefixIsWellFormed(fields), fields[0] == summaryDomainTag else { return false }
        var index = 2
        // class … resourceLabel: twenty scalar fields plus the two-field
        // `isProduction` label/value pair.
        func take(_ count: Int) -> Bool {
            guard index + count <= fields.count else { return false }
            index += count
            return true
        }
        func label(_ expected: String) -> Bool {
            guard index < fields.count, fields[index] == expected else { return false }
            index += 1
            return true
        }
        /// A `"label", "n"` group whose `n` counts items of `width` fields each.
        func group(_ expected: String, width: Int) -> Bool {
            guard label(expected), index < fields.count, let count = Int(fields[index]), count >= 0 else { return false }
            index += 1
            return take(count * width)
        }
        guard take(13) else { return false }                       // class … sensitivity
        guard label("isProduction"), take(1) else { return false }
        guard take(5) else { return false }                        // operation … resourceLabel
        // `destination` states a field count directly: "0", or "5" and five.
        guard label("destination"), index < fields.count, let destinationCount = Int(fields[index]),
              destinationCount == 0 || destinationCount == 5 else { return false }
        index += 1
        guard take(destinationCount) else { return false }
        guard group("offeredScopes", width: 1) else { return false }
        guard group("offeredDurations", width: 1) else { return false }
        guard group("offeredProjects", width: 2) else { return false }
        guard label("offeredProduction"), take(1) else { return false }
        guard group("choices", width: 3) else { return false }
        guard label("presence"), take(1) else { return false }
        guard label("openPendingCount"), take(1) else { return false }
        guard label("custodyClass"), take(1) else { return false }
        guard take(4) else { return false }                        // brokerDigestKind … expiresAt
        // The class section. Every class emits **both** headers, in this order.
        guard label("grant"), index < fields.count else { return false }
        let grantPresent = fields[index]
        guard grantPresent == "0" || grantPresent == "1" else { return false }
        index += 1
        if grantPresent == "1" {
            guard take(3) else { return false }                    // scopeLabel, durationLabel, expiresAtEpoch
            for name in ["environments", "operations", "mutations", "mutationKinds", "productionEnvs"] {
                guard group(name, width: 1) else { return false }
            }
            guard label("includesProduction"), take(1) else { return false }
            guard group("offeredMutations", width: 1) else { return false }
            guard take(1) else { return false }                    // offeredCoverageDigest
            guard label("recipient"), take(2) else { return false }
            guard group("sentences", width: 1) else { return false }
        }
        guard label("connect"), index < fields.count else { return false }
        let connectPresent = fields[index]
        guard connectPresent == "0" || connectPresent == "1" else { return false }
        index += 1
        if connectPresent == "1" {
            guard take(4) else { return false }                    // provider, label, capability, fieldSchemaId
        }
        return index == fields.count
    }

    // MARK: - P4 — summaryDigest

    public static let summaryDomainTag = RemoteApprovalSummary.schemaTag

    /// The appendix's P4 field order, which is also §3.3 rule 1b's **normative
    /// render manifest**: BL-096 lays out slots in this order.
    ///
    /// Lists are sorted here rather than at the caller, so two implementations
    /// that build the same coverage in different orders still produce one
    /// number. `offeredProjects` sorts by id, `choices` by id, and every string
    /// list sorts as a string list.
    ///
    /// **A labelled group's count is its number of items, not its number of
    /// encoded fields.** BL-098's TypeScript emitted `length * 2` for
    /// `offeredProjects` and `length * 3` for `choices` until 2026-09-13, and
    /// that one byte was the whole of the P4 cross-implementation divergence:
    /// `grant.readsOnly` hashed to `b225d7f9…` here and `5c0923c0…` there, with
    /// 1276 of 1277 preimage bytes identical. This reading is the one that
    /// stands, on the appendix's own authority:
    ///
    /// * §3.3.1 says the grant section is "count- and length-prefixed **exactly
    ///   as `Grant.coveringDigest` does**", and `Grant.coveringDigest`
    ///   (`Grant.swift:329-331`) emits `["bindings", "\(count)"]` ahead of ~20
    ///   encoded fields per binding — records, not fields.
    /// * §20 fixture decision 2 settled the identical question for P5's
    ///   `operations` group, and gave "matches `Grant.coveringDigest`" as the
    ///   reason. BL-098 won that one and then contradicted it here.
    /// * The appendix distinguishes `+ count + list` (width 1, where the two
    ///   readings coincide) from `+ count + pairs` and `+ count + triples`.
    ///
    /// `destination` is the one group whose count is a field count, and §3.3
    /// pins it as the literal `"0"`/`"5"` rather than `"\(n)"` — a
    /// presence-and-arity sentinel rather than a list count.
    public static func summaryFields(_ summary: RemoteApprovalSummary) -> [String] {
        var body: [String] = []
        body.append(summary.summaryClass.rawValue)
        body.append(canonicalIdentifier(summary.pendingId))
        body.append(summary.accountSubject)
        body.append(canonicalIdentifier(summary.macDeviceId))
        body.append(summary.agentState)
        body.append(summary.agentLabel ?? "")
        body.append(summary.agentClientId.map(canonicalIdentifier) ?? "none")
        body.append(summary.provider)
        body.append(summary.connectionLabel)
        body.append(summary.principalHint ?? "unknown")
        body.append(summary.projectName)
        body.append(summary.environmentName)
        body.append(summary.sensitivity)
        // The authority field, labelled in the preimage exactly as the appendix
        // writes it: `"isProduction"`, then the value (residual 1, DB-H30).
        body.append(contentsOf: ["isProduction", "\(summary.isProduction)"])
        body.append(summary.operation)
        body.append(summary.verb)
        body.append(summary.effect)
        body.append(summary.trustClass)
        body.append(summary.resourceLabel ?? "none")
        body.append("destination")
        if let destination = summary.destination {
            body.append("5")
            body.append(contentsOf: destination.canonicalFields)
        } else {
            body.append("0")
        }
        let scopes = summary.offeredScopes.sorted()
        body.append(contentsOf: ["offeredScopes", "\(scopes.count)"] + scopes)
        let durations = summary.offeredDurations.sorted()
        body.append(contentsOf: ["offeredDurations", "\(durations.count)"] + durations)
        // v9 deviation 4: the id is fixed to its canonical (lowercase) spelling
        // **before** the sort — `"A1…" < "a1…"` in ASCII, so sorting first and
        // lowercasing after can leave the list out of order.
        let projects = summary.offeredProjects
            .map { RemoteOfferedProject(id: canonicalIdentifier($0.id), name: $0.name) }
            .sorted { $0.id < $1.id }
        body.append(contentsOf: ["offeredProjects", "\(projects.count)"])
        for project in projects { body.append(contentsOf: [project.id, project.name]) }
        body.append(contentsOf: ["offeredProduction", "\(summary.offeredProduction)"])
        let choices = summary.choices
            .map { RemoteChoice(id: canonicalIdentifier($0.id), label: $0.label, detail: $0.detail) }
            .sorted { $0.id < $1.id }
        body.append(contentsOf: ["choices", "\(choices.count)"])
        for choice in choices { body.append(contentsOf: [choice.id, choice.label, choice.detail]) }
        body.append(contentsOf: ["presence", summary.presence.rawValue])
        body.append(contentsOf: ["openPendingCount", "\(summary.openPendingCount)"])
        body.append(contentsOf: ["custodyClass", summary.custodyClass.rawValue])
        body.append(summary.brokerDigestKind)
        body.append(summary.brokerRequestDigest)
        body.append("\(summary.issuedAt)")
        body.append("\(summary.expiresAt)")
        body.append(contentsOf: classSectionFields(summary))
        return sealed(summaryDomainTag, body)
    }

    /// The class-discriminated section (§3.3.1). **Every class emits both
    /// headers, in this order**, with a `"0"` count for the section that does
    /// not apply — which version 4's own example did not (checklist 16, DB-M23).
    /// The encoding stays injective not because arity is fixed (the grant
    /// section holds six variable-length lists) but because every list is
    /// count-prefixed, which is `CanonicalDigest`'s own argument.
    public static func classSectionFields(_ summary: RemoteApprovalSummary) -> [String] {
        var fields: [String] = []
        if let grant = summary.grant {
            fields.append(contentsOf: ["grant", "1"])
            fields.append(grant.scopeLabel)
            fields.append(grant.durationLabel)
            fields.append("\(grant.expiresAtEpoch)")
            let environments = grant.environments.sorted()
            fields.append(contentsOf: ["environments", "\(environments.count)"] + environments)
            let operations = grant.operations.sorted()
            fields.append(contentsOf: ["operations", "\(operations.count)"] + operations)
            let mutations = grant.mutations.sorted()
            fields.append(contentsOf: ["mutations", "\(mutations.count)"] + mutations)
            let mutationKinds = grant.mutationKinds.sorted()
            fields.append(contentsOf: ["mutationKinds", "\(mutationKinds.count)"] + mutationKinds)
            let productionEnvs = grant.productionEnvs.sorted()
            fields.append(contentsOf: ["productionEnvs", "\(productionEnvs.count)"] + productionEnvs)
            fields.append(contentsOf: ["includesProduction", "\(grant.includesProduction)"])
            let offeredMutations = grant.offeredMutations.sorted()
            fields.append(contentsOf: ["offeredMutations", "\(offeredMutations.count)"] + offeredMutations)
            fields.append(grant.offeredCoverageDigest)
            // v9 deviation 4: the recipient device id is a UUID and is spelled
            // canonically. The thumbprint is base64url and is never touched.
            fields.append(contentsOf: ["recipient", canonicalIdentifier(grant.recipientDeviceId), grant.recipientApvThumbprint])
            fields.append(contentsOf: ["sentences", "4"] + RemoteGrantSection.sentenceIdentifiers)
        } else {
            fields.append(contentsOf: ["grant", "0"])
        }
        if let connect = summary.connect {
            fields.append(contentsOf: ["connect", "1", connect.providerSlug, connect.connectionLabel, connect.capability, connect.fieldSchemaId])
        } else {
            fields.append(contentsOf: ["connect", "0"])
        }
        return fields
    }

    public static func summaryDigest(_ summary: RemoteApprovalSummary) -> String {
        CanonicalDigest.hex(summaryFields(summary))
    }

    // MARK: - P6 — approvalRequestDigest

    public static let requestDomainTag = "vaultage.remote.request.v4"

    /// P6, count `"9"` — a constant, asserted against the body length by the
    /// self-tests so a field added here without the appendix moving is a test
    /// failure rather than a silent divergence.
    public static func approvalRequestFields(_ summary: RemoteApprovalSummary, summaryDigest digest: String) -> [String] {
        sealed(requestDomainTag, [
            summary.accountSubject,
            // The same two values P4 digests, so they carry P4's canonical
            // spelling too (v9 deviation 4). A split here would hash one
            // logical id two ways inside one chain.
            canonicalIdentifier(summary.macDeviceId),
            canonicalIdentifier(summary.pendingId),
            summary.summaryClass.rawValue,
            summary.brokerDigestKind,
            summary.brokerRequestDigest,
            digest,
            "\(summary.issuedAt)",
            "\(summary.expiresAt)"
        ])
    }

    public static func approvalRequestDigest(_ summary: RemoteApprovalSummary, summaryDigest digest: String) -> String {
        CanonicalDigest.hex(approvalRequestFields(summary, summaryDigest: digest))
    }

    /// Both numbers from one object, which is the only way a caller should ever
    /// get them: `approvalRequestDigest` carries `summaryDigest` (§3.3 rule 7),
    /// so a future schema change cannot silently drop a field from the chain.
    public static func digests(for summary: RemoteApprovalSummary) -> (summary: String, request: String) {
        let summaryValue = summaryDigest(summary)
        return (summaryValue, approvalRequestDigest(summary, summaryDigest: summaryValue))
    }

    // MARK: - P1 — the QR payload

    public static let pairingDomainTag = "vaultage.device.pairing.v3"

    /// P1, count `"7"`. Displayed, never signed: substitution is caught by the
    /// six words, not by a signature (§2.4).
    public static func pairingPayloadFields(_ payload: RemotePairingPayload) -> [String] {
        sealed(pairingDomainTag, [
            payload.pairingId,
            payload.macDeviceId,
            payload.accountSubject,
            payload.macSigThumbprint,
            payload.macKexThumbprint,
            payload.nonce,
            "\(payload.createdAt)"
        ])
    }

    // MARK: - P2 — the six-word SAS

    public static let sasDomainTag = "vaultage.device.pairing.sas.v3"

    /// P2, count `"8"`. Both devices compute it; the owner compares the words.
    public static func sasFields(_ inputs: RemoteSASInputs) -> [String] {
        sealed(sasDomainTag, [
            inputs.nonce,
            inputs.macSigThumbprint,
            inputs.macKexThumbprint,
            inputs.phoneSigThumbprint,
            inputs.phoneSigwThumbprint,
            inputs.phoneApvThumbprint,
            inputs.phoneSumThumbprint,
            inputs.phoneSum2Thumbprint
        ])
    }

    // MARK: - P3 — the device-signed revocation statement

    public static let revocationDomainTag = "vaultage.device.revocation.v1"

    /// P3, count `"6"`. **Signed by `apv`, never by `sig`** (DB-H11; version 7,
    /// DB-M43a): `sig` admits a passcode, which handed a thief holding an
    /// unlocked phone an irreversible kill switch over the owner's Mac.
    public static func revocationFields(_ statement: RemoteRevocationStatement) -> [String] {
        sealed(revocationDomainTag, [
            statement.accountSubject,
            statement.revokedDeviceId,
            "\(statement.revokedAtEpochSeconds)",
            statement.revokingDeviceId,
            "\(statement.serial)",
            statement.reason.rawValue
        ])
    }

    public static func revocationPreimage(_ statement: RemoteRevocationStatement) -> Data {
        CanonicalDigest.encode(revocationFields(statement))
    }

    // MARK: - P8 / P9 — the two HPKE `info` lists

    public static let summaryEnvelopeDomainTag = "vaultage.remote.summary.envelope.v1"
    public static let connectEnvelopeDomainTag = "vaultage.connect.envelope.v1"

    /// The HPKE ciphersuite label, carried as a **string** rather than a number
    /// (Q4) so the context is readable in a fixture and in a log of the fixture.
    public static let hpkeSuiteLabel = "P256-SHA256-AES256GCM"

    /// P8, count `"7"` — corrected from version 4's `"8"` for seven fields
    /// (checklist 10). The recipient thumbprint is `sum` for an ordinary summary
    /// and `sum2` for a sensitive one, so the ACL enforces §2.5's promise rather
    /// than a UI branch (DB-M19).
    public static func summaryEnvelopeInfoFields(_ info: RemoteSummaryEnvelopeInfo) -> [String] {
        sealed(summaryEnvelopeDomainTag, [
            hpkeSuiteLabel,
            info.pendingId,
            info.accountSubject,
            info.macDeviceId,
            info.phoneDeviceId,
            info.recipientThumbprint,
            "\(info.issuedAt)"
        ])
    }

    /// P9, count `"9"`. The version byte is inside the context as well as on the
    /// wire, so a downgrade is an AEAD failure rather than a parse.
    public static func connectEnvelopeInfoFields(_ info: RemoteConnectEnvelopeInfo) -> [String] {
        sealed(connectEnvelopeDomainTag, [
            hpkeSuiteLabel,
            "1",
            info.connectRequestId,
            info.accountSubject,
            info.macDeviceId,
            info.providerSlug,
            info.phoneDeviceId,
            info.macKexThumbprint,
            info.fieldSchemaId
        ])
    }

    // MARK: - P10 — the connect context

    public static let connectContextDomainTag = "vaultage.connect.context.v2"

    /// P10, count `"9"`. Produced by BL-096 under `apv`; **verified here before
    /// anything is stored** (DB-H20). `macKexThumbprint` comes from the pin, not
    /// from the request.
    public static func connectContextFields(_ context: RemoteConnectContext) -> [String] {
        sealed(connectContextDomainTag, [
            context.connectRequestId,
            context.accountSubject,
            context.macDeviceId,
            context.phoneDeviceId,
            context.providerSlug,
            context.capability,
            context.fieldSchemaId,
            context.macKexThumbprint,
            "\(context.issuedAt)"
        ])
    }

    public static func connectContextPreimage(_ context: RemoteConnectContext) -> Data {
        CanonicalDigest.encode(connectContextFields(context))
    }

    // MARK: - P7 — the decision preimage

    public static let decisionDomainTag = "vaultage.remote.decision.v4"

    /// P7, computed count. The field order is the appendix's, which differs from
    /// §4.1's code block in nothing and is the one implemented.
    ///
    /// `approvalRequestDigest` and `summaryDigest` are **derived by the phone and
    /// re-derived by the Mac**; neither is on the wire (§4.2). `accountSubject`
    /// and `macDeviceId` are likewise filled from local state on both sides.
    public static func decisionFields(_ decision: RemoteDecisionPayload) -> [String] {
        // v9 deviation 4, applied to **every** identifier-typed field of P7 and
        // not only to `scopeProjectIds`: `scopeClientId`, `choiceId`,
        // `decisionId`, `macDeviceId` and `decidingDeviceId` are all UUIDs the
        // phone mints or echoes, and check 7 compares them against values this
        // Mac parsed. `canonicalIdentifier` is shape-guarded, so the `"none"`
        // sentinels and `includedMutations` (`Operation` raw values, never
        // UUIDs) pass through untouched.
        var body: [String] = [
            decision.approvalRequestDigest,
            decision.summaryDigest,
            decision.decision.rawValue,
            decision.scope.rawValue,
            decision.scopeClientId.map(canonicalIdentifier) ?? "none"
        ]
        let projects = canonicalIdentifiers(decision.scopeProjectIds)
        body.append("\(projects.count)")
        body.append(contentsOf: projects)
        body.append(decision.duration.rawValue)
        body.append("\(decision.includeProduction)")
        body.append(decision.typedEnvironmentName ?? "none")
        let mutations = decision.includedMutations.sorted()
        body.append("\(mutations.count)")
        body.append(contentsOf: mutations)
        body.append(decision.choiceId.map(canonicalIdentifier) ?? "none")
        body.append(canonicalIdentifier(decision.decisionId))
        body.append("\(decision.issuedAt)")
        body.append("\(decision.expiresAt)")
        body.append(decision.accountSubject)
        body.append(canonicalIdentifier(decision.macDeviceId))
        body.append(canonicalIdentifier(decision.decidingDeviceId))
        body.append(decision.apvThumbprint)
        return sealed(decisionDomainTag, body)
    }

    public static func decisionPreimage(_ decision: RemoteDecisionPayload) -> Data {
        CanonicalDigest.encode(decisionFields(decision))
    }

    /// §4.1's domain-separation check, run **before any curve operation**: the
    /// preimage begins with the 30 bytes `27:vaultage.remote.decision.v4`, and a
    /// JWS signing input always begins `eyJ`. A candidate that does not start
    /// with these exact bytes is refused without touching a key.
    public static let decisionPreimagePrefix = Data("\(decisionDomainTag.utf8.count):\(decisionDomainTag)".utf8)

    public static func hasDecisionDomainPrefix(_ candidate: Data) -> Bool {
        candidate.starts(with: decisionPreimagePrefix)
    }
}

// MARK: - The inputs each preimage takes

/// P1's inputs. Valid **120 seconds**, single use, never reused across pairings
/// (§2.4).
public struct RemotePairingPayload: Codable, Hashable, Sendable {
    public static let validitySeconds: Int = 120
    public static let nonceBytes = 32

    public let pairingId: String
    public let macDeviceId: String
    public let accountSubject: String
    public let macSigThumbprint: String
    public let macKexThumbprint: String
    /// 32 random bytes, base64url.
    public let nonce: String
    public let createdAt: Int

    public init(pairingId: String, macDeviceId: String, accountSubject: String, macSigThumbprint: String, macKexThumbprint: String, nonce: String, createdAt: Int) {
        self.pairingId = pairingId
        self.macDeviceId = macDeviceId
        self.accountSubject = accountSubject
        self.macSigThumbprint = macSigThumbprint
        self.macKexThumbprint = macKexThumbprint
        self.nonce = nonce
        self.createdAt = createdAt
    }

    /// What the QR image actually carries: the canonical payload, base64url'd.
    /// The phone decodes it back to this field list and pins three of the
    /// fields; the six words then prove both sides agree on all of them.
    public var qrText: String {
        RemoteBase64URL.encode(CanonicalDigest.encode(RemoteApprovalDigests.pairingPayloadFields(self)))
    }

    public func isFresh(at now: Int) -> Bool {
        now >= createdAt && now - createdAt <= Self.validitySeconds
    }
}

/// P2's inputs: the nonce, the Mac's two thumbprints and the phone's five.
///
/// **All five phone thumbprints, not three** (DB-L29): §2.4's pin record is
/// `(phoneDeviceId, phoneSig, phoneSigw, phoneApv, phoneSum, phoneSum2)`, and
/// every one of them is in the SAS, so the owner's single comparison covers the
/// whole pin.
public struct RemoteSASInputs: Codable, Hashable, Sendable {
    public let nonce: String
    public let macSigThumbprint: String
    public let macKexThumbprint: String
    public let phoneSigThumbprint: String
    public let phoneSigwThumbprint: String
    public let phoneApvThumbprint: String
    public let phoneSumThumbprint: String
    public let phoneSum2Thumbprint: String

    public init(nonce: String, macSigThumbprint: String, macKexThumbprint: String, phoneSigThumbprint: String, phoneSigwThumbprint: String, phoneApvThumbprint: String, phoneSumThumbprint: String, phoneSum2Thumbprint: String) {
        self.nonce = nonce
        self.macSigThumbprint = macSigThumbprint
        self.macKexThumbprint = macKexThumbprint
        self.phoneSigThumbprint = phoneSigThumbprint
        self.phoneSigwThumbprint = phoneSigwThumbprint
        self.phoneApvThumbprint = phoneApvThumbprint
        self.phoneSumThumbprint = phoneSumThumbprint
        self.phoneSum2Thumbprint = phoneSum2Thumbprint
    }
}

public enum RemoteRevocationReason: String, Codable, Hashable, Sendable, CaseIterable {
    case owner, lost, rotated
}

/// P3's inputs.
public struct RemoteRevocationStatement: Codable, Hashable, Sendable {
    public let accountSubject: String
    public let revokedDeviceId: String
    public let revokedAtEpochSeconds: Int
    public let revokingDeviceId: String
    /// Monotonically increasing per revoking device. A statement whose serial is
    /// ≤ the highest seen from that signer is ignored (§2.6 rule 3), and a Touch
    /// ID clearance **never resets the watermark** (rule 5).
    public let serial: Int
    public let reason: RemoteRevocationReason

    public init(accountSubject: String, revokedDeviceId: String, revokedAtEpochSeconds: Int, revokingDeviceId: String, serial: Int, reason: RemoteRevocationReason) {
        self.accountSubject = accountSubject
        self.revokedDeviceId = revokedDeviceId
        self.revokedAtEpochSeconds = revokedAtEpochSeconds
        self.revokingDeviceId = revokingDeviceId
        self.serial = serial
        self.reason = reason
    }
}

/// P8's inputs.
public struct RemoteSummaryEnvelopeInfo: Codable, Hashable, Sendable {
    public let pendingId: String
    public let accountSubject: String
    public let macDeviceId: String
    public let phoneDeviceId: String
    /// `sum` for an ordinary summary, `sum2` for a sensitive one.
    public let recipientThumbprint: String
    public let issuedAt: Int

    public init(pendingId: String, accountSubject: String, macDeviceId: String, phoneDeviceId: String, recipientThumbprint: String, issuedAt: Int) {
        self.pendingId = pendingId
        self.accountSubject = accountSubject
        self.macDeviceId = macDeviceId
        self.phoneDeviceId = phoneDeviceId
        self.recipientThumbprint = recipientThumbprint
        self.issuedAt = issuedAt
    }
}

/// P9's inputs.
public struct RemoteConnectEnvelopeInfo: Codable, Hashable, Sendable {
    public let connectRequestId: String
    public let accountSubject: String
    public let macDeviceId: String
    public let providerSlug: String
    public let phoneDeviceId: String
    public let macKexThumbprint: String
    public let fieldSchemaId: String

    public init(connectRequestId: String, accountSubject: String, macDeviceId: String, providerSlug: String, phoneDeviceId: String, macKexThumbprint: String, fieldSchemaId: String) {
        self.connectRequestId = connectRequestId
        self.accountSubject = accountSubject
        self.macDeviceId = macDeviceId
        self.providerSlug = providerSlug
        self.phoneDeviceId = phoneDeviceId
        self.macKexThumbprint = macKexThumbprint
        self.fieldSchemaId = fieldSchemaId
    }
}

/// P10's inputs.
public struct RemoteConnectContext: Codable, Hashable, Sendable {
    public let connectRequestId: String
    public let accountSubject: String
    public let macDeviceId: String
    public let phoneDeviceId: String
    public let providerSlug: String
    public let capability: String
    public let fieldSchemaId: String
    public let macKexThumbprint: String
    public let issuedAt: Int

    public init(connectRequestId: String, accountSubject: String, macDeviceId: String, phoneDeviceId: String, providerSlug: String, capability: String, fieldSchemaId: String, macKexThumbprint: String, issuedAt: Int) {
        self.connectRequestId = connectRequestId
        self.accountSubject = accountSubject
        self.macDeviceId = macDeviceId
        self.phoneDeviceId = phoneDeviceId
        self.providerSlug = providerSlug
        self.capability = capability
        self.fieldSchemaId = fieldSchemaId
        self.macKexThumbprint = macKexThumbprint
        self.issuedAt = issuedAt
    }
}

public enum RemoteDecisionVerdict: String, Codable, Hashable, Sendable, CaseIterable {
    case allow, deny
}

public enum RemoteDecisionScope: String, Codable, Hashable, Sendable, CaseIterable {
    case once, client, projects
}

/// `"none"` is a real value here, not an absence: a `once` decision carries no
/// duration and says so (§4.3 check 7).
public enum RemoteDecisionDuration: String, Codable, Hashable, Sendable, CaseIterable {
    case none, oneDay, twoDays, sevenDays
}

/// P7's inputs — the signed decision, exactly as the phone builds it.
public struct RemoteDecisionPayload: Codable, Hashable, Sendable {
    public let approvalRequestDigest: String
    public let summaryDigest: String
    public let decision: RemoteDecisionVerdict
    public let scope: RemoteDecisionScope
    public let scopeClientId: String?
    public let scopeProjectIds: [String]
    public let duration: RemoteDecisionDuration
    public let includeProduction: Bool
    /// **Exactly the bytes typed**, NFC-normalised (§4.3 step 8, §3.3 item 1c).
    /// Stripping it in transit must fail the signature, which is A24's test.
    public let typedEnvironmentName: String?
    public let includedMutations: [String]
    public let choiceId: String?
    public let decisionId: String
    public let issuedAt: Int
    public let expiresAt: Int
    public let accountSubject: String
    public let macDeviceId: String
    /// **Relay-supplied and verified, not sourced** (checklist 15, DB-M27). The
    /// Mac has no state saying which phone decided; it learns it from the
    /// Worker, and check 2 is what makes that safe.
    public let decidingDeviceId: String
    /// The wire copy exists only so a mismatch produces a clear error rather
    /// than a signature failure. **The verifying key comes from the pin.**
    public let apvThumbprint: String

    public init(approvalRequestDigest: String, summaryDigest: String, decision: RemoteDecisionVerdict, scope: RemoteDecisionScope, scopeClientId: String?, scopeProjectIds: [String], duration: RemoteDecisionDuration, includeProduction: Bool, typedEnvironmentName: String?, includedMutations: [String], choiceId: String?, decisionId: String, issuedAt: Int, expiresAt: Int, accountSubject: String, macDeviceId: String, decidingDeviceId: String, apvThumbprint: String) {
        self.approvalRequestDigest = approvalRequestDigest
        self.summaryDigest = summaryDigest
        self.decision = decision
        self.scope = scope
        self.scopeClientId = scopeClientId
        self.scopeProjectIds = scopeProjectIds
        self.duration = duration
        self.includeProduction = includeProduction
        self.typedEnvironmentName = typedEnvironmentName
        self.includedMutations = includedMutations
        self.choiceId = choiceId
        self.decisionId = decisionId
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.accountSubject = accountSubject
        self.macDeviceId = macDeviceId
        self.decidingDeviceId = decidingDeviceId
        self.apvThumbprint = apvThumbprint
    }
}

// MARK: - base64url, without padding

/// The one spelling of base64url in this protocol. Kept here rather than reached
/// for ad hoc, because a padded thumbprint and an unpadded one are two different
/// strings and both sides digest the string.
public enum RemoteBase64URL {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ string: String) -> Data? {
        var value = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while value.count % 4 != 0 { value.append("=") }
        return Data(base64Encoded: value)
    }
}
