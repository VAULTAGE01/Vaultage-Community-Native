import Foundation

// BL-094 / owner decision D36, guarantee 2 — "deliver to where it runs".
//
// > Binding a vault item or provisioned resource to a cloud environment offers
// > "Deliver to {provider} secrets" as a typed mutation (generalising BL-051's
// > Worker-secret PUT): preflight the exact target, write, verify by listing
// > names (never values), receipt.
//
// This file is the shape of one delivery: what is asked for, what the sheet
// says, and what comes back. `VaultageBroker.deliverCredential` performs it.
//
// **Two doors, one path (D71).** The delivery class is native-approval every
// time and nothing a grant could ever cover. The owner reaches it from the
// environment card (`deliverCredential`); an agent reaches it through
// `vaultage_deliver` (`deliverForAgent`), which runs the identical preflight,
// sheet, write, verification and ledger write and differs in one rule — the
// source. The owner picks any item that holds a value, and the sheet naming
// it is the authorization; an agent may name only an item the owner allowed
// for that binding in the app (`AgentSources`). `vaultage_execute` carries no
// delivery at all: the individual write operations it once exposed for Vercel
// and Cloudflare are reachable only through this path now.
//
// **Where the value goes, and the only place it goes.** The value is read from
// the Keychain inside the broker, handed to the adapter as a `VaultSecret`, and
// assembled into the request body inside the existing self-zeroing
// `SecretPayloadBuilder`. It is not a field on any type in this file, not a
// receipt field, not a ledger field, and not a projection field. The three
// types here carry identifiers, names and labels.

// MARK: - The request

/// One delivery: this vault item's value, into that destination.
/// Which door a delivery came through (D71).
///
/// Both doors run the same delivery — the check before the write, one native
/// sheet, the write, the check after it, the ledger row. What differs is the
/// **source rule**: in the app, the person's pick and the sheet that names it
/// are the authorization; an agent may name only a source the owner allowed
/// for that binding (`RuntimeSourceAuthorization`). The door is declared by
/// Vaultage's own code at the door — the desktop app, or the MCP server — and
/// never by the agent: no tool argument names it.
public enum DeliveryDoor: String, Codable, Sendable {
    case owner, agent
}

public struct CredentialDeliveryRequest: Codable, Sendable, Hashable {
    public let projectID: UUID
    public let environmentID: UUID
    /// The binding whose connection holds the credential that is allowed to
    /// write this store, and whose immutable scope is the container written to.
    public let bindingID: UUID
    /// The vault item whose value is delivered. Through the owner's door, any
    /// item that holds a value; through the agent's, only one the owner allowed
    /// for this exact binding (`RuntimeSourceAuthorization`), so an agent
    /// cannot move an unrelated production password into somebody's preview.
    public let sourceVaultItemID: UUID
    /// **CC-H6** — which single field of a composite source is delivered.
    ///
    /// Required exactly when the source item's stored value is a composite
    /// envelope, and refused when it is not. **One named half per approval.**
    /// See `CredentialDeliverySource` for the rule and for why the whole
    /// envelope is never a deliverable value.
    public let sourceField: CompositeCredentialField?
    /// The entry's name at the provider.
    public let destinationName: String
    /// Required exactly when the store has a target axis. **One target per
    /// delivery, and therefore per approval.**
    public let target: DeliveryTarget?
    /// Set when this delivery is one step of a rotation, so the receipt and the
    /// ledger row can be attributed to it.
    public let rotationID: UUID?

    public init(projectID: UUID, environmentID: UUID, bindingID: UUID, sourceVaultItemID: UUID, sourceField: CompositeCredentialField? = nil, destinationName: String, target: DeliveryTarget? = nil, rotationID: UUID? = nil) {
        self.projectID = projectID
        self.environmentID = environmentID
        self.bindingID = bindingID
        self.sourceVaultItemID = sourceVaultItemID
        self.sourceField = sourceField
        self.destinationName = destinationName
        self.target = target
        self.rotationID = rotationID
    }
}

// MARK: - Which half of a composite is delivered

/// **CC-H6** — the field selector the delivery path did not have.
///
/// The independent pass on BL-117's design
/// (`evidence/security-review-bl117-design-2026-09-14.md`, Q9 and CC-H6) found
/// that `Broker.deliverCredential` read `vault.read(account:…)` — *the whole
/// stored value* — with no `withCompositeField` anywhere on the path and no
/// `isComposite` guard anywhere in `Broker.swift`. For a composite item that
/// value is the `VLTC1` envelope: magic, field count, tags, lengths and **both**
/// field bytes. Every byte of it is below `0x80` for an ASCII credential, so it
/// is valid UTF-8, `SecretPayloadBuilder.appendJSONString(of:)` accepts it, and
/// a delivery of a Twilio credential would have written a binary envelope
/// carrying the Auth Token into an environment variable named for the Account
/// SID. **That was live before BL-117** — Twilio is composite and shippable
/// today — which is why this closes on BL-094's lane rather than BL-117's.
///
/// Three rules, and they are the whole of it:
///
/// 1. **A composite source without a `sourceField` is refused.** Never the
///    envelope, not even "as a fallback": there is no destination for which an
///    envelope is the right value, and a delivery that guessed a field would be
///    a delivery the approval did not name.
/// 2. **A single-token source with a `sourceField` is refused.** The sheet
///    names the field, so naming one for a credential that has no halves would
///    put a sentence on the sheet that is not true of the value delivered.
/// 3. **`.token` is never a `sourceField`.** It is the *whole* of a
///    single-token credential rather than a half of anything, and
///    `withCompositeField(.token)` on a bare token deliberately borrows the
///    entire value — which is exactly the outcome rule 1 exists to prevent.
///    Refused on shape, before any record is resolved.
///
/// With those, §4.4 item 1's conservative default — **two approved deliveries
/// for an access-key pair**, one name, one value, one sheet, each truthful — is
/// correct and implementable.
///
/// **Where the test lives, and why it is on the bytes.** Whether an item is
/// composite is a fact about what is in the Keychain record, not about
/// metadata: `VaultageCore` cannot see a provider manifest's `custodyKind`
/// (`VaultageProviders` depends on this module, not the other way round), and a
/// metadata field claiming compositeness would be a second source of truth that
/// could disagree with the record. So the test is `VaultSecret.isComposite` on
/// the value the broker just read, run **after** the read and **before** any
/// egress — the same position as the delivery's other pre-egress proofs. A
/// refusal there costs the human a sheet they had already approved, which is
/// the right price: nothing is sent, the receipt says why, and the alternative
/// is a guess.
public enum CredentialDeliverySource {

    /// Rules 3 and 4, checked on shape alone so they refuse before a record is
    /// resolved, a sheet is raised or a Keychain record is opened.
    public static func validate(_ field: CompositeCredentialField?) throws {
        guard let field else { return }
        guard field != .token else { throw VaultageError.invalidInput(tokenIsNotAHalf) }
        // Rule 4 — BL-117's GitHub slot, §4.4 item 4.
        guard field != .refreshToken else { throw VaultageError.policyDenied(userGrantIsNotDeliverable) }
    }

    /// The exact bytes this delivery sends: one named field of a composite, or
    /// the whole of a credential that has no fields.
    ///
    /// The half is copied out of the envelope through `withCompositeField`'s
    /// scoped borrow into a `VaultSecret` of its own, which pins and zeroes its
    /// allocation like every other credential in this product. The envelope
    /// itself is never handed to an adapter, a builder or a transport.
    public static func delivered(
        _ value: VaultSecret,
        field: CompositeCredentialField?,
        sourceLabel: String
    ) throws -> VaultSecret {
        try validate(field)
        guard value.isComposite else {
            // Rule 2. A bare token is delivered whole, exactly as it always
            // was, and only when the approval did not claim otherwise.
            guard field == nil else { throw VaultageError.policyDenied(notCompositeRefusal(sourceLabel)) }
            return value
        }
        // Rule 1.
        guard let field else { throw VaultageError.policyDenied(envelopeRefusal(sourceLabel)) }
        var half: VaultSecret?
        try value.withCompositeField(field) { half = VaultSecret(bytes: $0) }
        guard let half, half.byteCount > 0 else {
            throw VaultageError.invalidInput("\"\(sourceLabel)\" has no \(field.defaultLabel) to deliver.")
        }
        return half
    }

    public static func envelopeRefusal(_ sourceLabel: String) -> String {
        "\"\(sourceLabel)\" holds more than one field, and what is stored for it is an envelope carrying every one of them. A delivery writes one named field into one named destination, so this delivery has to say which. Nothing was read out and nothing was sent."
    }

    public static func notCompositeRefusal(_ sourceLabel: String) -> String {
        "\"\(sourceLabel)\" holds one value rather than named fields, so a delivery of it cannot name one. Nothing was sent."
    }

    public static let tokenIsNotAHalf = "A delivery names one field of a composite credential. The single-token field is the whole of a credential that has no fields, so it is never a delivery's source field."

    /// BL-117's GitHub slot — **§4.4 item 4, as a compiled shape rule.**
    ///
    /// *"`authorizationCodePKCE` connections deliver nothing, and the
    /// environment card says so in a sentence rather than showing an empty
    /// affordance: a user grant is a human's authority, it is revoked when they
    /// leave, and no production runtime should depend on one."*
    ///
    /// It is expressed on the **field** rather than on the connection's class
    /// for the reason the rest of this type is: `VaultageCore` cannot see a
    /// provider manifest's `credentialClass`, and a metadata field claiming one
    /// would be a second source of truth that could disagree with the record. A
    /// user grant's two halves are `.token` and `.refreshToken`, so rule 3
    /// refuses the first and this refuses the second — which makes "a user grant
    /// delivers nothing" a property of the two rules together rather than a
    /// class lookup this module cannot perform.
    ///
    /// The **short-lived** half needs no rule here at all and that is worth
    /// saying: an exchanged access token is never written to a vault item, so
    /// no `sourceVaultItemID` can ever name one. §4.4's prohibition on
    /// delivering one is satisfied by there being nothing to name.
    public static let userGrantIsNotDeliverable = "This connection is a person's own authority at the provider, granted in a browser and revoked when they leave. It is not a credential a production runtime should depend on, so Vaultage will not write either half of it into an environment. Nothing was read out and nothing was sent."

    /// The sentence the sheet carries whenever a delivery names a field, so the
    /// human is told why an access-key pair is two approvals rather than one —
    /// the same service `DeliveryDestination.oneTargetPerApprovalRationale`
    /// performs for the target axis.
    public static let oneFieldPerApprovalRationale = "This approval covers one field of this credential. Delivering its other field is a second approval, naming its own destination and its own field, because one approval covering every field would be a wider thing than the sentence above describes."
}

public extension CompositeCredentialField {
    /// A stable, injective spelling for a request digest, an MCP argument and a
    /// `--run` command line.
    ///
    /// Built from the raw value rather than from the case name: the raw values
    /// are already stable on disk (they are written into the envelope) and a
    /// case added later — BL-117's `keyIdentifier`, `privateKey`,
    /// `refreshToken` — gets a name here without this switch having to be
    /// exhaustive, so adding one cannot break the build on another lane.
    /// `CredentialDeliveryContracts` asserts the names are unique and round
    /// trip for **every** case, including one this table does not yet spell.
    var wireName: String { Self.wireNames[self] ?? "field\(rawValue)" }

    /// The field a wire name denotes, or nil. Unknown text is nil rather than a
    /// default: an argument Vaultage does not understand is a refusal.
    static func named(_ wireName: String) -> CompositeCredentialField? {
        allCases.first { $0.wireName == wireName }
    }

    private static var wireNames: [CompositeCredentialField: String] {
        [.token: "token", .identifier: "identifier", .secret: "secret", .document: "document"]
    }
}

// MARK: - The sheet

/// What the native delivery sheet says. Every string is built from resolved
/// local records and from a destination that has already passed
/// `DeliveryDestination.isWellFormed`; nothing here is provider text and
/// nothing here is agent-supplied.
public struct CredentialDeliveryDisclosure: Codable, Sendable, Hashable {
    /// Line 1, D34's copy rule: the resource. "Environment variable
    /// UPSTREAM_API_KEY (production) on checkout-web".
    public let destinationLine: String
    /// Line 2: the action, naming the vault item the value comes from.
    public let actionLine: String
    /// Line 3: the safety sentence, which is also the continuity promise.
    public let safetyLine: String
    public let sourceLabel: String
    public let sourceVaultItemID: UUID
    /// **CC-H6.** What the delivered field is called, or nil for a source that
    /// has no fields. Present exactly when `actionLine` names a field, so a
    /// projection cannot show one without the other.
    public let sourceFieldLabel: String?
    /// The one-field-per-approval rationale, present exactly when
    /// `sourceFieldLabel` is.
    public let sourceFieldNote: String?
    public let destination: DeliveryDestination
    public let project: String
    public let environment: String
    /// The Vaultage environment is a production one.
    public let isProductionEnvironment: Bool
    /// The provider *target* serves live traffic, which is a separate fact: a
    /// human may deliver to Vercel's production target from an environment they
    /// called staging.
    public let isLiveTrafficTarget: Bool
    public let productionWarning: String?
    /// Present whenever the store has a target axis, so the human is told why
    /// three targets is three approvals.
    public let targetNote: String?
    /// The sentence for a store the provider reads back with values.
    public let valueDisclosure: String?
    /// Present when this delivery is a rotation step, naming which and how many.
    public let rotationNote: String?
    public let requestDigest: String
    /// D71. Set on the agent's door only: who asked, and that approving here
    /// is the whole of the agent's authorization.
    public let requesterNote: String?

    public init(destinationLine: String, actionLine: String, safetyLine: String, sourceLabel: String, sourceVaultItemID: UUID, sourceFieldLabel: String? = nil, sourceFieldNote: String? = nil, destination: DeliveryDestination, project: String, environment: String, isProductionEnvironment: Bool, isLiveTrafficTarget: Bool, productionWarning: String?, targetNote: String?, valueDisclosure: String?, rotationNote: String?, requestDigest: String, requesterNote: String? = nil) {
        self.destinationLine = destinationLine
        self.actionLine = actionLine
        self.safetyLine = safetyLine
        self.sourceLabel = sourceLabel
        self.sourceVaultItemID = sourceVaultItemID
        self.sourceFieldLabel = sourceFieldLabel
        self.sourceFieldNote = sourceFieldNote
        self.destination = destination
        self.project = project
        self.environment = environment
        self.isProductionEnvironment = isProductionEnvironment
        self.isLiveTrafficTarget = isLiveTrafficTarget
        self.productionWarning = productionWarning
        self.targetNote = targetNote
        self.valueDisclosure = valueDisclosure
        self.rotationNote = rotationNote
        self.requestDigest = requestDigest
        self.requesterNote = requesterNote
    }

    /// The safety line every delivery sheet carries. The second sentence is
    /// D36's promise, stated where the human is deciding rather than only in
    /// the docs — the ticket asks for "copy that states the guarantee".
    public static let safetySentence = "The value is read from the named vault item on this Mac and sent only to the provider. It never travels through MCP, never reaches an agent, and is never written to a receipt or a log. Once it is there, the deployment reads it from the provider: nothing at runtime calls this Mac, so it keeps working with Vaultage quit and this laptop shut."

    public static let productionSentence = "WARNING: this environment is production. Replacing this value takes effect on live traffic."

    public static let liveTrafficSentence = "WARNING: this delivery targets the provider's production target, which serves live traffic."

    /// Cloudflare's own deployment behaviour, carried over from BL-051 because
    /// the human still needs telling.
    public static let immediateDeploymentSentence = "Cloudflare creates and deploys a new Worker version immediately when this secret is written."

    /// Vercel's, which is the opposite and is just as important.
    public static let deploymentNeededSentence = "Vercel applies this to the next build. A deployment already running keeps the value it was built with until it is redeployed."

    /// GitHub's (BL-128 slice 3c): when it takes effect, and the one custody
    /// fact that differs from the other two stores — the value is sealed here.
    public static let nextWorkflowRunSentence = "GitHub Actions uses it for every job that starts after this; a job already running keeps the value it started with. It is sealed on this Mac to the repository's own public key before it is sent, and GitHub never shows it back."

    public static let valueReturningStoreSentence = "Vercel returns environment-variable values on the route Vaultage uses to check this destination. Vaultage drops every value-bearing field inside the transport, so no value reaches this sheet, the result, the receipt or the ledger."
}

// MARK: - The outcome

/// What one delivery did. Value-free.
public struct CredentialDeliveryOutcome: Codable, Hashable, Sendable {
    /// The ledger row this delivery wrote or replaced.
    public let ledgerRowID: UUID
    public let destination: DeliveryDestination
    /// The operation that actually ran, decided by the preflight:
    /// `vercel.env.create` for a name that was not there, `vercel.env.update`
    /// for one that was.
    public let operation: String
    /// True when the preflight found the name already present, so this delivery
    /// replaced a value rather than adding one.
    public let replacedExistingEntry: Bool
    /// The identifier the provider returned, where it returns one.
    public let providerResourceID: String?
    /// Whether the post-write name list reported the destination.
    public let verified: Bool
    public let status: DeployedCredentialStatus
    public let deliveredAt: Date
    /// How many entries the destination's store held after the write. A count,
    /// never a list of names in a receipt.
    public let entryCountAfter: Int
    /// One sentence, for the Activity row and the environment card.
    public let effect: String

    public init(ledgerRowID: UUID, destination: DeliveryDestination, operation: String, replacedExistingEntry: Bool, providerResourceID: String?, verified: Bool, status: DeployedCredentialStatus, deliveredAt: Date, entryCountAfter: Int, effect: String) {
        self.ledgerRowID = ledgerRowID
        self.destination = destination
        self.operation = operation
        self.replacedExistingEntry = replacedExistingEntry
        self.providerResourceID = providerResourceID
        self.verified = verified
        self.status = status
        self.deliveredAt = deliveredAt
        self.entryCountAfter = entryCountAfter
        self.effect = effect
    }

    public var actionResult: ActionResult {
        ActionResult(summary: effect, fields: [
            "store": destination.store.rawValue,
            "destination": destination.name,
            "target": destination.target?.rawValue ?? "n/a",
            "scope": destination.scopeID,
            "operation": operation,
            "verified": verified ? "true" : "false",
            "status": status.rawValue
        ])
    }
}

/// What "verify deployed" found for one environment.
public struct DeployedVerificationReport: Codable, Hashable, Sendable {
    public struct Row: Codable, Hashable, Sendable {
        public let ledgerRowID: UUID
        public let destination: DeliveryDestination
        public let outcome: Outcome
        public let detail: String
        public init(ledgerRowID: UUID, destination: DeliveryDestination, outcome: Outcome, detail: String) {
            self.ledgerRowID = ledgerRowID
            self.destination = destination
            self.outcome = outcome
            self.detail = detail
        }
    }

    public enum Outcome: String, Codable, Sendable, CaseIterable {
        /// The name list reported the destination.
        case present
        /// The name list ran and did not report it.
        case absent
        /// The list could not be run at all — the binding is gone, the
        /// connection is unverified, the provider failed. Deliberately not
        /// `absent`: "we looked and it was not there" and "we could not look"
        /// are different answers, and only one of them is about the deployment.
        case notChecked = "not-checked"
    }

    public let environmentID: UUID
    public let checkedAt: Date
    public let rows: [Row]
    /// Advisory health after the sweep.
    public let health: DeliveryHealth
    public let message: String

    public init(environmentID: UUID, checkedAt: Date, rows: [Row], health: DeliveryHealth, message: String) {
        self.environmentID = environmentID
        self.checkedAt = checkedAt
        self.rows = rows
        self.health = health
        self.message = message
    }

    public var present: Int { rows.filter { $0.outcome == .present }.count }
    public var absent: Int { rows.filter { $0.outcome == .absent }.count }
    public var notChecked: Int { rows.filter { $0.outcome == .notChecked }.count }
}

// MARK: - What a rotation asks for

public struct CredentialRotationRequest: Codable, Sendable, Hashable {
    /// The vault item being rotated away from. Every ledger row it feeds
    /// becomes a step.
    public let oldVaultItemID: UUID
    /// The vault item holding the new value. It exists already: rotation never
    /// mints. Where the provider supports minting, BL-074's
    /// `createProviderResource` runs first, in its own approval and its own
    /// class, and its created item is named here.
    public let newVaultItemID: UUID
    public let origin: RotationValueOrigin

    public init(oldVaultItemID: UUID, newVaultItemID: UUID, origin: RotationValueOrigin) {
        self.oldVaultItemID = oldVaultItemID
        self.newVaultItemID = newVaultItemID
        self.origin = origin
    }
}

/// One turn of the rotation: what it did, and what it is waiting for.
public struct CredentialRotationProgress: Codable, Hashable, Sendable {
    public let rotation: CredentialRotation
    /// The deliveries this turn performed, in order.
    public let delivered: [CredentialDeliveryOutcome]
    /// True when every destination is delivered and verified and the old
    /// credential may now be revoked.
    public let mayRevokeOldCredential: Bool
    /// Why not, when not.
    public let blockedReason: String?
    /// The words for the final button, once it is offered.
    public let providerRevocationPrompt: String
    public let message: String

    public init(rotation: CredentialRotation, delivered: [CredentialDeliveryOutcome], mayRevokeOldCredential: Bool, blockedReason: String?, providerRevocationPrompt: String, message: String) {
        self.rotation = rotation
        self.delivered = delivered
        self.mayRevokeOldCredential = mayRevokeOldCredential
        self.blockedReason = blockedReason
        self.providerRevocationPrompt = providerRevocationPrompt
        self.message = message
    }
}

// MARK: - D71: the sources an agent may deliver

/// The vault items an agent may deliver from one binding: the
/// `RuntimeSourceAuthorization` records the owner writes for it.
///
/// A record grants nothing by itself — every delivery still raises its own
/// native sheet — and the owner never needs one (the pick in the app and the
/// sheet naming it are the authorization). It is the agent's rule alone, which
/// is why it is written here, by the owner, and not by a delivery.
public enum AgentSources {
    public static func allowed(for bindingID: UUID, in state: VaultageMetadata) -> [RuntimeSourceAuthorization] {
        state.runtimeSourceAuthorizations.filter { $0.bindingID == bindingID }
    }

    /// Allows `itemID` as a source an agent may deliver from `bindingID`.
    /// Refused when the binding allows no delivery (there would be nothing to
    /// deliver), when the item does not exist, holds no value, is on its way
    /// out, or is the connection's own token. Allowing twice is once.
    @discardableResult
    public static func allow(_ itemID: UUID, for bindingID: UUID, in state: inout VaultageMetadata) throws -> RuntimeSourceAuthorization {
        guard let binding = state.bindings.first(where: { $0.id == bindingID }) else {
            throw VaultageError.invalidInput("That binding no longer exists.")
        }
        guard binding.allowedOperations.contains(where: \.isDelivery) else {
            throw VaultageError.policyDenied("This binding allows no delivery, so there is nothing an agent could deliver from it. Allow a delivery operation first.")
        }
        guard let connection = state.connections.first(where: { $0.id == binding.connectionID }) else {
            throw VaultageError.invalidInput("That binding's connection no longer exists.")
        }
        guard let item = state.vaultItems.first(where: { $0.id == itemID }), item.hasProtectedValue,
              MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil else {
            throw VaultageError.invalidInput("That vault item does not exist, holds no value, or is being deleted.")
        }
        guard item.id != connection.vaultItemID else {
            throw VaultageError.policyDenied("The connection's own credential cannot be a source for its own destination.")
        }
        if let existing = allowed(for: bindingID, in: state).first(where: { $0.sourceVaultItemID == itemID }) { return existing }
        let record = RuntimeSourceAuthorization(sourceVaultItemID: itemID, bindingID: binding.id, projectID: binding.projectID, environmentID: binding.environmentID)
        state.runtimeSourceAuthorizations.append(record)
        return record
    }

    /// Withdraws `itemID` from the sources an agent may deliver from
    /// `bindingID`. Nothing already delivered changes: the ledger row and the
    /// value at the provider stay, and only the agent's next request refuses.
    @discardableResult
    public static func disallow(_ itemID: UUID, for bindingID: UUID, in state: inout VaultageMetadata) -> Bool {
        let before = state.runtimeSourceAuthorizations.count
        state.runtimeSourceAuthorizations.removeAll { $0.bindingID == bindingID && $0.sourceVaultItemID == itemID }
        return state.runtimeSourceAuthorizations.count < before
    }
}

