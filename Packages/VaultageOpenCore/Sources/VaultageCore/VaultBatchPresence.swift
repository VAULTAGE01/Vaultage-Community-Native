import Foundation

// BL-100 slice A — §2.4.1's presence rule, expressed around the **context
// instance** (`13-MULTI-DEVICE-CUSTODY.md` version 17 §2.4.1; third pass,
// DB3-C1).
//
// > **Every `vkx` operation that opens an item key uses a `LAContext` instance
// > created for that operation and used for no other**, evaluated with reuse
// > duration `0`, and released when the operation returns. **Reuse duration `0`
// > on a shared instance is not the control and does not satisfy this rule.**
//
// The reuse duration is the wrong knob: it bounds how long an evaluated context
// stays good, and it does not create sharing. What produces one prompt for two
// operations is **one instance**, evaluated once and handed to both — which is
// what PF-9 (b) measured, and what PF-9 (×) extended to a *second, different*
// key. So an evaluated context is a **process-wide capability over every
// presence-gated Enclave key the process can reach**, the subject set has no
// backing in the platform, and the binding has to be structural.

// MARK: - Subjects

/// A `value` record's subject — `(keychainAccount, credentialVersion)`, §3.1's
/// rule. **A field whose `keychainAccount` equals the item's produces no
/// separate record**: it *is* the primary.
public struct ValueSubject: Hashable, Sendable {
    public let keychainAccount: String
    public let credentialVersion: UUID?

    public init(keychainAccount: String, credentialVersion: UUID?) {
        self.keychainAccount = keychainAccount
        self.credentialVersion = credentialVersion
    }

    public var recordSubject: VaultRecordSubject {
        .value(keychainAccount: keychainAccount, credentialVersion: credentialVersion)
    }
}

/// Flow 5's Phase 2 verification reads a `.userPresence` **Keychain** record
/// through `kSecUseAuthenticationContext`, not an item key through `vkx`. A
/// subject is therefore a **kind**, and membership is checked against the kind
/// as well as the identity.
public struct KeychainSubject: Hashable, Sendable {
    public let account: String
    public init(account: String) { self.account = account }
}

/// Flow 7's, and flow 7's only.
public struct VaultSubject: Hashable, Sendable {
    public let vaultID: UUID
    public init(vaultID: UUID) { self.vaultID = vaultID }
}

/// **A three-case sum type** (twelfth pass, DB12-M2). Version 13 typed
/// `subjects` as `Set<ValueSubject>` fifty lines below a bullet saying flow 7's
/// set is *"**not** a set of `ValueSubject`s"*, and two things BL-100 tests rest
/// on the set being able to hold all three kinds: the prompt count is derived
/// from `subjects.count`, and membership is checked against the **kind** as
/// well as the identity. A builder widening it under deadline reaches for an
/// untyped identifier set, which deletes the kind check that is the point.
public enum PresenceSubject: Hashable, Sendable {
    case value(ValueSubject)
    case keychain(KeychainSubject)
    case vault(VaultSubject)

    public enum Kind: String, Sendable, CaseIterable { case value, keychain, vault }

    public var kind: Kind {
        switch self {
        case .value: .value
        case .keychain: .keychain
        case .vault: .vault
        }
    }
}

// MARK: - The flows

/// **The reason is rendered by the machinery from typed parameters, never
/// passed as a string** (fifth pass, DB5-M1). `flow` carries what the prompt
/// must name, and the machinery renders the localized reason from those and
/// from `subjects.count`. A prompt that names the wrong destination is
/// unrepresentable, for the same reason a count that lies is.
public enum BatchFlow: Hashable, Sendable {
    /// 1 — the Mac must open every pinned `IK` to re-wrap it to the new device.
    case pair(deviceName: String)
    /// 2 — re-wrapping every item key to the remaining devices **and to
    /// `RK_v(g+1)`, in the same traversal**.
    case rekey(vaultName: String)
    /// 3 — the first kit for a generation wraps `RK_v.private`.
    case recoveryKit(vaultName: String)
    /// 4 — **the one flow whose subject set leaves the device**, so the prompt
    /// names the destination the owner chose in a system file picker.
    case export(destination: URL)
    /// 5 — the measured chunk of the five-phase migration.
    case migrationChunk(from: Int, to: Int, total: Int, vaultName: String)
    /// 6 — re-sealing queued records at a new generation must decrypt them.
    case transcode(queued: Int)
    /// **7 — open the vault's metadata plane.** The prompt names **the vaults,
    /// never a credential count**.
    case metadataPlane(vaults: [String])

    /// **All seven**, so the enumeration test sees seven flows rather than six
    /// plus an exception.
    public static let allFlowNames = ["pair", "rekey", "recoveryKit", "export", "migrationChunk", "transcode", "metadataPlane"]

    public var name: String {
        switch self {
        case .pair: "pair"
        case .rekey: "rekey"
        case .recoveryKit: "recoveryKit"
        case .export: "export"
        case .migrationChunk: "migrationChunk"
        case .transcode: "transcode"
        case .metadataPlane: "metadataPlane"
        }
    }

    /// **Each flow's row fixes which cases its set may contain**, so a flow that
    /// smuggles a value subject into flow 7's set fails rather than prompting
    /// for the wrong thing.
    public var admissibleKinds: Set<PresenceSubject.Kind> {
        switch self {
        case .pair, .rekey, .recoveryKit, .export, .transcode: [.value]
        case .migrationChunk: [.keychain]
        case .metadataPlane: [.vault]
        }
    }

    /// The localized reason, rendered here and nowhere else. **The count is
    /// derived from `subjects.count`**, never passed alongside it, so
    /// *"Share 3 credentials"* over a 214-member set is unrepresentable.
    public func reason(subjectCount: Int) -> String {
        switch self {
        case .pair(let deviceName):
            "Share \(subjectCount) credentials with \(deviceName)?"
        case .rekey(let vaultName):
            "Re-key \(subjectCount) credentials in \(vaultName)?"
        case .recoveryKit(let vaultName):
            "Make a recovery kit covering \(subjectCount) credentials in \(vaultName)?"
        case .export(let destination):
            "Export \(subjectCount) credentials to \(destination.path)?"
        case .migrationChunk(let from, let to, let total, let vaultName):
            "Migrate items \(from)–\(to) of \(total) in \(vaultName)?"
        case .transcode(let queued):
            "Re-seal \(queued) queued changes?"
        case .metadataPlane(let vaults):
            // **The vaults, never a credential count.** One unlock shows these
            // vaults' names and structure on this device.
            "Show and update the names and structure of \(vaults.joined(separator: " and ")) on this Mac?"
        }
    }
}

// MARK: - The evaluated context, which the caller never holds

/// The machinery's private evaluated authentication.
///
/// **It cannot be constructed outside this module**, which is the structural
/// half of *"the caller never holds the evaluated `LAContext`"*: a caller that
/// obtained one could reach every presence-gated key in the process, per PF-9
/// (×), whatever the subject set said.
public final class EvaluatedPresence: @unchecked Sendable {
    /// The platform object, owned privately. There is **no accessor** and no
    /// conversion.
    private var handle: AnyObject?
    private(set) var isValid: Bool

    /// Constructible outside the module only so a `VaultKeyCustody`
    /// implementation and a headless harness can exist — **holding one buys
    /// nothing**, because `platformContext` is internal and there is no
    /// accessor, no conversion and no way to reach the machinery's own
    /// instance. The control is that the **token** never yields it and that the
    /// spend points check membership themselves.
    public init(handle: AnyObject?) {
        self.handle = handle
        self.isValid = true
    }

    /// `invalidate()` on **every** exit path, including a throw. It bounds the
    /// *end* of the window; the opaque token bounds its *width*; the ceiling
    /// bounds its *duration*. None of the three alone is sufficient.
    func invalidate() {
        if let invalidatable = handle as? NSObject,
           invalidatable.responds(to: Selector(("invalidate"))) {
            invalidatable.perform(Selector(("invalidate")))
        }
        handle = nil
        isValid = false
    }

    /// What a custody implementation passes to the platform. Internal, so no
    /// caller of `VaultageCore` can reach it.
    var platformContext: AnyObject? { handle }
}

/// Constructs and evaluates a **fresh** context. The production implementation
/// is `LocalAuthenticationPresence`; the deterministic suite substitutes a
/// counting one, because a headless run cannot prompt.
///
/// **The injection point is here and not `OwnerAuthenticating`** (fifteenth
/// pass, DB15-M3): that seam is the shortcut the rule excludes, and a builder
/// resolving the contradiction alone keeps it.
public protocol PresenceEvaluating: Sendable {
    /// Must construct a context **created for this evaluation and used for no
    /// other**, at reuse duration `0`.
    func evaluate(reason: String) throws -> EvaluatedPresence
}

// MARK: - The token

/// **`BatchToken` is `~Copyable`**, passed `borrowing` into each unwrap and
/// consumed at flow exit. *"Cannot be carried out of the flow"* is then a
/// **compile error**, not an adjective — the standard version 5's
/// "non-escaping" could not meet, because that is a guarantee for closure
/// parameters and not for a copyable value.
///
/// **The token is not the context and cannot yield it.** There is no accessor,
/// no conversion and no `LAContext` in its stored properties; the spend points
/// reach the context through the machinery and check subject membership
/// **themselves**.
public struct BatchToken: ~Copyable {
    let flowID: UUID
    init(flowID: UUID) { self.flowID = flowID }
}

public enum BatchPresenceRefusal: Error, Equatable, Sendable, LocalizedError {
    case subjectKindNotAdmissibleForFlow(flow: String, kind: String)
    case notInThisFlow
    case subjectNotInSet
    case ceilingExpired(after: TimeInterval)
    case presenceDenied

    public var errorDescription: String? {
        switch self {
        case .subjectKindNotAdmissibleForFlow(let flow, let kind):
            "A \(kind) subject cannot be opened inside the \(flow) flow."
        case .notInThisFlow:
            "That authorization is not this flow's."
        case .subjectNotInSet:
            "That item was not one of the items you approved."
        case .ceilingExpired:
            "The unlock has expired. Vaultage will ask again to continue."
        case .presenceDenied:
            "Vaultage could not confirm it is you."
        }
    }
}

/// Where the key bytes come from, once presence has been proved.
///
/// **In slice A this is not a `vkx` unwrap**, because slice A creates no `vkx`
/// and writes no wrap addressed to one — that is slice B, and it is the one
/// irreversible act. The seam exists at slice A's first commit so slice B
/// replaces one implementation rather than threading a key through the
/// machinery afterwards.
public protocol VaultKeyCustody: Sendable {
    func itemKey(_ subject: ValueSubject, presence: EvaluatedPresence) throws -> VaultSecret
    func keychainValue(_ subject: KeychainSubject, presence: EvaluatedPresence) throws -> VaultSecret
    func vaultContentKey(_ subject: VaultSubject, presence: EvaluatedPresence) throws -> VaultSecret
}

/// §2.4.1's machinery. **All seven flows run in the broker** (fourth pass,
/// DB4-M7): a flow holds an evaluated context, and §2.4.2 says what that
/// reaches. Running one in the app process would put that capability in the
/// reader set O-8′ concedes; running it in the broker puts it beside `sig` and
/// `kex`, which is the set already governed by the XPC code-signing admission.
///
/// **On the phone there is no broker** (fifth pass, DB5-H8), so "the broker,
/// all seven" is a macOS answer. Flows 1, 2, 3 and 5 are structurally Mac-only;
/// BL-107 runs flows 4 and 6 in the containing app, and the machinery is
/// written so BL-107 inherits it without a fork.
public final class VaultBatchPresence: @unchecked Sendable {
    /// **Half the shipped `OwnerAuthentication.lifetime`**, enforced by the
    /// machinery. **All seven flows, not only flow 5.** When it expires the
    /// flow **checkpoints and re-prompts**; it never extends.
    public static let ceiling: TimeInterval = 30

    private let evaluator: any PresenceEvaluating
    private let custody: any VaultKeyCustody
    private let monotonic: any MonotonicClock
    private let lock = NSLock()

    private struct LiveFlow {
        let id: UUID
        let flow: BatchFlow
        let subjects: Set<PresenceSubject>
        let presence: EvaluatedPresence
        let deadline: TimeInterval
    }
    private var live: LiveFlow?

    public init(
        evaluator: any PresenceEvaluating,
        custody: any VaultKeyCustody,
        monotonic: any MonotonicClock = SystemMonotonicClock()
    ) {
        self.evaluator = evaluator
        self.custody = custody
        self.monotonic = monotonic
    }

    /// **The only way into a batch flow, and there is no `reason:`
    /// parameter** — the selector is `withBatchPresence(subjects:flow:)`
    /// (sixth pass, DB6-H6).
    ///
    /// It is `throws` rather than `rethrows`: the machinery has refusals of its
    /// own — a denied evaluation, a subject kind the flow does not admit — and
    /// a `rethrows` function cannot have them. §2.4.1's block writes
    /// `rethrows`; this lane's evidence records the divergence and why.
    public func withBatchPresence<R>(
        subjects: Set<PresenceSubject>,
        flow: BatchFlow,
        _ body: (borrowing BatchToken) throws -> R
    ) throws -> R {
        for subject in subjects where !flow.admissibleKinds.contains(subject.kind) {
            throw BatchPresenceRefusal.subjectKindNotAdmissibleForFlow(flow: flow.name, kind: subject.kind.rawValue)
        }
        let presence = try evaluator.evaluate(reason: flow.reason(subjectCount: subjects.count))
        let id = UUID()
        lock.lock()
        live = LiveFlow(id: id, flow: flow, subjects: subjects, presence: presence, deadline: monotonic.uptime + Self.ceiling)
        lock.unlock()
        // `invalidate()` on **every** exit path including a throw.
        defer {
            lock.lock()
            live?.presence.invalidate()
            live = nil
            lock.unlock()
        }
        let token = BatchToken(flowID: id)
        return try body(token)
    }

    /// **Each chunk constructs a fresh `LAContext` instance** — not *"its own
    /// evaluation"*, which is what version 7 wrote and which is not the control
    /// (sixth pass, DB6-M1). Per PF-9 (b), calling `evaluatePolicy` again on a
    /// **live shared instance** costs **no prompt**, so a builder who implements
    /// checkpointing by re-evaluating the machinery's retained context produces
    /// a flow that re-prompts zero times and holds the capability for its whole
    /// duration.
    ///
    /// **A subject set larger than one lifetime is split**, and the count in
    /// each chunk's prompt is that chunk's own.
    public func withChunkedBatchPresence<Subject, R>(
        subjects: [Subject],
        flow: BatchFlow,
        chunkSize: Int,
        makeSubject: (Subject) -> PresenceSubject,
        _ body: (borrowing BatchToken, Subject) throws -> R
    ) throws -> [R] {
        var results: [R] = []
        var index = 0
        while index < subjects.count {
            let end = min(index + max(chunkSize, 1), subjects.count)
            let chunk = Array(subjects[index ..< end])
            let set = Set(chunk.map(makeSubject))
            let produced = try withBatchPresence(subjects: set, flow: flow) { token in
                var chunkResults: [R] = []
                for subject in chunk { chunkResults.append(try body(token, subject)) }
                return chunkResults
            }
            results.append(contentsOf: produced)
            index = end
        }
        return results
    }

    // MARK: - The closed spend surface, fixed here

    /// §2.4.1's spend surface is a **closed set of three**, fixed by BL-100
    /// because BL-100 owns the type and BL-100's enumeration test asserts the
    /// call-site set **exactly** — a spend point discovered in BL-105 would be
    /// either a test failure or an allowlist edit under deadline.
    public func openItemKey(_ token: borrowing BatchToken, subject: ValueSubject) throws -> VaultSecret {
        let presence = try presence(for: token.flowID, subject: .value(subject))
        return try custody.itemKey(subject, presence: presence)
    }

    public func readKeychainAccount(_ token: borrowing BatchToken, account: KeychainSubject) throws -> VaultSecret {
        let presence = try presence(for: token.flowID, subject: .keychain(account))
        return try custody.keychainValue(account, presence: presence)
    }

    /// **The third is flow 7's, and its caller set is exactly flow 7.** It
    /// returns a **vault content key, never a credential**, so §3.2's *"the only
    /// two calls that return a credential"* is unchanged.
    public func openVaultContentKey(_ token: borrowing BatchToken, vault: VaultSubject) throws -> VaultSecret {
        let presence = try presence(for: token.flowID, subject: .vault(vault))
        return try custody.vaultContentKey(vault, presence: presence)
    }

    /// Membership is checked **here, inside**, against the kind as well as the
    /// identity. A caller holding the token cannot point it at a key of its own
    /// choosing.
    private func presence(for flowID: UUID, subject: PresenceSubject) throws -> EvaluatedPresence {
        lock.lock()
        defer { lock.unlock() }
        guard let live, live.id == flowID else { throw BatchPresenceRefusal.notInThisFlow }
        guard live.flow.admissibleKinds.contains(subject.kind) else {
            throw BatchPresenceRefusal.subjectKindNotAdmissibleForFlow(flow: live.flow.name, kind: subject.kind.rawValue)
        }
        guard live.subjects.contains(subject) else { throw BatchPresenceRefusal.subjectNotInSet }
        let now = monotonic.uptime
        guard now <= live.deadline else {
            throw BatchPresenceRefusal.ceilingExpired(after: Self.ceiling)
        }
        return live.presence
    }

    // MARK: - The non-batch path

    /// **Everything else — every reveal, every copy, every AutoFill, every
    /// delivery, every MCP-driven read — takes its own instance, one per
    /// credential.**
    ///
    /// **(ii) Non-shareability**, asserted by the type: this path **constructs
    /// its own context and cannot be passed one** — the parameter does not
    /// exist — and it takes **no `OwnerAuthentication`** either, because the
    /// shipped carrier returns the live `LAContext` after a software account
    /// check and, per §2.4.2's cross-key result, that context opens `vkx` too.
    public func openItemKeyOnce(subject: ValueSubject, reason: String) throws -> VaultSecret {
        let presence = try evaluator.evaluate(reason: reason)
        defer { presence.invalidate() }
        return try custody.itemKey(subject, presence: presence)
    }
}
