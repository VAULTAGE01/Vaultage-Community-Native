import Foundation
import CryptoKit
#if canImport(AppKit)
import AppKit
#endif

/// BL-062 — human-only reveal and copy.
///
/// This is the second Vaultage path that deliberately gives up the
/// no-secret-to-process property, and the first that gives up
/// no-secret-to-*screen*. Owner decision D10 requires it: humans retrieve
/// credentials for provider dashboards and login screens, and a vault with no
/// human path out is a vault the owner cannot use.
///
/// The whole security argument is structural, and it is stated once here.
///
/// **`HumanDisclosure` is not a member of `BrokerFacade`, and no broker
/// conforms to it.** `BrokerFacade` is the seam every agent-facing caller
/// depends on: the `--mcp` subprocess, `VaultageMCPServer`, the XPC client and
/// the auto-allow grant path all hold a `any BrokerFacade` and nothing else.
/// Because disclosure is a separate protocol implemented by a separate type
/// that no broker vends, there is no cast, no downcast, no default
/// implementation and no wire message by which an MCP client, a `--run`
/// invocation, an XPC request from an MCP subprocess, or a grant can reach it.
/// `HumanDisclosureService` is constructed in exactly one place — the desktop
/// window's own code — from the same `MetadataStore` and `KeychainVault` the
/// Vault screen already uses to create and delete items.
///
/// That is the *reason* the capability is not on the facade. Adding it there
/// would hand every agent-facing composition a handle to it, and the only thing
/// standing between an agent and a credential would then be a runtime check.
public protocol HumanDisclosure: Sendable {
    /// Reads one **field** of one vault item behind a fresh OS authentication
    /// and returns a short-lived in-memory handle. The handle renders its bytes
    /// at most once and zeroes them when the display window closes.
    ///
    /// BL-079 made the field explicit. `fieldID` nil means the item's *primary*
    /// field — the one whose Keychain account is `VaultItem.keychainAccount`,
    /// which is exactly what this method read before there were other fields.
    /// A named field must be a secret field **of that item**, with an account
    /// of its own; anything else is refused before the prompt, so an
    /// authentication for one field can never open another.
    func reveal(itemID: UUID, fieldID: UUID?) async throws -> RevealHandle
    /// The same read, placed on the general pasteboard marked concealed, under
    /// a lease that clears the pasteboard after a bounded interval — and only
    /// if nothing else has written to it since.
    func copy(itemID: UUID, fieldID: UUID?) async throws -> ClipboardLease
}

/// BL-079 — previewing a sealed attachment.
///
/// It is a **separate protocol from `HumanDisclosure`**, implemented by the
/// same service and vended by no broker, for exactly the reason given above:
/// `BrokerFacade` is the seam every agent-facing caller holds, and neither
/// reveal nor attachment preview is a member of it. A screenshot of a
/// credential is a credential.
public protocol AttachmentDisclosure: Sendable {
    /// Opens one sealed attachment behind a fresh OS authentication and returns
    /// a short-lived handle over its plaintext bytes. The handle renders once
    /// and zeroes itself when the preview window closes, exactly as
    /// `RevealHandle` does for text.
    func revealAttachment(itemID: UUID, attachmentID: String) async throws -> AttachmentRevealHandle
}

/// A bounded, in-memory attachment preview.
///
/// The bytes live in a `VaultSecret` — the same manually-zeroed allocation
/// every credential in this product lives in — so "zeroed when the window
/// closes" is a `memset_s`, not a flag. The borrow is `Void`-returning for the
/// same reason it is on `VaultSecret`: the only way to move the bytes out is a
/// deliberate copy the reviewer can see, and the one caller that makes it
/// (`AttachmentPreviewSheet`) builds an `NSImage` inside the closure and drops
/// it when the window closes.
public actor AttachmentRevealHandle {
    public nonisolated let itemID: UUID
    public nonisolated let itemLabel: String
    public nonisolated let attachment: VaultItemAttachment
    public nonisolated let openedAt: Date
    public nonisolated let expiresAt: Date

    private var bytes: VaultSecret?
    private var rendered = false
    private let clock: @Sendable () -> Date

    init(itemID: UUID, itemLabel: String, attachment: VaultItemAttachment, bytes: VaultSecret, openedAt: Date, window: TimeInterval, clock: @escaping @Sendable () -> Date) {
        self.itemID = itemID
        self.itemLabel = itemLabel
        self.attachment = attachment
        self.openedAt = openedAt
        self.expiresAt = openedAt.addingTimeInterval(window)
        self.bytes = bytes
        self.clock = clock
    }

    public func isLive() -> Bool {
        expireIfElapsed()
        return bytes != nil
    }

    public func hasRendered() -> Bool { rendered }

    public func remainingSeconds() -> Int {
        expireIfElapsed()
        guard bytes != nil else { return 0 }
        return max(0, Int(expiresAt.timeIntervalSince(clock())))
    }

    /// Renders the bytes exactly once, inside a closure, while the window is
    /// open. A second call, or any call after the window closed, throws.
    public func withRevealedBytes(_ body: (UnsafeRawBufferPointer) -> Void) throws {
        expireIfElapsed()
        guard !rendered else {
            throw VaultageError.policyDenied("This attachment has already been shown. Authenticate again to show it a second time.")
        }
        guard let bytes else {
            throw VaultageError.policyDenied("This preview expired. Authenticate again to show it a second time.")
        }
        rendered = true
        bytes.withBytes(body)
    }

    /// The same single render, for a UI that must hold the bytes while a
    /// window is on screen.
    ///
    /// It exists for the same reason `RevealHandle.renderedOnce()` does: an
    /// AppKit window cannot do its work inside a synchronous closure that spans
    /// the window's life, and the closure form cannot cross an actor boundary
    /// from `@MainActor` code. It is the deliberate, reviewable copy the
    /// closure form is designed to force — it consumes the same single-render
    /// budget, it is bounded by the store's 10 MiB import cap, and the one
    /// caller (`RevealSheet.presentAttachment`) turns it straight into an
    /// `NSImage` and drops it when the window closes.
    ///
    /// Residual: a Foundation `Data` cannot be zeroed by its holder once
    /// copy-on-write has handed it out. See IMPLEMENTATION.md, "Secret material
    /// in memory" — the same residual the text path documents.
    public func renderedOnce() throws -> Data {
        var copy = Data()
        try withRevealedBytes { copy = Data($0) }
        return copy
    }

    public func dismiss() { bytes = nil }

    @discardableResult
    public func expireIfElapsed() -> Bool {
        guard bytes != nil, clock() >= expiresAt else { return false }
        bytes = nil
        return true
    }
}

extension HumanDisclosure {
    /// The pre-BL-079 spelling, preserved so every existing caller keeps
    /// meaning exactly what it meant: disclose the item's primary value.
    public func reveal(itemID: UUID) async throws -> RevealHandle {
        try await reveal(itemID: itemID, fieldID: nil)
    }

    public func copy(itemID: UUID) async throws -> ClipboardLease {
        try await copy(itemID: itemID, fieldID: nil)
    }
}

/// Where a disclosed value is going. There are exactly two destinations, and
/// each one names itself in the OS authentication prompt and in the receipt.
public enum HumanDisclosureDestination: String, Codable, Sendable, CaseIterable {
    case onScreen
    case clipboard
    /// BL-079. A sealed attachment previewed in the content-protected window.
    /// It is its own destination rather than a flavour of `onScreen` so that a
    /// receipt says which capability ran, and so an attachment preview can
    /// never be mistaken in the log for a text reveal.
    case attachmentOnScreen

    /// The two destinations that disclose a **text value** of a field. The
    /// attachment preview is deliberately not one of them: it opens bytes from
    /// the sealed store rather than reading a field's Keychain record, so it
    /// takes a different path and is asserted separately.
    public static let textCases: [HumanDisclosureDestination] = [.onScreen, .clipboard]

    /// The words the human reads in the Touch ID prompt, alongside the item
    /// label. These strings are the ticket's contract.
    public var title: String {
        switch self {
        case .onScreen: "Reveal on screen"
        case .clipboard: "Copy to clipboard"
        case .attachmentOnScreen: "Show attachment"
        }
    }

    /// The receipt's operation name.
    public var operation: String {
        switch self {
        case .onScreen: "vault.human.reveal"
        case .clipboard: "vault.human.copy"
        case .attachmentOnScreen: "vault.human.attachment.reveal"
        }
    }

    /// The terminal decision written when the disclosure completes.
    public var successDecision: AuditDecision {
        switch self {
        case .onScreen, .attachmentOnScreen: .humanRevealed
        case .clipboard: .humanCopied
        }
    }

    /// The reason string handed to `LAContext.evaluatePolicy`. It names the
    /// destination, the item and — since BL-079 gave an item more than one
    /// field — which field is about to be disclosed, because an authentication
    /// prompt that does not say what it authorizes is not an approval.
    ///
    /// The field key is a label the owner typed ("Password", "Passphrase"). It
    /// is metadata, never a value, and it is the only new thing this string
    /// carries.
    public func authenticationReason(itemLabel: String, fieldKey: String? = nil) -> String {
        guard let fieldKey, !fieldKey.isEmpty else { return "\(title): \(itemLabel)" }
        return "\(title): \(itemLabel) — \(fieldKey)"
    }
}

// MARK: - Reveal handle

/// A bounded, in-memory reveal.
///
/// The handle owns the only reference to the `VaultSecret` the service read.
/// Dropping that reference runs `SecretStorage.deinit`, which zeroes the
/// allocation with `memset_s` — so "zeroed after the window" is a real byte
/// operation, not a flag.
///
/// Residual: `withRevealedText` must hand the UI a Swift `String`, whose
/// storage cannot be zeroed. This is the same residual documented for
/// `VaultSecret.withAuthorizationHeaderValue`; see IMPLEMENTATION.md, "Secret
/// material in memory".
public actor RevealHandle {
    /// The display window the ticket fixes. It is a constant, not a preference:
    /// there is no setting, argument or environment variable that lengthens it.
    public static let defaultWindow: TimeInterval = 20

    public nonisolated let itemID: UUID
    public nonisolated let itemLabel: String
    /// BL-079. Which field this handle holds — "Password", "Passphrase", the
    /// item's primary key name. A label the owner typed, never a value; the
    /// reveal window titles itself with it so two open reveals of one item are
    /// distinguishable.
    public nonisolated let fieldKey: String
    public nonisolated let openedAt: Date
    public nonisolated let expiresAt: Date

    private var secret: VaultSecret?
    private var rendered = false
    private let clock: @Sendable () -> Date

    init(itemID: UUID, itemLabel: String, fieldKey: String = "", secret: VaultSecret, openedAt: Date, window: TimeInterval, clock: @escaping @Sendable () -> Date) {
        self.itemID = itemID
        self.itemLabel = itemLabel
        self.fieldKey = fieldKey
        self.openedAt = openedAt
        self.expiresAt = openedAt.addingTimeInterval(window)
        self.secret = secret
        self.clock = clock
    }

    /// True while the bytes are still held. It goes false the moment the window
    /// closes or the handle is dismissed, and never goes back.
    public func isLive() -> Bool {
        expireIfElapsed()
        return secret != nil
    }

    public func hasRendered() -> Bool { rendered }

    public func remainingSeconds() -> Int {
        expireIfElapsed()
        guard secret != nil else { return 0 }
        return max(0, Int(expiresAt.timeIntervalSince(clock())))
    }

    /// Renders the value exactly once, inside a closure, while the window is
    /// open. A second call, or any call after the window closed, throws and
    /// leaves nothing behind. The closure returns `Void`, so the only way to
    /// move the text out is a deliberate, reviewable copy by the UI.
    public func withRevealedText(_ body: (String) -> Void) throws {
        expireIfElapsed()
        guard !rendered else {
            throw VaultageError.policyDenied("This reveal has already been shown. Authenticate again to reveal it a second time.")
        }
        guard let secret else {
            throw VaultageError.policyDenied("This reveal expired. Authenticate again to reveal it a second time.")
        }
        rendered = true
        try secret.withDisclosureText(body)
    }

    /// The same single render, for a UI that must hold the text while a window
    /// is on screen. It exists because a SwiftUI or AppKit view cannot do its
    /// work inside a synchronous closure that spans the life of a window.
    ///
    /// It is the deliberate, reviewable copy the closure form is designed to
    /// force: there is exactly one caller — `RevealSheet` — it consumes the
    /// same single-render budget, and the view that holds the result clears it
    /// when the window closes. Nothing outside `VaultageApp` calls it.
    ///
    /// Residual: as with every derived form, Swift `String` storage cannot be
    /// zeroed. See IMPLEMENTATION.md, "Secret material in memory".
    public func renderedOnce() throws -> String {
        var value = ""
        try withRevealedText { value = $0 }
        return value
    }

    /// The explicit close: the sheet dismissing, the window resigning key, the
    /// app locking. Idempotent.
    public func dismiss() { zero() }

    /// Drops the bytes if the display window has elapsed. Called on every query
    /// so a handle is never live merely because no timer fired.
    @discardableResult
    public func expireIfElapsed() -> Bool {
        guard secret != nil, clock() >= expiresAt else { return false }
        zero()
        return true
    }

    private func zero() { secret = nil }
}

// MARK: - Clipboard lease

/// What settling a clipboard lease did.
public enum ClipboardLeaseOutcome: String, Codable, Sendable {
    /// The lease is still running.
    case pending
    /// The pasteboard was unchanged since the write, so Vaultage cleared it.
    case cleared
    /// Something else wrote to the pasteboard after Vaultage did. The lease
    /// expired without touching it: clearing here would destroy a value
    /// Vaultage does not own.
    case superseded
}

/// The clipboard lease v1 kept as a value comparison, restated as a change
/// count.
///
/// v1 (`vaultSecretIpc.ts`) cleared the clipboard only if `clipboard.readText()`
/// still equalled the copied value. That works, but it requires holding a
/// plaintext copy of the secret for the whole lease and reading the pasteboard
/// back to compare it. `NSPasteboard.changeCount` answers the same question —
/// "has anyone written since I did?" — without either, so the lease holds no
/// credential material at all.
public actor ClipboardLease {
    /// The lease the ticket fixes. Like the reveal window, it is a constant.
    public static let defaultDuration: TimeInterval = 45
    /// Audit M-08. This lease's row in `ClipboardOwnership`, so a quit can
    /// settle it without reaching into the actor.
    private nonisolated let ownership = UUID()

    public nonisolated let itemID: UUID
    public nonisolated let itemLabel: String
    public nonisolated let copiedAt: Date
    public nonisolated let expiresAt: Date

    private let pasteboard: any ConcealedPasteboard
    /// The change count observed immediately after Vaultage's own write.
    private let changeCountAtWrite: Int
    private var outcome: ClipboardLeaseOutcome = .pending
    private let clock: @Sendable () -> Date

    init(itemID: UUID, itemLabel: String, pasteboard: any ConcealedPasteboard, changeCountAtWrite: Int, copiedAt: Date, duration: TimeInterval, clock: @escaping @Sendable () -> Date) {
        self.itemID = itemID
        self.itemLabel = itemLabel
        self.pasteboard = pasteboard
        self.changeCountAtWrite = changeCountAtWrite
        self.copiedAt = copiedAt
        self.expiresAt = copiedAt.addingTimeInterval(duration)
        self.clock = clock
        // Audit M-08. Registered from the start, with a settlement that reads
        // no actor state: the change count and the pasteboard are immutable
        // and `Sendable`, so a terminating process can run it synchronously.
        ClipboardOwnership.shared.add(ownership, pasteboard: pasteboard, changeCountAtWrite: changeCountAtWrite)
    }

    public func state() -> ClipboardLeaseOutcome { outcome }

    public func remainingSeconds() -> Int {
        guard outcome == .pending else { return 0 }
        return max(0, Int(expiresAt.timeIntervalSince(clock())))
    }

    /// Runs the lease's decision. Before the deadline this is a no-op that
    /// reports `pending`; at or after it, the pasteboard is cleared only when
    /// its change count is still the one Vaultage's own write produced.
    ///
    /// Settling twice cannot clear twice: the outcome is terminal.
    @discardableResult
    public func settle() -> ClipboardLeaseOutcome {
        guard outcome == .pending else { return outcome }
        guard clock() >= expiresAt else { return .pending }
        return clearNow()
    }

    /// RP-03. Ends the lease immediately, without waiting for the deadline.
    ///
    /// It exists for one caller: `HumanDisclosureService.copy`, when the
    /// terminal receipt for a copy it has already performed cannot be written.
    /// The value is on the pasteboard at that moment and the invocation is
    /// about to fail, so leaving it there for the rest of the lease would be
    /// leaving a credential on the clipboard of a copy the durable log does not
    /// record as having happened.
    ///
    /// It applies the same ownership rule as `settle()` — if something else has
    /// written since, the outcome is `superseded` and the pasteboard is left
    /// alone, because clearing would destroy a value Vaultage does not own.
    @discardableResult
    public func clearNow() -> ClipboardLeaseOutcome {
        guard outcome == .pending else { return outcome }
        if pasteboard.changeCount == changeCountAtWrite {
            pasteboard.clear()
            outcome = .cleared
        } else {
            outcome = .superseded
        }
        ClipboardOwnership.shared.remove(ownership)
        return outcome
    }
}

/// Audit M-08. Every clipboard lease this process holds, by what settles it.
///
/// A lease is a promise that the value leaves the pasteboard; the promise has
/// to survive the caller dropping the lease (the timer holds it, see `copy`)
/// and it has to be kept at quit, when no timer will fire. Each row is the
/// pasteboard and the change count the write produced — nothing else — and
/// `settleAll()` applies the one rule every lease applies: cleared if the
/// count is still ours, left alone if something else has written since.
public final class ClipboardOwnership: @unchecked Sendable {
    public static let shared = ClipboardOwnership()

    private struct Row: Sendable {
        let pasteboard: any ConcealedPasteboard
        let changeCountAtWrite: Int
    }

    private let lock = NSLock()
    private var rows: [UUID: Row] = [:]

    public init() {}

    public func add(_ id: UUID, pasteboard: any ConcealedPasteboard, changeCountAtWrite: Int) {
        lock.lock(); defer { lock.unlock() }
        rows[id] = Row(pasteboard: pasteboard, changeCountAtWrite: changeCountAtWrite)
    }

    public func remove(_ id: UUID) {
        lock.lock(); defer { lock.unlock() }
        rows[id] = nil
    }

    /// How many leases are live.
    public var count: Int { lock.lock(); defer { lock.unlock() }; return rows.count }

    /// Settles every live lease now. Synchronous, so `applicationWillTerminate`
    /// can call it. Returns how many pasteboards were actually cleared.
    @discardableResult
    public func settleAll() -> Int {
        lock.lock()
        let live = rows
        rows.removeAll()
        lock.unlock()
        var cleared = 0
        for row in live.values where row.pasteboard.changeCount == row.changeCountAtWrite {
            row.pasteboard.clear()
            cleared += 1
        }
        return cleared
    }
}

/// The pasteboard seam.
///
/// It is a protocol so the lease contracts can be proved without a window
/// server, and so the only implementation that touches `NSPasteboard` is the
/// handful of lines below.
public protocol ConcealedPasteboard: Sendable {
    /// The general pasteboard's monotonic change count.
    var changeCount: Int { get }
    /// Writes the value as concealed text and returns the change count that
    /// write produced. Throws rather than writing anything partial.
    func writeConcealed(_ secret: VaultSecret) throws -> Int
    /// Clears the pasteboard and returns the resulting change count.
    @discardableResult
    func clear() -> Int
}

public enum ConcealedPasteboardTypes {
    /// The community convention clipboard managers honour: an item carrying
    /// this type must not be recorded in clipboard history.
    ///
    /// It is a request, not an enforcement. A clipboard manager that ignores it
    /// will still capture the value, and macOS offers no mechanism that would
    /// stop it. IMPLEMENTATION.md states this as an honest limitation.
    public static let concealed = "org.nspasteboard.ConcealedType"
    /// Marks the item as machine-generated, which well-behaved managers also
    /// use to skip history.
    public static let autoGenerated = "org.nspasteboard.AutoGeneratedType"
}

/// The largest value Vaultage will reveal or copy. A credential or a secure
/// note is small; a multi-megabyte blob on screen or on the pasteboard is not a
/// use case this path serves, and bounding it keeps the derived `String` small.
public let humanDisclosureMaximumBytes = 64 * 1024

#if canImport(AppKit)
/// The general pasteboard. `NSPasteboard` is safe to use off the main thread;
/// the unchecked conformance is because `NSPasteboard` is not `Sendable`.
public struct SystemConcealedPasteboard: ConcealedPasteboard, @unchecked Sendable {
    private let pasteboard: NSPasteboard

    public init(pasteboard: NSPasteboard = .general) { self.pasteboard = pasteboard }

    public var changeCount: Int { pasteboard.changeCount }

    public func writeConcealed(_ secret: VaultSecret) throws -> Int {
        let concealed = NSPasteboard.PasteboardType(ConcealedPasteboardTypes.concealed)
        let autoGenerated = NSPasteboard.PasteboardType(ConcealedPasteboardTypes.autoGenerated)
        var wrote = false
        var failure: Error?
        do {
            try secret.withDisclosureText { text in
                pasteboard.clearContents()
                // The concealed markers are declared alongside the string, so a
                // clipboard manager sees them in the same pasteboard item.
                pasteboard.setData(Data(), forType: concealed)
                pasteboard.setData(Data(), forType: autoGenerated)
                wrote = pasteboard.setString(text, forType: .string)
            }
        } catch { failure = error }
        if let failure {
            pasteboard.clearContents()
            throw failure
        }
        guard wrote else {
            pasteboard.clearContents()
            throw VaultageError.storage("The value could not be placed on the clipboard.")
        }
        return pasteboard.changeCount
    }

    @discardableResult
    public func clear() -> Int {
        pasteboard.clearContents()
        return pasteboard.changeCount
    }
}
#endif

// MARK: - The service

/// The one implementation of `HumanDisclosure`.
///
/// It is deliberately *not* a `BrokerFacade` and deliberately holds no broker.
/// It composes the same primitives the Vault screen already uses — the metadata
/// store, the Keychain vault, the durable receipt log, the Activity projection
/// and the owner authenticator — and nothing else.
public actor HumanDisclosureService: HumanDisclosure, AttachmentDisclosure {
    /// Bumped when the disclosed facts or the ordering below change. It is
    /// folded into the request digest, so a receipt is attributable to the exact
    /// policy that produced it.
    public static let policyRevision = "human-disclosure.v1"
    /// How long an OS authentication stays good for. The same bound the grant
    /// path uses: authenticating and then disclosing are one act, not two.
    public static let authenticationLifetime: TimeInterval = 60

    private let metadata: MetadataStore
    private let vault: any SecretVault
    private let receipts: any ReceiptPersisting
    private let audit: any AuditPersisting
    private let authenticator: any OwnerAuthenticating
    private let pasteboard: any ConcealedPasteboard
    /// BL-079. Where sealed attachments live. Nil means this composition has no
    /// attachment store, and every attachment preview is refused — which is the
    /// fail-closed reading, not a silent no-op.
    private let attachments: VaultAttachmentStore?
    private let revealWindow: TimeInterval
    private let leaseDuration: TimeInterval
    /// Whether the service arms its own background timers. The self-tests turn
    /// this off and drive `expireIfElapsed()` and `settle()` from a scripted
    /// clock, so lease and window timing are proved deterministically rather
    /// than by sleeping.
    private let schedulesTimers: Bool
    private let now: @Sendable () -> Date

    public init(
        metadata: MetadataStore,
        vault: any SecretVault,
        receipts: (any ReceiptPersisting)? = nil,
        audit: (any AuditPersisting)? = nil,
        authenticator: (any OwnerAuthenticating)? = nil,
        pasteboard: (any ConcealedPasteboard)? = nil,
        attachments: VaultAttachmentStore? = nil,
        revealWindow: TimeInterval = RevealHandle.defaultWindow,
        leaseDuration: TimeInterval = ClipboardLease.defaultDuration,
        schedulesTimers: Bool = true,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.metadata = metadata
        self.vault = vault
        self.receipts = receipts ?? ReceiptStore(directory: metadata.directory)
        self.audit = audit ?? MetadataAuditStore(metadata: metadata)
        self.authenticator = authenticator ?? LocalOwnerAuthentication()
        #if canImport(AppKit)
        self.pasteboard = pasteboard ?? SystemConcealedPasteboard()
        #else
        self.pasteboard = pasteboard ?? UnavailablePasteboard()
        #endif
        self.attachments = attachments ?? VaultAttachmentStore(directory: metadata.directory, vault: vault)
        self.revealWindow = revealWindow
        self.leaseDuration = leaseDuration
        self.schedulesTimers = schedulesTimers
        self.now = now
    }

    public func reveal(itemID: UUID, fieldID: UUID?) async throws -> RevealHandle {
        let disclosed = try await disclose(itemID: itemID, fieldID: fieldID, destination: .onScreen)
        let handle = RevealHandle(
            itemID: disclosed.item.id,
            itemLabel: disclosed.item.label,
            fieldKey: disclosed.field.key,
            secret: disclosed.secret,
            openedAt: disclosed.at,
            window: revealWindow,
            clock: now
        )
        try await complete(disclosed, result: "Revealed on screen for \(Int(revealWindow)) seconds. The value was not returned to any client and was zeroed when the window closed.")
        if schedulesTimers {
            let window = revealWindow
            Task.detached { [weak handle] in
                try? await Task.sleep(nanoseconds: UInt64(max(0, window) * 1_000_000_000))
                await handle?.dismiss()
            }
        }
        return handle
    }

    public func copy(itemID: UUID, fieldID: UUID?) async throws -> ClipboardLease {
        let disclosed = try await disclose(itemID: itemID, fieldID: fieldID, destination: .clipboard)
        let changeCount: Int
        do { changeCount = try pasteboard.writeConcealed(disclosed.secret) }
        catch {
            try? await record(disclosed, decision: .humanDenied, result: "The value could not be placed on the clipboard; nothing was copied.")
            throw error
        }
        let lease = ClipboardLease(
            itemID: disclosed.item.id,
            itemLabel: disclosed.item.label,
            pasteboard: pasteboard,
            changeCountAtWrite: changeCount,
            copiedAt: disclosed.at,
            duration: leaseDuration,
            clock: now
        )
        // RP-03. The value is on the pasteboard from the line above, so the
        // clearing timer is armed *here* — before the terminal receipt, and
        // before anything else that can fail. Previously the timer was armed
        // after the receipt, so a receipt failure dropped the lease on the
        // floor: the credential stayed on the general pasteboard with nothing
        // arranged to remove it, while the durable log's last word on the
        // invocation was `pending`.
        //
        // The service keeps no reference to the lease either, so arming is also
        // what makes the clearing guarantee independent of whether the caller
        // retains what `copy` returns (BL-062 §9: the Vault-screen buttons that
        // would retain it are the UI lane's).
        if schedulesTimers {
            let duration = leaseDuration
            // Audit M-08: the timer holds the lease strongly, so the clearing
            // happens whether or not the caller kept its handle.
            Task.detached { [lease] in
                try? await Task.sleep(nanoseconds: UInt64(max(0, duration) * 1_000_000_000))
                _ = await lease.settle()
            }
        }
        do {
            try await complete(disclosed, result: "Copied to the clipboard as concealed text under a \(Int(leaseDuration))-second lease. The clipboard is cleared at expiry only if nothing else has written to it.")
        } catch {
            // The copy happened and cannot be un-happened, but it cannot be
            // recorded, so it is compensated instead of left standing: clear the
            // pasteboard immediately rather than at the deadline, and write the
            // compensating decision that says the value was placed and removed.
            //
            // Ownership still applies — if something else wrote in between, the
            // outcome is `superseded` and Vaultage does not clobber it.
            let outcome = await lease.clearNow()
            try? await record(disclosed, decision: .humanDenied, result: outcome == .cleared
                ? "The copy could not be recorded, so the clipboard was cleared immediately. Nothing was left on the clipboard by Vaultage."
                : "The copy could not be recorded. Another application had already written to the clipboard, so Vaultage left it alone rather than destroying a value it does not own.")
            throw error
        }
        return lease
    }

    // MARK: - Attachments

    /// Opens one sealed attachment behind one OS authentication.
    ///
    /// It is the same shape as `disclose` and keeps the same order — resolve,
    /// refuse, authenticate, re-resolve, read — because the properties that
    /// order buys are the same ones: nothing before the prompt touches a key,
    /// so a cancelled prompt cannot have moved bytes; and the re-resolution
    /// afterwards means authenticating for one attachment does not authorize a
    /// different one that arrived while the prompt was open.
    ///
    /// The authentication is bound to the **vault's content-key account**, not
    /// to the item's, because that is the record the store actually reads.
    /// Carrying it is what keeps this at one prompt.
    public func revealAttachment(itemID: UUID, attachmentID: String) async throws -> AttachmentRevealHandle {
        let correlationID = UUID()
        let destination = HumanDisclosureDestination.attachmentOnScreen
        let state = try await metadata.load()

        guard let item = state.vaultItems.first(where: { $0.id == itemID }) else {
            try? await refuse(itemID: itemID, destination: destination, correlationID: correlationID, digest: Self.unresolvedDigest(itemID: itemID, destination: destination), result: "No such protected vault item. Nothing was opened.")
            throw VaultageError.invalidInput("That protected vault item no longer exists.")
        }
        guard let attachment = item.attachments.first(where: { $0.id == attachmentID }) else {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: Self.unresolvedDigest(itemID: itemID, destination: destination), result: "No such attachment on this item. Nothing was opened.")
            throw VaultageError.invalidInput("That attachment is no longer on this item.")
        }
        let digest = Self.attachmentDigest(item: item, attachment: attachment)

        guard MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil else {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "The protected vault item is being deleted. Nothing was opened.")
            throw VaultageError.policyDenied("The protected vault item is being deleted and cannot be used.")
        }
        guard let attachments else {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "This build has no attachment store. Nothing was opened.")
            throw VaultageError.unsupported("Sealed attachments are unavailable in this build.")
        }

        try await write(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, decision: .pending, result: "\(destination.title) awaiting owner authentication for \(item.label) (\(attachment.fileName)).")

        let requestedAt = now()
        let authentication: OwnerAuthentication
        do {
            authentication = try await authenticator.authenticateOwner(
                reason: "\(destination.title): \(item.label) — \(attachment.fileName)",
                unlocking: VaultAttachmentStore.unlockedAccounts(attachment.vaultID)
            )
        } catch {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "Owner authentication failed or was cancelled. Nothing was opened.")
            throw error
        }
        defer { authentication.invalidate() }
        guard now().timeIntervalSince(requestedAt) <= Self.authenticationLifetime else {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "The owner authentication expired before the attachment was opened. Nothing was opened.")
            throw VaultageError.approvalDenied
        }

        let fresh = try await metadata.load()
        guard let current = fresh.vaultItems.first(where: { $0.id == itemID }),
              let currentAttachment = current.attachments.first(where: { $0.id == attachmentID }),
              Self.attachmentDigest(item: current, attachment: currentAttachment) == digest,
              MetadataRemoval.deletionReservation(forVaultItem: current.id, in: fresh) == nil else {
            try? await refuse(itemID: itemID, destination: destination, correlationID: correlationID, digest: digest, result: "The attachment changed while authentication was open. Nothing was opened.")
            throw VaultageError.policyDenied("The attachment changed before it could be shown.")
        }

        let bytes: VaultSecret
        do { bytes = try await attachments.open(currentAttachment, authentication: authentication) }
        catch {
            try? await refuse(itemID: current.id, destination: destination, correlationID: correlationID, digest: digest, result: "The sealed attachment could not be opened.")
            throw error
        }

        let handle = AttachmentRevealHandle(
            itemID: current.id,
            itemLabel: current.label,
            attachment: currentAttachment,
            bytes: bytes,
            openedAt: now(),
            window: revealWindow,
            clock: now
        )
        try await write(itemID: current.id, destination: destination, correlationID: correlationID, digest: digest, decision: destination.successDecision, result: "Shown on screen for \(Int(revealWindow)) seconds in a window screen capture cannot read. The file was not written anywhere and was zeroed when the window closed.")
        if schedulesTimers {
            let window = revealWindow
            Task.detached { [weak handle] in
                try? await Task.sleep(nanoseconds: UInt64(max(0, window) * 1_000_000_000))
                await handle?.dismiss()
            }
        }
        return handle
    }

    // MARK: - The shared path

    private struct Disclosed {
        let item: VaultItem
        /// BL-079. The exact field that was read. Its `keychainAccount` is the
        /// only account this disclosure ever touched.
        let field: VaultItemField
        let destination: HumanDisclosureDestination
        let secret: VaultSecret
        let correlationID: UUID
        let digest: String
        let at: Date
    }

    /// Resolves the field a disclosure names, or says why it cannot be
    /// disclosed. Every refusal here happens **before** any prompt and before
    /// any Keychain call.
    ///
    /// - `nil` means the item's primary field, which is what `reveal(itemID:)`
    ///   meant before BL-079.
    /// - A certificate item, whose payload is a sealed file, has no primary
    ///   field at all and is refused here rather than by a Keychain read that
    ///   would find nothing.
    /// - A non-secret field is metadata that is already on screen; disclosing
    ///   it would create a receipt claiming a protected value was released when
    ///   none was.
    private static func resolveField(_ fieldID: UUID?, in item: VaultItem) throws -> VaultItemField {
        guard let fieldID else {
            guard let primary = item.primaryField else {
                throw VaultageError.policyDenied("\(item.label) holds no protected value to reveal or copy. Its contents are a sealed attachment and value-free metadata.")
            }
            return primary
        }
        guard let field = item.fields.first(where: { $0.id == fieldID }) else {
            throw VaultageError.invalidInput("That field no longer exists on this item.")
        }
        guard field.isSecret, field.keychainAccount != nil else {
            throw VaultageError.policyDenied("\(field.key) is not a protected field. Its value is ordinary metadata and is already shown.")
        }
        return field
    }

    /// Resolve, refuse, authenticate, re-resolve, read. In that order.
    ///
    /// Nothing before the authentication step touches the Keychain, so a denied
    /// or cancelled prompt cannot have moved any bytes: there are none to move.
    private func disclose(itemID: UUID, fieldID: UUID?, destination: HumanDisclosureDestination) async throws -> Disclosed {
        let correlationID = UUID()
        let state = try await metadata.load()

        guard let item = state.vaultItems.first(where: { $0.id == itemID }) else {
            try? await refuse(itemID: itemID, destination: destination, correlationID: correlationID, digest: Self.unresolvedDigest(itemID: itemID, destination: destination), result: "No such protected vault item. Nothing was read.")
            throw VaultageError.invalidInput("That protected vault item no longer exists.")
        }

        // BL-079. The field is resolved before anything else is written or
        // prompted, so an item with no protected value, a field that does not
        // exist, and a field that is plain metadata are all refused with a
        // receipt and without an OS prompt.
        let field: VaultItemField
        do { field = try Self.resolveField(fieldID, in: item) }
        catch {
            let digest = Self.unresolvedFieldDigest(item: item, fieldID: fieldID, destination: destination)
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "That field cannot be disclosed. Nothing was read.")
            throw error
        }
        let digest = Self.digest(item: item, field: field, destination: destination)

        guard MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil else {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "The protected vault item is being deleted. Nothing was read.")
            throw VaultageError.policyDenied("The protected vault item is being deleted and cannot be used.")
        }

        // The invocation is durable before the prompt, so a denial is a record
        // rather than an absence of one.
        try await write(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, decision: .pending, result: "\(destination.title) awaiting owner authentication for \(item.label) (\(field.key)).")

        // The one account this presence may be carried into. `resolveField`
        // already refused a field without one.
        let fieldAccount = field.keychainAccount ?? item.keychainAccount
        let requestedAt = now()
        let authentication: OwnerAuthentication
        do {
            // BL-062 follow-up. The presence is bound to this item's Keychain
            // account and to nothing else, so carrying it into the read below
            // cannot unlock a different record even if the metadata moved while
            // the prompt was open. The re-resolution after the prompt still
            // runs; the binding is the second, independent refusal.
            authentication = try await authenticator.authenticateOwner(
                reason: destination.authenticationReason(itemLabel: item.label, fieldKey: field.key),
                unlocking: [fieldAccount]
            )
        } catch {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "Owner authentication failed or was cancelled. Nothing was read.")
            throw error
        }
        // The evaluated presence dies when `disclose` returns, however it
        // returns, so it can never satisfy a later read. Registered before the
        // expiry and re-resolution refusals below, because those throw.
        defer { authentication.invalidate() }
        guard now().timeIntervalSince(requestedAt) <= Self.authenticationLifetime else {
            try? await refuse(itemID: item.id, destination: destination, correlationID: correlationID, digest: digest, result: "The owner authentication expired before the value was read. Nothing was read.")
            throw VaultageError.approvalDenied
        }

        // Re-resolve after authentication. Authenticating for one item does not
        // authorize a different record, a rotated credential, or an item that
        // entered deletion while the prompt was open.
        let fresh = try await metadata.load()
        guard let current = fresh.vaultItems.first(where: { $0.id == itemID }),
              let currentField = try? Self.resolveField(fieldID, in: current),
              Self.digest(item: current, field: currentField, destination: destination) == digest,
              MetadataRemoval.deletionReservation(forVaultItem: current.id, in: fresh) == nil else {
            try? await refuse(itemID: itemID, destination: destination, correlationID: correlationID, digest: digest, result: "The protected vault item changed while authentication was open. Nothing was read.")
            throw VaultageError.policyDenied("The protected vault item changed before it could be disclosed.")
        }

        let secret: VaultSecret
        do {
            // One prompt, not two: `KeychainVault` hands this already-evaluated
            // context to `SecItemCopyMatching` as `kSecUseAuthenticationContext`
            // instead of building a fresh one and asking the owner again. The
            // digest comparison above already proved `current.keychainAccount`
            // is the account the human authenticated for, and `isValid(for:at:)`
            // re-checks it inside the vault regardless.
            secret = try vault.read(
                account: currentField.keychainAccount ?? current.keychainAccount,
                prompt: destination.authenticationReason(itemLabel: current.label, fieldKey: currentField.key),
                authentication: authentication
            )
        } catch {
            try? await refuse(itemID: current.id, destination: destination, correlationID: correlationID, digest: digest, result: "The protected value could not be read.")
            throw error
        }
        guard secret.byteCount > 0, secret.byteCount <= humanDisclosureMaximumBytes, secret.isValidUTF8 else {
            try? await refuse(itemID: current.id, destination: destination, correlationID: correlationID, digest: digest, result: "The protected value is empty, too large, or not text, so it cannot be disclosed.")
            throw VaultageError.invalidInput("That protected value cannot be revealed or copied as text.")
        }
        return Disclosed(item: current, field: currentField, destination: destination, secret: secret, correlationID: correlationID, digest: digest, at: now())
    }

    private func complete(_ disclosed: Disclosed, result: String) async throws {
        try await write(itemID: disclosed.item.id, destination: disclosed.destination, correlationID: disclosed.correlationID, digest: disclosed.digest, decision: disclosed.destination.successDecision, result: result)
    }

    private func record(_ disclosed: Disclosed, decision: AuditDecision, result: String) async throws {
        try await write(itemID: disclosed.item.id, destination: disclosed.destination, correlationID: disclosed.correlationID, digest: disclosed.digest, decision: decision, result: result)
    }

    private func refuse(itemID: UUID, destination: HumanDisclosureDestination, correlationID: UUID, digest: String, result: String) async throws {
        try await write(itemID: itemID, destination: destination, correlationID: correlationID, digest: digest, decision: .humanDenied, result: result)
    }

    /// One writer for every receipt on this path. It carries an item identifier,
    /// a destination class, a digest and an already-redacted sentence — and
    /// there is no parameter through which a value could reach it.
    private func write(itemID: UUID, destination: HumanDisclosureDestination, correlationID: UUID, digest: String, decision: AuditDecision, result: String) async throws {
        let safe = Redactor.safeError(result)
        try await receipts.append(DurableReceipt(
            eventID: UUID(),
            correlationID: correlationID,
            at: now(),
            projectID: nil,
            environmentID: nil,
            bindingID: nil,
            vaultItemID: itemID,
            operation: destination.operation,
            requestDigest: digest,
            decision: decision,
            result: safe
        ))
        try? await audit.append(AuditEvent(
            at: now(),
            projectID: nil,
            environmentID: nil,
            connectionID: nil,
            operation: destination.operation,
            decision: decision,
            result: safe
        ))
    }

    /// The canonical facts this disclosure is bound to. It contains no value and
    /// no derivation of one: an item identifier, its Keychain account name, its
    /// opaque credential revision, the destination and the policy revision.
    public static func digest(item: VaultItem, field: VaultItemField, destination: HumanDisclosureDestination) -> String {
        canonicalDigest([
            "policy:\(policyRevision)",
            "destination:\(destination.rawValue)",
            "item:\(item.id.uuidString)",
            "account:\(field.keychainAccount ?? item.keychainAccount)",
            "version:\(field.credentialVersion?.uuidString ?? "none")",
            // The item's own revision as well as the field's. The two are
            // mirrored for the primary field by `VaultItemTypes.normalize`, but
            // binding both means a rotation invalidates an open authentication
            // whether or not the repair pass has run on the record in hand.
            "itemversion:\(item.credentialVersion?.uuidString ?? "none")",
            // BL-079. The field is part of what was authorized. Without it, an
            // authentication for one field of an item would re-resolve cleanly
            // against another field of the same item after a change.
            "field:\(field.id.uuidString)",
            "fieldkey:\(field.key)"
        ])
    }

    /// The pre-BL-079 spelling: the digest of an item's primary field. It is
    /// kept so a caller that thinks in items rather than fields — and every
    /// test that predates BL-079 — keeps computing the same value the service
    /// does for `fieldID: nil`.
    public static func digest(item: VaultItem, destination: HumanDisclosureDestination) -> String {
        guard let primary = item.primaryField else {
            return unresolvedFieldDigest(item: item, fieldID: nil, destination: destination)
        }
        return digest(item: item, field: primary, destination: destination)
    }

    /// The digest for a field that could not be resolved: a certificate item
    /// with no scalar value, a field id that names nothing, a plain metadata
    /// field. Distinct from every resolvable field's digest, so a refusal is
    /// never mistaken for a record about a real disclosure.
    public static func unresolvedFieldDigest(item: VaultItem, fieldID: UUID?, destination: HumanDisclosureDestination) -> String {
        canonicalDigest([
            "policy:\(policyRevision)",
            "destination:\(destination.rawValue)",
            "item:\(item.id.uuidString)",
            "account:unresolved",
            "version:unresolved",
            "field:\(fieldID?.uuidString ?? "primary")",
            "fieldkey:unresolved"
        ])
    }

    /// The digest for an item that could not be resolved at all. It is distinct
    /// from every resolvable item's digest, so a refusal for a missing record is
    /// never mistaken for one about a real one.
    public static func unresolvedDigest(itemID: UUID, destination: HumanDisclosureDestination) -> String {
        canonicalDigest([
            "policy:\(policyRevision)",
            "destination:\(destination.rawValue)",
            "item:\(itemID.uuidString)",
            "account:unresolved",
            "version:unresolved",
            "field:unresolved",
            "fieldkey:unresolved"
        ])
    }

    /// The canonical facts an attachment preview is bound to. Like the field
    /// digest, it contains no value and no derivation of one: the item, the
    /// vault whose key seals the blob, the content address and the media type.
    public static func attachmentDigest(item: VaultItem, attachment: VaultItemAttachment) -> String {
        canonicalDigest([
            "policy:\(policyRevision)",
            "destination:\(HumanDisclosureDestination.attachmentOnScreen.rawValue)",
            "item:\(item.id.uuidString)",
            "vault:\(attachment.vaultID.uuidString)",
            "attachment:\(attachment.id)",
            "mediatype:\(attachment.mediaType)"
        ])
    }

    private static func canonicalDigest(_ lines: [String]) -> String {
        SHA256.hash(data: Data(lines.joined(separator: "\n").utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

#if !canImport(AppKit)
/// Fail-closed stand-in for a platform with no pasteboard. Copy refuses rather
/// than silently succeeding.
struct UnavailablePasteboard: ConcealedPasteboard {
    var changeCount: Int { 0 }
    func writeConcealed(_ secret: VaultSecret) throws -> Int {
        throw VaultageError.unsupported("This platform has no clipboard.")
    }
    @discardableResult func clear() -> Int { 0 }
}
#endif
