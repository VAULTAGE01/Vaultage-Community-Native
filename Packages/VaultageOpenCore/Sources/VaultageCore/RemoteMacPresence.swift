import Foundation
#if canImport(AppKit)
import AppKit
import CoreGraphics
import IOKit.pwr_mgt
#endif

/// BL-099 slice 2 step (c) — **§3.7.1's presence detector, the power assertion
/// and the wake resume.**
///
/// Three separate things that share one fact about this Mac: whether the owner
/// is at it, and whether it is going to stay awake long enough to hear an
/// answer. All three are structured the same way — a **pure decision** over
/// signals, and a thin shim that reads the signals — because the decision is
/// what has to be right and the shim is what cannot be tested unsigned in CI.

// MARK: - The signals, as data

/// One reading of the three signals §3.7.1 names. Separated from the OS calls so
/// the table can be asserted exhaustively.
public struct RemotePresenceSignals: Hashable, Sendable {
    /// `CGSessionCopyCurrentDictionary()` answered at all. `false` is the
    /// `unknown` case, and it is **counted** (§3.7.1).
    public let sessionReadable: Bool
    /// `kCGSessionOnConsoleKey`. **Authoritative.**
    public let onConsole: Bool
    /// `CGSSessionScreenIsLocked`. **Authoritative.**
    public let screenLocked: Bool
    /// Set by the `NSWorkspace` sleep observer and cleared on wake. A display
    /// that is asleep is treated the same: LocalAuthentication cannot prompt at
    /// either.
    public let asleepSinceLastWake: Bool
    /// `CGEventSourceSecondsSinceLastEventType(.combinedSessionState,
    /// .anyInputEventType)` — a **counter**, not an event tap, so no input
    /// content is observed.
    public let secondsSinceLastInput: TimeInterval

    public init(sessionReadable: Bool, onConsole: Bool, screenLocked: Bool, asleepSinceLastWake: Bool, secondsSinceLastInput: TimeInterval) {
        self.sessionReadable = sessionReadable
        self.onConsole = onConsole
        self.screenLocked = screenLocked
        self.asleepSinceLastWake = asleepSinceLastWake
        self.secondsSinceLastInput = secondsSinceLastInput
    }
}

public enum RemotePresenceRule {
    /// §3.7.1's default threshold.
    public static let idleThresholdSeconds: TimeInterval = 120

    /// §3.7.1's table, in its own order of authority.
    ///
    /// **Unreadable signals are `unknown`, never `active`.** A build in which
    /// detection silently never works must not be a build that reports the
    /// owner as present; `unknown` alerts, is counted, and — per
    /// `RemotePresence.canPromptForPresence` — is treated as unable to prompt.
    public static func presence(_ s: RemotePresenceSignals, idleThreshold: TimeInterval = idleThresholdSeconds) -> RemotePresence {
        guard s.sessionReadable else { return .unknown }
        if s.asleepSinceLastWake { return .asleep }
        // Screen locked **or another user holds the console** — §3.7.1 words
        // them as one row, because the consequence is identical: this login
        // session cannot raise a prompt.
        if s.screenLocked || !s.onConsole { return .locked }
        guard s.secondsSinceLastInput.isFinite, s.secondsSinceLastInput >= 0 else { return .unknown }
        return s.secondsSinceLastInput <= idleThreshold ? .active : .idle
    }
}

// MARK: - The Mac-only half
//
// **BL-096 slice 1.** Everything below reads macOS-only signals —
// `CGSessionCopyCurrentDictionary`, `NSWorkspace`'s sleep notifications and
// `IOPMAssertionCreateWithName` — and describes *the Mac's* presence, which is
// §3.7.1's subject. The phone never computes it: `RemoteApprovalSummary`
// carries `presence` as a field the Mac sealed, and the phone renders it.
//
// The two types above this line are pure functions over
// `RemotePresenceSignals` and compile everywhere, so the phone's tests assert
// §3.7.1's table from the same implementation the Mac runs.
#if canImport(AppKit)

// MARK: - The detector

/// Reads the three signals and applies `RemotePresenceRule`.
///
/// **Established, not assumed** (§12 platform fact 7): the spike ran
/// `CGSessionCopyCurrentDictionary` and `CGEventSourceSecondsSinceLastEventType`
/// unsigned, without Accessibility and **without App Sandbox**, which is what
/// ships. Adding `com.apple.security.app-sandbox` invalidates that fact —
/// `CGSessionCopyCurrentDictionary` has no public header — and the entitlements
/// files are asserted not to carry it by `Scripts/build-app.sh`.
///
/// `com.apple.screenIsLocked` is **not** observed. §3.7.1 marks the distributed
/// notification an optimisation only, because its delivery is not certain, and
/// a design that depends on it has a silent failure mode this one does not.
public final class RemoteMacPresenceDetector: RemotePresenceProbe, @unchecked Sendable {
    private let lock = NSLock()
    private var asleep = false
    private var unknownReadings = 0
    private var observers: [NSObjectProtocol] = []
    private let idleThreshold: TimeInterval
    /// Injected only so the self-tests can drive the table; the product passes
    /// nothing and the real signals are read.
    private let readSignals: (@Sendable (Bool) -> RemotePresenceSignals)?

    public init(idleThreshold: TimeInterval = RemotePresenceRule.idleThresholdSeconds, readSignals: (@Sendable (Bool) -> RemotePresenceSignals)? = nil) {
        self.idleThreshold = idleThreshold
        self.readSignals = readSignals
    }

    deinit { stopObservingSleep() }

    /// The counter §3.7.1 requires: "a build in which detection silently never
    /// works would otherwise be indistinguishable from an owner who is always
    /// away". Surfaced in the Mac's diagnostics.
    public var unknownPresenceReadings: Int {
        lock.lock(); defer { lock.unlock() }
        return unknownReadings
    }

    public func currentPresence() -> RemotePresence {
        let signals = signalsNow()
        let presence = RemotePresenceRule.presence(signals, idleThreshold: idleThreshold)
        if presence == .unknown {
            lock.lock(); unknownReadings += 1; lock.unlock()
        }
        return presence
    }

    public func signalsNow() -> RemotePresenceSignals {
        lock.lock(); let sleeping = asleep; lock.unlock()
        if let readSignals { return readSignals(sleeping) }
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else {
            return RemotePresenceSignals(sessionReadable: false, onConsole: false, screenLocked: false, asleepSinceLastWake: sleeping, secondsSinceLastInput: 0)
        }
        let onConsole = (session[kCGSessionOnConsoleKey as String] as? NSNumber)?.boolValue ?? false
        let locked = (session["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue ?? false
        // `kCGAnyInputEventType` is `~0` and CoreGraphics does not expose it as
        // a `CGEventType` case in Swift. It is the documented sentinel, and it
        // is what makes this a counter over *any* input rather than over one
        // event kind.
        let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: ~0)!)
        return RemotePresenceSignals(sessionReadable: true, onConsole: onConsole, screenLocked: locked, asleepSinceLastWake: sleeping, secondsSinceLastInput: idle)
    }

    /// `NSWorkspace`'s sleep and wake notifications — the third signal. System
    /// and **display** sleep both set the flag, because the owner cannot answer
    /// a prompt at either.
    public func startObservingSleep(onWake: @escaping @Sendable () -> Void = {}) {
        stopObservingSleep()
        let center = NSWorkspace.shared.notificationCenter
        func observe(_ name: NSNotification.Name, _ body: @escaping @Sendable () -> Void) {
            observers.append(center.addObserver(forName: name, object: nil, queue: nil) { _ in body() })
        }
        observe(NSWorkspace.willSleepNotification) { [weak self] in self?.setAsleep(true) }
        observe(NSWorkspace.screensDidSleepNotification) { [weak self] in self?.setAsleep(true) }
        observe(NSWorkspace.didWakeNotification) { [weak self] in self?.setAsleep(false); onWake() }
        observe(NSWorkspace.screensDidWakeNotification) { [weak self] in self?.setAsleep(false); onWake() }
    }

    public func stopObservingSleep() {
        let center = NSWorkspace.shared.notificationCenter
        for observer in observers { center.removeObserver(observer) }
        observers = []
    }

    /// The sleep observer's writer, and the seam the self-tests drive. Public
    /// because the third signal has no readable OS accessor — "has this Mac
    /// slept since the last wake" is a fact only the notification stream knows.
    public func setAsleep(_ value: Bool) { lock.lock(); asleep = value; lock.unlock() }
}

// MARK: - The power assertion, and the wake resume

/// **Why an assertion at all.** A pending lives for five minutes (§3.5) and the
/// decision arrives over the network. If the Mac idle-sleeps in the middle of
/// that window the owner taps Approve on the phone, the Mac never fetches it,
/// and the pending expires — which reads to the owner as "remote approval does
/// not work", not as "my Mac slept".
///
/// **What it must not be.** `kIOPMAssertPreventUserIdleSystemSleep` prevents
/// *idle* sleep only: a closed lid, a chosen Sleep, or low power still sleep the
/// Mac, and nothing here overrides the owner. It is held only while a decision
/// window is open, is released the instant the window closes, and is bounded by
/// the pending's own TTL so a leaked window cannot hold a Mac awake.
public enum RemotePowerAssertionRule {
    /// The ceiling, from §3.5: no assertion outlives the longest pending.
    public static let maximumSeconds = TimeInterval(RemotePendingTTL.ceilingSeconds)

    /// Should an assertion be held right now, and for how long?
    ///
    /// Returns `nil` when none should be held. Pure, so the decision is
    /// asserted in CI and only the `IOPMAssertionCreateWithName` call is not.
    public static func assertionSeconds(openWindows: [Date], now: Date) -> TimeInterval? {
        let remaining = openWindows.map { $0.timeIntervalSince(now) }.filter { $0 > 0 }
        guard let longest = remaining.max() else { return nil }
        return min(longest, maximumSeconds)
    }
}

/// Holds at most one `kIOPMAssertPreventUserIdleSystemSleep` assertion while a
/// remote decision window is open, and resumes the fetch on wake.
public final class RemoteDecisionWindow: @unchecked Sendable {
    private let lock = NSLock()
    private var windows: [String: Date] = [:]
    private var assertion: IOPMAssertionID = 0
    private var holding = false
    /// Pendings that were open when the Mac slept. §5.6's sibling problem: on
    /// wake the answer may already be waiting, and nothing else would fetch it
    /// until the next poll tick — which can be after the pending expires.
    private var resumeOnWake: @Sendable ([String]) -> Void = { _ in }

    public init() {}

    deinit { release() }

    public func onWakeResume(_ body: @escaping @Sendable ([String]) -> Void) {
        lock.lock(); resumeOnWake = body; lock.unlock()
    }

    /// Opens a window for one pending, bounded by its own expiry.
    public func open(pendingID: String, until expiresAt: Date, now: Date = Date()) {
        lock.lock()
        windows[pendingID] = expiresAt
        let seconds = RemotePowerAssertionRule.assertionSeconds(openWindows: Array(windows.values), now: now)
        lock.unlock()
        apply(seconds)
    }

    /// Closes it — on a decision, a local decision, a cancel or an expiry.
    /// **Always called**, which is why it is idempotent.
    public func close(pendingID: String, now: Date = Date()) {
        lock.lock()
        windows[pendingID] = nil
        let seconds = RemotePowerAssertionRule.assertionSeconds(openWindows: Array(windows.values), now: now)
        lock.unlock()
        apply(seconds)
    }

    /// The wake half. Called from `RemoteMacPresenceDetector`'s wake observer:
    /// every window that is still open and not yet expired is handed back so
    /// its decision is fetched immediately rather than at the next tick.
    public func resumeAfterWake(now: Date = Date()) {
        lock.lock()
        let live = windows.filter { $0.value > now }.map(\.key).sorted()
        windows = windows.filter { $0.value > now }
        let body = resumeOnWake
        let seconds = RemotePowerAssertionRule.assertionSeconds(openWindows: Array(windows.values), now: now)
        lock.unlock()
        apply(seconds)
        guard !live.isEmpty else { return }
        body(live)
    }

    /// Which pendings are open. Exposed for the self-tests and the diagnostics
    /// line; nothing authorizes on it.
    public func openPendingIDs(now: Date = Date()) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return windows.filter { $0.value > now }.map(\.key).sorted()
    }

    public var isHoldingAssertion: Bool {
        lock.lock(); defer { lock.unlock() }
        return holding
    }

    /// **The computed ceiling is applied to the assertion, not discarded**
    /// (BM-M7). `IOPMAssertionCreateWithName` takes no timeout, so the old code
    /// computed `RemotePowerAssertionRule.assertionSeconds` and wrote
    /// `_ = seconds`: a window that was opened and never closed kept
    /// `holding == true` and the assertion alive for the life of the process,
    /// past the pending's own expiry, with no timer to re-evaluate — while this
    /// file's own doc comment said the assertion "is bounded by the pending's
    /// own TTL so a leaked window cannot hold a Mac awake".
    ///
    /// `IOPMAssertionCreateWithProperties` takes both, and a re-computed ceiling
    /// — a second window opened, or one closed — moves the existing assertion's
    /// timeout rather than creating a second assertion. A `SetProperty` that
    /// does not succeed means the assertion is already gone (the OS timed it
    /// out), so that path drops the stale handle and creates a fresh one instead
    /// of leaving `holding` true over nothing.
    private func apply(_ seconds: TimeInterval?) {
        lock.lock()
        defer { lock.unlock() }
        guard let seconds else {
            if holding { IOPMAssertionRelease(assertion); assertion = 0; holding = false }
            return
        }
        if holding {
            if IOPMAssertionSetProperty(assertion, kIOPMAssertionTimeoutKey as CFString, seconds as CFNumber) == kIOReturnSuccess {
                return
            }
            IOPMAssertionRelease(assertion)
            assertion = 0
            holding = false
        }
        var id: IOPMAssertionID = 0
        let properties: [String: Any] = [
            kIOPMAssertionTypeKey as String: kIOPMAssertPreventUserIdleSystemSleep as String,
            kIOPMAssertionNameKey as String: "Vaultage is waiting for a decision from your phone",
            kIOPMAssertionLevelKey as String: kIOPMAssertionLevelOn,
            kIOPMAssertionTimeoutKey as String: seconds,
            kIOPMAssertionTimeoutActionKey as String: kIOPMAssertionTimeoutActionRelease
        ]
        // A Mac that will not grant the assertion is not a Mac that refuses
        // remote approvals: the window stays open and the only cost is that an
        // idle sleep can end it early.
        guard IOPMAssertionCreateWithProperties(properties as CFDictionary, &id) == kIOReturnSuccess else { return }
        assertion = id
        holding = true
    }

    private func release() {
        lock.lock(); defer { lock.unlock() }
        if holding { IOPMAssertionRelease(assertion); assertion = 0; holding = false }
    }
}

#endif
