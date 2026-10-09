import Foundation
#if canImport(AppKit)
import AppKit
#endif

/// The OS signals that mean the owner has left this Mac, wired to a lock
/// (audit H-04). Screen lock and the screensaver arrive as distributed
/// notifications, which any process — the nested broker service included —
/// receives; sleep and the session going inactive (fast user switching) come
/// from `NSWorkspace`. Each fires the handler once; the handler is the lock,
/// and the lock is idempotent.
public final class SystemLockSignals: @unchecked Sendable {
    public static let distributedNames = ["com.apple.screenIsLocked", "com.apple.screensaver.didstart"]
    private let handler: @Sendable () async -> Void
    private var observers: [NSObjectProtocol] = []
    private let lock = NSLock()

    public init(_ handler: @escaping @Sendable () async -> Void) { self.handler = handler }

    public func start() {
        lock.lock(); defer { lock.unlock() }
        guard observers.isEmpty else { return }
        let handler = self.handler
        let fire: @Sendable () -> Void = { Task { await handler() } }
        _ = fire
        // The Mac only: the phone has no screen-lock notification a process
        // may observe, and its summaries are covered by scene phase instead.
        #if canImport(AppKit)
        let distributed = DistributedNotificationCenter.default()
        for name in Self.distributedNames {
            observers.append(distributed.addObserver(forName: Notification.Name(name), object: nil, queue: nil) { _ in fire() })
        }
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(workspace.addObserver(forName: name, object: nil, queue: nil) { _ in fire() })
        }
        #endif
    }

    public func stop() {
        lock.lock(); defer { lock.unlock() }
        #if canImport(AppKit)
        for observer in observers {
            DistributedNotificationCenter.default().removeObserver(observer)
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        #endif
        observers = []
    }

    deinit { stop() }
}
