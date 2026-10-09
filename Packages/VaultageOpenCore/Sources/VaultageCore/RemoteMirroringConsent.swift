import Foundation

/// BL-099 slice 2 step (c) — **"Approve on my phone", and the consent moment it
/// cannot be turned on without** (§3.7, DB-H7 item 3; D38).
///
/// The switch is one line of UI and three lines of rule, and the rule is the
/// part that matters: the position defaults to *When I'm away* **only after**
/// the owner acknowledges a one-screen statement naming what is published and to
/// whom. **No acknowledgement, no mirroring** — not "defaults to off", not "a
/// banner they can dismiss": `position` is unreadable until the acknowledgement
/// exists, and `RemoteMirroringSetting.effectivePosition` returns `.off`.
///
/// The copy lives here, in the core, rather than in the view, for the same
/// reason the four grant sentences live in the digest: a sentence the UI can
/// choose is a sentence the UI can quietly drop. The UI lane renders these
/// strings; a test asserts they still name both recipients.
public struct RemoteMirroringConsent: Codable, Hashable, Sendable {
    /// What the owner acknowledged. Versioned, so a materially changed statement
    /// is a **new** acknowledgement rather than a silently re-used one.
    public static let currentRevision = "vaultage.mirroring.consent.v1"

    public let revision: String
    public let acknowledgedAt: Date
    /// Which phone's enrolment raised the screen. Recorded for the receipt
    /// trail; the acknowledgement is per account, not per device.
    public let phoneDeviceID: String

    public init(revision: String = RemoteMirroringConsent.currentRevision, acknowledgedAt: Date, phoneDeviceID: String) {
        self.revision = revision
        self.acknowledgedAt = acknowledgedAt
        self.phoneDeviceID = phoneDeviceID
    }

    public var isCurrent: Bool { revision == Self.currentRevision }

    // MARK: - The copy the design names

    public static let switchTitle = "Approve on my phone"

    public static let consentTitle = "What your phone will receive"

    /// §3.7's consent moment, and A19's disclosure row: the statement names the
    /// control plane **and Apple**, because APNs receives the device token and
    /// precise timing for every push — the thing an owner would not otherwise
    /// guess and the thing the privacy policy (O7) has to match.
    public static let consentBody = [
        "When an agent asks for something that needs your approval, your Mac sends a summary of the request to Vaultage's servers, sealed so that only this phone can open it.",
        "The summary never contains a credential, a value, or anything from inside your vault. It names the agent, the provider, the project and environment, and what is being asked for.",
        "Vaultage's servers can see when a request happens and roughly what shape it is — the kind of request, whether it touches production, and when it expires — but not what it says.",
        "Apple receives a push notification for each request. That means Apple learns your device token and the exact time of every approval you are asked for, which is how notifications work on iPhone.",
        "Both keep this for a short time. You can turn this off at any time with \"Approve on my phone\", and nothing is sent while it is off."
    ]

    public static let consentAcceptLabel = "Turn on approvals on my phone"
    public static let consentDeclineLabel = "Not now"

    /// The three positions' owner-facing labels and the sentence under each, so
    /// the UI lane renders §3.7's table rather than inventing one.
    public static func label(for position: RemoteMirrorEligibility.Position) -> (title: String, detail: String) {
        switch position {
        case .off:
            ("Off", "Nothing is ever sent. Approvals happen on this Mac only.")
        case .whenAway:
            ("When I'm away", "Requests are sent to your phone only when this Mac is locked, asleep or idle.")
        case .always:
            ("Always", "Every request that can be approved remotely is sent to your phone, even while you are using this Mac.")
        }
    }
}

/// The stored switch, and the gate.
public extension RemoteMirroringConsent {
    /// What the acknowledgement prompt says (BM-M6). §2.2: the reason **names
    /// the act**, because an owner cannot tell one Touch ID prompt from another
    /// at the sensor, and this one is not a credential read.
    static let authenticationReason = "Confirm you have read what Vaultage sends to its servers and to Apple when a request waits for your phone."
}

public struct RemoteMirroringSetting: Codable, Hashable, Sendable {
    /// What the owner chose. Meaningless without `consent`.
    public let chosenPosition: RemoteMirrorEligibility.Position
    public let consent: RemoteMirroringConsent?

    public init(chosenPosition: RemoteMirrorEligibility.Position = .whenAway, consent: RemoteMirroringConsent? = nil) {
        self.chosenPosition = chosenPosition
        self.consent = consent
    }

    /// **The gate.** No current acknowledgement, no mirroring — whatever the
    /// stored position says, and including the case where a previous
    /// acknowledgement exists at an older revision.
    public var effectivePosition: RemoteMirrorEligibility.Position {
        guard let consent, consent.isCurrent else { return .off }
        return chosenPosition
    }

    public var needsConsentScreen: Bool { consent?.isCurrent != true }

    /// Acknowledging turns the switch to §3.7's default, not to `Always`: the
    /// consent screen is not where a position is chosen.
    public func acknowledged(at date: Date, phoneDeviceID: String) -> RemoteMirroringSetting {
        RemoteMirroringSetting(
            chosenPosition: chosenPosition == .off ? .whenAway : chosenPosition,
            consent: RemoteMirroringConsent(acknowledgedAt: date, phoneDeviceID: phoneDeviceID)
        )
    }

    /// Turning the switch off **keeps** the acknowledgement: the owner has read
    /// the statement, and making them read it again to turn mirroring back on
    /// is friction that teaches people to click through consent screens.
    public func movedTo(_ position: RemoteMirrorEligibility.Position) -> RemoteMirroringSetting {
        RemoteMirroringSetting(chosenPosition: position, consent: consent)
    }
}
