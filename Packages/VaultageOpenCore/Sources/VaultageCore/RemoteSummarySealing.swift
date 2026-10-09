import CryptoKit
import Foundation

/// BL-099 — HPKE, RFC 9180, ciphersuite `.P256_SHA256_AES_GCM_256` (§5.3).
///
/// **One construction, not two.** The platform-facts spike established that
/// `SecureEnclave.P256.KeyAgreement.PrivateKey` conforms to
/// `HPKEDiffieHellmanPrivateKey` and ran an authenticated-decrypt roundtrip
/// against it (fact 1), so versions 2–5's "use HPKE *if* it conforms, otherwise
/// hand-roll" is resolved and the hand-rolled ECDH + HKDF + AES-GCM schedule is
/// deleted from the protocol. There is nothing for BL-096 and BL-099 to diverge
/// on.
///
/// ```
/// envelope := version(1)=0x01 ‖ suite(1)=0x01 ‖ enc(65) ‖ ciphertext(bucket) ‖ tag(16)
/// ```
///
/// `info` is passed as **both** HPKE's `info` — so it enters the key schedule —
/// and the per-message AAD, so tampering fails the tag. There is no explicit
/// nonce field: HPKE derives the per-message nonce from the key schedule, and a
/// single-shot seal uses sequence 0.
///
/// **Availability.** CryptoKit's `HPKE` is macOS 14.0+. D45 raised the
/// package's deployment target to macOS 14 for exactly this reason — §5.3 has
/// no fallback construction, so remote approvals could not work below macOS 14
/// at all — so this construction is called directly rather than gated behind
/// an `#available` check.
public enum RemoteSummarySealing {
    /// Seals one recipient's summary.
    ///
    /// The recipient key is the phone's **pinned** `sum` or `sum2` key — never a
    /// key from the roster and never one from the wire (§2.4 rule 1).
    public static func seal(_ publication: RemoteRecipientPublication) throws -> RemoteSealedSummary {
        let recipientKey = publication.recipient.summaryRecipient(isSensitive: publication.isSensitive)
        guard let publicKey = try? P256.KeyAgreement.PublicKey(x963Representation: recipientKey.publicKey) else {
            throw VaultageError.invalidInput("A paired phone's summary key is not a usable P-256 point; re-pair it before mirroring.")
        }
        let info = CanonicalDigest.encode(RemoteApprovalDigests.summaryEnvelopeInfoFields(publication.envelopeInfo))
        let padded = try RemoteEnvelopePadding.pad(try RemoteSummaryComposer.plaintext(publication.summary))
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
        let ciphertext = try sender.seal(padded, authenticating: info)
        var envelope = Data([RemoteSealedSummary.version, RemoteSealedSummary.suite])
        envelope.append(sender.encapsulatedKey)
        envelope.append(ciphertext)
        guard RemoteEnvelopePadding.rawEnvelopeSizes.contains(envelope.count) else {
            throw VaultageError.storage("A sealed summary is \(envelope.count) bytes, which is not one of the four permitted sizes.")
        }
        return RemoteSealedSummary(
            phoneDeviceID: publication.recipient.phoneDeviceID,
            envelope: envelope,
            recipientThumbprint: recipientKey.thumbprint,
            isSensitive: publication.isSensitive,
            // The last field of the `info` this seal just used, carried beside
            // the ciphertext so the phone can rebuild the same AAD.
            sealedAt: publication.envelopeInfo.issuedAt
        )
    }

    /// Opens an envelope this Mac sealed, which is what the self-tests use to
    /// prove the seal round-trips and what the two-device live proof's failure
    /// analysis needs. The product never opens a summary it sealed: the phone
    /// does.
    public static func open(_ sealed: RemoteSealedSummary, info: RemoteSummaryEnvelopeInfo, recipientPrivateKey: P256.KeyAgreement.PrivateKey) throws -> RemoteApprovalSummary {
        guard sealed.isWellFormed else {
            throw VaultageError.invalidInput("A sealed summary's version, suite or length is wrong.")
        }
        let infoBytes = CanonicalDigest.encode(RemoteApprovalDigests.summaryEnvelopeInfoFields(info))
        let encapsulated = sealed.envelope.subdata(in: 2..<67)
        let ciphertext = sealed.envelope.subdata(in: 67..<sealed.envelope.count)
        var recipient = try HPKE.Recipient(privateKey: recipientPrivateKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: infoBytes, encapsulatedKey: encapsulated)
        let plaintext = try RemoteEnvelopePadding.unpad(try recipient.open(ciphertext, authenticating: infoBytes))
        return try JSONDecoder().decode(RemoteApprovalSummary.self, from: plaintext)
    }
}
