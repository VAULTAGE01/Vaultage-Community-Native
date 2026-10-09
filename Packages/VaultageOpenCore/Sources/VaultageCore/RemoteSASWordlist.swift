import CryptoKit
import Foundation

/// BL-099 — the six-word short authentication string of §2.4, and the committed
/// word list it reads from.
///
/// **Why a word list is a committed cross-platform artefact** (version 7,
/// DB-M45; version 8, NEW-M5). Both devices compute the same 66 bits and index
/// the same list; a one-word divergence between the Mac's copy and the phone's
/// makes **every** ceremony show mismatched words, for a reason neither screen
/// can diagnose. So the file is committed once —
/// `product/contracts/remote-approvals/sas-wordlist.txt` — its SHA-256 is
/// recorded in the §9.3 fixture as `sasWordlistSha256`, and all three suites
/// assert it.
///
/// **Which list, and why.** The **BIP-39 English wordlist**, 2,048 words, from
/// BIP-0039 (`bitcoin/bips`, `bip-0039/english.txt`), **public domain / CC0**.
/// Chosen because it is already audited for four-character prefix-uniqueness and
/// for cross-language confusability — properties this use needs and which a
/// hand-picked list would have to re-establish. 2,048 = 2¹¹, so six words are
/// **exactly 66 bits**.
///
/// Six words compared once beat sixteen base64url characters compared once
/// (`device_fingerprint` is `hash(jwk).slice(0,16)`, `device.ts:224`): words are
/// read as units and mismatches are salient.
public struct RemoteSASWordlist: Sendable {
    /// The repository path of the single committed copy. Three suites in two
    /// languages read this one file; **there is deliberately no second copy**,
    /// because two copies is the divergence the artefact exists to prevent.
    public static let repositoryRelativePath = "product/contracts/remote-approvals/sas-wordlist.txt"

    /// The SHA-256 of the committed file, byte for byte including its trailing
    /// newline. This is the canonical published digest of the BIP-39 English
    /// list, which is a second, independent check that the committed bytes are
    /// the genuine list and not a transcription of it.
    public static let sha256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

    public static let wordCount = 2048
    /// Six words, eleven bits each.
    public static let sasWordCount = 6
    public static let bitsPerWord = 11
    /// **Exactly 66**, stated as a constant because "the first 66 bits" is the
    /// sentence two implementations have to agree on.
    public static let sasBitCount = sasWordCount * bitsPerWord

    public let words: [String]

    /// Validates the list rather than trusting it. Every property here is one
    /// the ceremony's usefulness rests on, so a corrupted or substituted file is
    /// a refusal at load rather than six wrong words at the moment of trust.
    public init(words: [String]) throws {
        guard words.count == Self.wordCount else {
            throw VaultageError.storage("The SAS word list must hold exactly \(Self.wordCount) words; this one holds \(words.count).")
        }
        guard Set(words).count == words.count else {
            throw VaultageError.storage("The SAS word list repeats a word.")
        }
        guard words == words.sorted() else {
            throw VaultageError.storage("The SAS word list is not in sorted order.")
        }
        guard words.allSatisfy({ word in
            !word.isEmpty && word.count <= 8 && word.allSatisfy { $0.isASCII && $0.isLowercase && $0.isLetter }
        }) else {
            throw VaultageError.storage("The SAS word list carries a word that is not lower-case ASCII letters.")
        }
        // Four-character prefix uniqueness is the property that lets an owner
        // compare at a glance and a builder truncate safely.
        guard Set(words.map { String($0.prefix(4)) }).count == words.count else {
            throw VaultageError.storage("The SAS word list is not four-character prefix-unique.")
        }
        self.words = words
    }

    /// Parses the committed file's bytes: one word per line, a trailing newline,
    /// nothing else. The digest is checked **before** the words are used.
    public static func parse(_ data: Data) throws -> RemoteSASWordlist {
        let observed = Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
        guard observed == sha256 else {
            throw VaultageError.storage("The SAS word list's SHA-256 is \(observed); this build pins \(sha256). One divergent word makes every pairing ceremony show mismatched words for a reason neither screen can diagnose.")
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw VaultageError.storage("The SAS word list is not UTF-8.")
        }
        var lines = text.components(separatedBy: "\n")
        if lines.last == "" { lines.removeLast() }
        return try RemoteSASWordlist(words: lines)
    }

    public static func load(from url: URL) throws -> RemoteSASWordlist {
        guard let data = FileManager.default.contents(atPath: url.path) else {
            throw VaultageError.storage("The SAS word list is not at \(url.path).")
        }
        return try parse(data)
    }

    // MARK: - Runtime resolution (BL-099 item 2, `Scripts/build-app.sh` staging)

    /// Where `loadForRuntime` found the list, or why it refused to look
    /// further — kept so a self-test can assert *which* branch ran rather than
    /// only its outcome.
    public enum RuntimeSource: Equatable, Sendable {
        /// `bundle.url(forResource: "sas-wordlist", withExtension: "txt")`
        /// resolved. `Scripts/build-app.sh` stages the committed file here —
        /// verifying its SHA-256 against `sasWordlistSha256` at build time —
        /// for exactly this to succeed in a shipped `.app`.
        case bundleResource(URL)
        /// This process is not a bundled `.app` (a `swift run` binary, this
        /// package's own self-tests, or a build-time verification step), so
        /// reading the single committed repository file carries none of the
        /// risk documented on `isBundledApp(_:)`'s doc comment below.
        case repositoryFile(URL)
        /// A real, bundled `.app` with nothing staged in `Resources`. Refused
        /// rather than falling back to the repository or an environment
        /// override — see `isBundledApp(_:)` below.
        case none
    }

    /// **Why a bundled `.app` may never fall back to the repository copy, or
    /// to an environment override, when nothing is staged.** An earlier
    /// version of this loader resolved the committed file from `#filePath`
    /// unconditionally, which is a path under the owner's `~/Documents`. A
    /// bundled, hardened-runtime, `.accessory`-policy app reading a path under
    /// `~/Documents` raises the "would like to access files in your Documents
    /// folder" TCC prompt, and an app that never comes to the front cannot
    /// show one: the capture bundle **hung**, two 0×0 windows, no error, no
    /// crash, with `sample` putting the main thread inside `open()`
    /// (`blueprint/evidence/ui-lane-remote-approval-views-2026-09-13.md` §6).
    ///
    /// A `swift run` process is not that process. It is a plain, foreground
    /// binary that already holds whatever filesystem access its terminal has —
    /// the same reason `VaultageSelfTests` already reads this repository
    /// directly for its own fixtures. The rule this type exists to enforce is
    /// therefore not "prefer the bundle" but **"never reach into the
    /// repository, or honour a caller-supplied path, from something Finder
    /// could have launched."** `bundle.bundleURL.pathExtension == "app"` is
    /// what tells the two apart: a `swift run` binary's `Bundle.main` has no
    /// `.app` bundle at all, while every shipped or staged build — signed or
    /// the unsigned development-preview `Scripts/build-app.sh` also stages —
    /// does.
    public static func isBundledApp(_ bundle: Bundle) -> Bool { bundle.bundleURL.pathExtension == "app" }

    /// Resolves the committed word list the way `Scripts/build-app.sh` and
    /// `swift run` each make true: the staged bundle resource inside a real
    /// `.app`, and the repository's own committed copy everywhere else.
    ///
    /// `environment`'s `VAULTAGE_SAS_WORDLIST` is a development-only override
    /// (pointing a self-test or a capture harness at a scratch copy of the
    /// list), consulted **only** when this process is not a bundled `.app` —
    /// the same boundary that gates the repository fallback, for the same
    /// reason.
    public static func resolveRuntimeSource(
        bundle: Bundle = .main,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> RuntimeSource {
        if let bundled = bundle.url(forResource: "sas-wordlist", withExtension: "txt") {
            return .bundleResource(bundled)
        }
        guard !isBundledApp(bundle) else { return .none }
        if let override = environment["VAULTAGE_SAS_WORDLIST"]?.trimmingCharacters(in: .whitespaces), !override.isEmpty {
            return .repositoryFile(URL(fileURLWithPath: override))
        }
        return .repositoryFile(repositoryFileURL())
    }

    /// `resolveRuntimeSource` plus the load and the digest check `load(from:)`
    /// already does. `nil` covers three distinct refusals a caller does not
    /// need to tell apart: nothing staged in a real bundle, a file that is not
    /// there, and a file whose SHA-256 does not match — in every case the
    /// ceremony screen shows no words rather than six wrong ones, which is
    /// `RemotePairingCeremonyModel`'s own rule.
    public static func loadForRuntime(
        bundle: Bundle = .main,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> RemoteSASWordlist? {
        switch resolveRuntimeSource(bundle: bundle, environment: environment) {
        case .bundleResource(let url), .repositoryFile(let url): return try? load(from: url)
        case .none: return nil
        }
    }

    /// The repository's single committed copy (`repositoryRelativePath`),
    /// located from this source file's own path rather than from the current
    /// working directory, so it resolves the same way whether this runs under
    /// `swift build`, `swift test`, or a script invoked from any directory.
    /// Only ever consulted when `resolveRuntimeSource` has already established
    /// this process is not a bundled `.app` (see
    /// `isBundledApp(_:)` above).
    /// **BM-L1.** The parameter used to default to `#filePath`, and a magic
    /// literal default argument is expanded **at the call site**: from outside
    /// `VaultageCore` this returned a path relative to the *caller's* file, and
    /// the doc comment above says "this source file's own path". In-module
    /// callers were correct, so nothing was broken — it was a footgun aimed at
    /// the next caller. The path is now a constant captured inside this file
    /// and the parameter is gone.
    public static func repositoryFileURL() -> URL {
        // …/product/apps/macos/Sources/VaultageCore/RemoteSASWordlist.swift —
        // six components up (the filename, VaultageCore, Sources, macos, apps,
        // product) reaches the repository root.
        var url = URL(fileURLWithPath: ownSourceFile)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url.appendingPathComponent(repositoryRelativePath)
    }

    /// Expanded here, in this file, once — never as a default argument.
    private static let ownSourceFile = #filePath

    /// The six words for a completed §2.4 exchange.
    ///
    /// > six words = six 11-bit indices over the **first 66 bits** of the
    /// > digest, read **MSB-first from byte 0**: word 0 = bits 0..10, word 5 =
    /// > bits 55..65.
    ///
    /// The digest is the SHA-256 of `CanonicalDigest.encode(P2)`, so the bits
    /// are the hash's own bytes rather than a re-encoding of its hex — reading
    /// the hex string's characters would give a different and equally
    /// plausible-looking answer, which is exactly the kind of divergence the
    /// fixture exists to catch.
    public func words(for inputs: RemoteSASInputs) -> [String] {
        let digest = Data(SHA256.hash(data: CanonicalDigest.encode(RemoteApprovalDigests.sasFields(inputs))))
        return words(forDigestBytes: digest)
    }

    /// Split out so the bit reader can be exercised against known vectors
    /// without building a whole pairing.
    public func words(forDigestBytes digest: Data) -> [String] {
        let bytes = [UInt8](digest)
        return (0..<Self.sasWordCount).map { position in
            var index = 0
            for bit in 0..<Self.bitsPerWord {
                let absolute = position * Self.bitsPerWord + bit
                let byte = bytes[absolute / 8]
                let value = (byte >> (7 - UInt8(absolute % 8))) & 1
                index = (index << 1) | Int(value)
            }
            return words[index]
        }
    }
}
