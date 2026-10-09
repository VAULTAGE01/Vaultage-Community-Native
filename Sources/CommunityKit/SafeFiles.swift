import Darwin
import Foundation
import VaultageCore

/// Descriptor-relative operations prevent symlink replacement from redirecting
/// reads/writes. Advisory locking coordinates this application's store instances.
/// It is not an isolation boundary against an unrestricted same-user attacker.
final class MetadataDirectory {
    static let metadataName = "workspace.json"
    static let rollbackName = "workspace.previous.json"
    private let descriptor: Int32
    private let lockDescriptor: Int32
    private let writeCheck: (@Sendable () throws -> Void)?

    init(_ url: URL, writeCheck: (@Sendable () throws -> Void)? = nil) throws {
        self.writeCheck = writeCheck
        descriptor = try SafeFile.openDirectory(url, createFinal: true)
        do {
            var attributes = stat()
            guard fstat(descriptor, &attributes) == 0, attributes.st_uid == getuid(),
                  fchmod(descriptor, 0o700) == 0 else { throw CommunityError.unsafeFile }
            var lock: Int32 = -1
            for _ in 0..<3 {
                lock = openat(descriptor, ".workspace.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
                // Observed macOS first-launch lookup race: two creators of a
                // new directory's lock file can transiently receive ENOENT.
                // Retry the same validated directory descriptor, never a path
                // fallback or a less restrictive set of flags.
                if lock >= 0 || errno != ENOENT { break }
            }
            guard lock >= 0 else { throw CommunityError.storageUnavailable }
            do {
                try SafeFile.checkPrivateRegularFile(lock)
                guard flock(lock, LOCK_EX) == 0 else { throw CommunityError.storageUnavailable }
            } catch { close(lock); throw error }
            lockDescriptor = lock
        } catch { close(descriptor); throw error }
    }

    deinit {
        flock(lockDescriptor, LOCK_UN)
        close(lockDescriptor)
        close(descriptor)
    }

    func readMetadata() throws -> Data? {
        // An interrupted cross-store transaction cannot be unambiguously replayed
        // without knowing whether macOS completed the Keychain call. Fail closed
        // for explicit review; never automatically delete an unknown credential.
        guard try !exists(Self.rollbackName) else { throw CommunityError.recoveryRequired }
        return try read(Self.metadataName)
    }

    func replace(_ data: Data, protectingExternalMutation: Bool = false, externalMutation: () throws -> Void = {}) throws {
        guard data.count <= CommunityStore.maximumMetadataBytes else { throw CommunityError.malformedMetadata }
        guard try !exists(Self.rollbackName) else { throw CommunityError.recoveryRequired }
        let previous = try read(Self.metadataName)
        do { try writeCheck?() }
        catch { throw CommunityError.storageUnavailable }
        let temporary = ".workspace-\(UUID().uuidString).tmp"
        defer { unlinkat(descriptor, temporary, 0) }
        try createFile(temporary, data: data)
        if protectingExternalMutation {
            try createFile(Self.rollbackName, data: previous ?? Data())
        }
        guard renameat(descriptor, temporary, descriptor, Self.metadataName) == 0 else {
            if protectingExternalMutation { unlinkat(descriptor, Self.rollbackName, 0) }
            throw CommunityError.storageUnavailable
        }
        // Persist the label-only rollback before touching the external vault.
        guard fsync(descriptor) == 0 else {
            try restore(previous, protected: protectingExternalMutation)
            throw CommunityError.storageUnavailable
        }
        do { try externalMutation() }
        catch {
            try restore(previous, protected: protectingExternalMutation)
            throw error
        }
        if protectingExternalMutation {
            // The credential operation has succeeded. No fallible write follows
            // it that could report failure while pretending to undo that success.
            // A leftover backup makes the next open fail closed for review.
            _ = unlinkat(descriptor, Self.rollbackName, 0)
            _ = fsync(descriptor)
        }
    }

    private func restore(_ previous: Data?, protected: Bool) throws {
        if protected {
            if previous != nil {
                guard renameat(descriptor, Self.rollbackName, descriptor, Self.metadataName) == 0 else { throw CommunityError.recoveryRequired }
            } else {
                guard unlinkat(descriptor, Self.metadataName, 0) == 0 else { throw CommunityError.recoveryRequired }
                guard unlinkat(descriptor, Self.rollbackName, 0) == 0 else { throw CommunityError.recoveryRequired }
            }
        } else if let previous {
            let restoration = ".restore-\(UUID().uuidString).tmp"
            defer { unlinkat(descriptor, restoration, 0) }
            try createFile(restoration, data: previous)
            guard renameat(descriptor, restoration, descriptor, Self.metadataName) == 0 else { throw CommunityError.recoveryRequired }
        } else {
            guard unlinkat(descriptor, Self.metadataName, 0) == 0 else { throw CommunityError.recoveryRequired }
        }
        _ = fsync(descriptor)
    }

    private func exists(_ name: String) throws -> Bool {
        var attributes = stat()
        if fstatat(descriptor, name, &attributes, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        guard errno == ENOENT else { throw CommunityError.storageUnavailable }
        return false
    }

    private func read(_ name: String) throws -> Data? {
        let file = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else {
            if errno == ENOENT { return nil }
            throw CommunityError.unsafeFile
        }
        defer { close(file) }
        try SafeFile.checkPrivateRegularFile(file)
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_size > 0,
              attributes.st_size <= CommunityStore.maximumMetadataBytes else { throw CommunityError.malformedMetadata }
        var data = Data(count: Int(attributes.st_size))
        try data.withUnsafeMutableBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.read(file, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw CommunityError.storageUnavailable }
                offset += count
            }
            var extra: UInt8 = 0
            guard Darwin.read(file, &extra, 1) == 0 else { throw CommunityError.malformedMetadata }
        }
        return data
    }

    private func createFile(_ name: String, data: Data) throws {
        let file = openat(descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw CommunityError.storageUnavailable }
        var finished = false
        defer { close(file); if !finished { unlinkat(descriptor, name, 0) } }
        try data.withUnsafeBytes { try SafeFile.writeAll(file, bytes: $0) }
        guard fsync(file) == 0 else { throw CommunityError.storageUnavailable }
        finished = true
    }
}

private enum SafeFile {
    /// Walk each component from / using O_NOFOLLOW. A caller can explicitly
    /// canonicalize a known system alias such as /var before supplying a URL.
    static func openDirectory(_ url: URL, createFinal: Bool = false) throws -> Int32 {
        guard url.isFileURL, url.path.hasPrefix("/"), !url.path.contains("\0") else { throw CommunityError.unsafeFile }
        // Do not use standardizedFileURL here: on macOS Foundation rewrites
        // /private/var back to the /var symlink, which would undo a caller's
        // explicit canonicalization before this no-follow traversal.
        let components = url.pathComponents.filter { $0 != "/" }
        guard !components.isEmpty, !components.contains("."), !components.contains("..") else { throw CommunityError.unsafeFile }
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw CommunityError.storageUnavailable }
        do {
            for (index, component) in components.enumerated() {
                if createFinal, index == components.count - 1 {
                    // Let mkdir's atomic EEXIST decision arbitrate first-launch
                    // concurrency, rather than using a prior existence lookup.
                    guard mkdirat(descriptor, component, 0o700) == 0 || errno == EEXIST else { throw CommunityError.storageUnavailable }
                }
                let next = openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw CommunityError.unsafeFile }
                close(descriptor)
                descriptor = next
            }
            return descriptor
        } catch { close(descriptor); throw error }
    }

    static func checkPrivateRegularFile(_ descriptor: Int32) throws {
        var attributes = stat()
        guard fstat(descriptor, &attributes) == 0, (attributes.st_mode & S_IFMT) == S_IFREG,
              attributes.st_uid == getuid(), attributes.st_nlink == 1, attributes.st_mode & 0o077 == 0
        else { throw CommunityError.unsafeFile }
    }

    static func writeAll(_ descriptor: Int32, bytes: UnsafeRawBufferPointer) throws {
        var offset = 0
        while offset < bytes.count {
            let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw CommunityError.storageUnavailable }
            offset += count
        }
    }
}

final class NewExportFile {
    private let directory: Int32
    private let filename: String
    private let publicationCheck: (@Sendable () throws -> Void)?

    init(_ target: URL, publicationCheck: (@Sendable () throws -> Void)? = nil) throws {
        guard target.isFileURL, !target.hasDirectoryPath, !target.path.contains("\0"),
              target.lastPathComponent != ".", target.lastPathComponent != "..", !target.lastPathComponent.isEmpty
        else { throw CommunityError.unsafeFile }
        let openedDirectory = try SafeFile.openDirectory(target.deletingLastPathComponent())
        let targetName = target.lastPathComponent
        var attributes = stat()
        if fstatat(openedDirectory, targetName, &attributes, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT {
            // Keep stored properties uninitialized until preflight succeeds, so
            // a throwing initializer cannot also run deinit and double-close.
            close(openedDirectory)
            throw CommunityError.unsafeFile
        }
        directory = openedDirectory
        filename = targetName
        self.publicationCheck = publicationCheck
    }

    deinit { close(directory) }

    func write(_ buffer: ExportBuffer) throws {
        // Do not create the public target until the whole export is durable.
        // Failure cleanup never names that target, which another writer might
        // have created or replaced while the human was authenticating.
        let temporary = ".vaultage-export-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw CommunityError.unsafeFile }
        defer {
            // Only clean up our private staged inode. If its name was moved or
            // replaced, leave the other inode alone rather than deleting it.
            if namesOwnedStagingFile(temporary, descriptor: file) { _ = unlinkat(directory, temporary, 0) }
            close(file)
        }
        try SafeFile.checkPrivateRegularFile(file)
        try buffer.withBytes { try SafeFile.writeAll(file, bytes: $0) }
        guard fsync(file) == 0 else { throw CommunityError.storageUnavailable }
        do { try publicationCheck?() }
        catch { throw CommunityError.storageUnavailable }
        guard namesOwnedStagingFile(temporary, descriptor: file) else { throw CommunityError.unsafeFile }
        // macOS atomic no-replace publication. O_EXCL at the start alone would
        // not protect against a new target appearing during the staging write.
        guard renameatx_np(directory, temporary, directory, filename, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw CommunityError.unsafeFile }
            throw CommunityError.storageUnavailable
        }
        _ = fsync(directory)
    }

    private func namesOwnedStagingFile(_ name: String, descriptor: Int32) -> Bool {
        var owned = stat()
        var named = stat()
        guard fstat(descriptor, &owned) == 0, fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
        return owned.st_dev == named.st_dev && owned.st_ino == named.st_ino &&
            (named.st_mode & S_IFMT) == S_IFREG && named.st_uid == getuid() && named.st_nlink == 1
    }
}

/// Plaintext export uses a fixed, explicitly zeroed scratch allocation. It never
/// materializes the entire export or a bare value as a Swift String or Data.
final class ExportBuffer {
    private let bytes: UnsafeMutableRawBufferPointer
    private var count = 0

    init(capacity: Int) {
        bytes = UnsafeMutableRawBufferPointer.allocate(byteCount: capacity, alignment: 1)
        SecretMemory.zero(bytes)
    }

    deinit { SecretMemory.zero(bytes); bytes.deallocate() }

    func appendPublic(_ text: String) throws {
        for byte in text.utf8 { try append(byte) }
    }

    func appendAssignment(key: String, secret: VaultSecret) throws {
        guard CommunityStore.isEnvironmentKey(key), secret.isValidUTF8, !secret.isEmpty,
              secret.byteCount <= CommunityStore.maximumValueBytes else { throw CommunityError.exportValueUnsupported }
        try secret.withBytes { raw in
            // A conservative common subset of Node's util.parseEnv and POSIX
            // shell quoting. Escaping for one parser can change a credential in
            // another, so ambiguous bytes are refused, never transformed.
            guard !Self.containsUnsupportedExportScalar(raw) else {
                throw CommunityError.exportValueUnsupported
            }
            try appendPublic(key + "='")
            for byte in raw { try append(byte) }
            try appendPublic("'\n")
        }
    }

    private func append(_ byte: UInt8) throws {
        guard count < bytes.count else { throw CommunityError.exportTooLarge }
        bytes[count] = byte
        count += 1
    }

    /// Scan already validated UTF-8 without copying a credential into a String.
    /// Unicode controls/newlines are also refused, including C1 and separators.
    private static func containsUnsupportedExportScalar(_ raw: UnsafeRawBufferPointer) -> Bool {
        var index = 0
        while index < raw.count {
            let first = raw[index]
            let length: Int
            var scalar: UInt32
            switch first {
            case 0...0x7F: length = 1; scalar = UInt32(first)
            case 0xC2...0xDF: length = 2; scalar = UInt32(first & 0x1F)
            case 0xE0...0xEF: length = 3; scalar = UInt32(first & 0x0F)
            case 0xF0...0xF4: length = 4; scalar = UInt32(first & 0x07)
            default: return true
            }
            guard raw.count - index >= length else { return true }
            if length > 1 {
                for offset in 1..<length { scalar = (scalar << 6) | UInt32(raw[index + offset] & 0x3F) }
            }
            guard let character = Unicode.Scalar(scalar) else { return true }
            if scalar == 0x27 || scalar == 0x5C || CharacterSet.controlCharacters.contains(character) || CharacterSet.newlines.contains(character) { return true }
            index += length
        }
        return false
    }

    func withBytes(_ body: (UnsafeRawBufferPointer) throws -> Void) rethrows {
        try body(UnsafeRawBufferPointer(start: bytes.baseAddress, count: count))
    }
}
