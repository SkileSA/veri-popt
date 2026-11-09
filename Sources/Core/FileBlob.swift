import CryptoKit
import Foundation

/// Attachment objects (SPEC § 7): AES-GCM combined blobs under a per-file
/// DEK carried, base64, inside the owning row's encrypted payload.
enum FileBlob {
    /// 12-byte nonce + 16-byte tag.
    static let overhead = 28
    static let thumbSuffix = ".thumb"

    enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case malformedDEK
        case tooShort(Int)
        case authenticationFailed

        var description: String {
            switch self {
            case .malformedDEK: "file DEK is not base64 of 32 bytes"
            case .tooShort(let n): "blob is \(n) bytes, shorter than the \(FileBlob.overhead)-byte nonce + tag"
            case .authenticationFailed: "authentication failed (wrong DEK, or the object was modified)"
            }
        }
    }

    /// Decodes an `attachmentRef.fileDEK` string.
    static func dek(from base64: String) throws -> SymmetricKey {
        guard let bytes = Data(base64Encoded: base64), bytes.count == Derivation.Constants.keyLength else {
            throw Error.malformedDEK
        }
        return SymmetricKey(data: bytes)
    }

    /// The bucket key of a row's thumbnail object.
    static func thumbObjectKey(storageKey: String) -> String {
        storageKey + thumbSuffix
    }

    static func open(_ combined: Data, with dek: SymmetricKey) throws -> Data {
        guard combined.count >= overhead else { throw Error.tooShort(combined.count) }
        let box = try AES.GCM.SealedBox(combined: combined)
        do {
            return try AES.GCM.open(box, using: dek)
        } catch CryptoKitError.authenticationFailure {
            throw Error.authenticationFailed
        }
    }

    static func seal(_ plaintext: Data, with dek: SymmetricKey) throws -> Data {
        try AES.GCM.seal(plaintext, using: dek).combined!
    }
}
