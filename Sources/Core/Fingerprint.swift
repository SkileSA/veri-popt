import CryptoKit
import Foundation

/// Short, non-reversible label for key material: the first bytes of a
/// SHA-256 digest, hex. Reports print fingerprints so two runs can be
/// compared without ever showing a key.
enum Fingerprint {
    static func of(_ bytes: Data, length: Int = 8) -> String {
        SHA256.hash(data: bytes).prefix(length).map { String(format: "%02x", $0) }.joined()
    }

    static func of(_ key: SymmetricKey, length: Int = 8) -> String {
        of(key.withUnsafeBytes { Data($0) }, length: length)
    }
}
