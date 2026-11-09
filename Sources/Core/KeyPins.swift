import CryptoKit
import Foundation

/// The account's key-pins block (SPEC § 6.5): the Curve25519 public key
/// pinned for every friend, plus the account's own, sealed under the
/// personal key. Every ECDH wrap and unwrap takes the peer's key from
/// here, never from `user_profiles`, where the server can serve any key.
struct KeyPins {
    static let type = "key_pins"
    static let scope = "user"
    /// The synced-dictionary block type tag.
    static let blockTypeTag = 14
    static let keyField = "x25519"
    static let unfriendedField = "unfriended"

    /// The deterministic id of the account's pins block:
    /// `hex(SHA256("popt-synced-dict-v1|<ownerId>|key_pins|user")[0..<16])`.
    static func blockId(ownerId: String) -> String {
        let input = "popt-synced-dict-v1|\(ownerId)|\(type)|\(scope)"
        return SHA256.hash(data: Data(input.utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    struct Entry {
        let userId: String
        /// nil when the entry cannot be read; it then counts as unpinned.
        let publicKey: Curve25519.KeyAgreement.PublicKey?
        let unfriended: Bool
        let updatedAt: Int64?
    }

    enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case notFound(id: String)
        case cannotOpen(String)
        case notADictionary(typeTag: Int)
        case wrongTenant(type: String, scope: String)

        var description: String {
            switch self {
            case .notFound(let id): "no key pins block at its id \(id)"
            case .cannotOpen(let why): "the key pins block does not open under the personal key: \(why)"
            case .notADictionary(let tag): "the row at the key pins id is not a synced dictionary (type \(tag))"
            case .wrongTenant(let t, let s): "the row at the key pins id echoes tenant \(t)/\(s), not \(KeyPins.type)/\(KeyPins.scope)"
            }
        }
    }

    let entries: [String: Entry]

    /// Reads a decrypted block as the pins block: the type tag, the tenant
    /// echo, then one entry per user id.
    init(decrypted: DecryptedBlock) throws {
        guard decrypted.type == Self.blockTypeTag else { throw Error.notADictionary(typeTag: decrypted.type) }
        let value = decrypted.value as? [String: Any] ?? [:]
        let type = value["type"] as? String ?? "?", scope = value["scope"] as? String ?? "?"
        guard type == Self.type, scope == Self.scope else { throw Error.wrongTenant(type: type, scope: scope) }
        var entries: [String: Entry] = [:]
        for (userId, raw) in value["entries"] as? [String: Any] ?? [:] {
            let field = raw as? [String: Any]
            let object = field?["value"] as? [String: Any]
            let key = (object?[Self.keyField] as? String)
                .flatMap { Data(base64Encoded: $0) }
                .flatMap { try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: $0) }
            entries[userId] = Entry(
                userId: userId,
                publicKey: key,
                unfriended: object?[Self.unfriendedField] as? Bool ?? false,
                updatedAt: (field?["updatedAt"] as? NSNumber)?.int64Value
            )
        }
        self.entries = entries
    }

    /// The pinned key, active or unfriended; nil when absent or unreadable.
    func publicKey(for userId: String) -> Curve25519.KeyAgreement.PublicKey? {
        entries[userId]?.publicKey
    }

    var pinnedIds: [String] { entries.filter { $0.value.publicKey != nil }.map(\.key).sorted() }
    var unreadableIds: [String] { entries.filter { $0.value.publicKey == nil }.map(\.key).sorted() }
}
