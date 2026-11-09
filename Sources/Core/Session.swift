import CryptoKit
import Foundation

/// Everything the secret-taking commands share: the record and code turned
/// into keys, the subkey tree, and, with a database, the audience keys
/// resolved on demand by the rule in SPEC § 6.2 and § 6.3.
final class Session {
    let record: VaultRecord
    let code: RecoveryCode
    let keys: VaultKeys
    let subkeys: SubkeyTree
    let db: Database?

    /// The account: the record's id. The database may name another account
    /// (`local_info`), which the evidence pass reports.
    var userId: String { record.id }

    /// How an audience key was obtained.
    enum Resolution: Equatable {
        /// The account's own owner-wrapped row.
        case ownerRow
        /// A row the audience owner wrapped for the account, opened through
        /// ECDH with the owner's published key.
        case peerRow(ownerId: String)
        /// No row, the account owns the audience: the deterministic mint.
        case mint
        /// No way in; the message says why.
        case unavailable(String)

        var description: String {
            switch self {
            case .ownerRow: "own owner row under ownerWrapKey"
            case .peerRow(let owner): "peer row wrapped by \(owner), opened through ECDH"
            case .mint: "no row; owned, so the mint rule"
            case .unavailable(let why): "unavailable: \(why)"
            }
        }
    }

    struct Resolved {
        let key: SymmetricKey?
        let resolution: Resolution
    }

    private var cache: [String: Resolved] = [:]
    private var pinsCache: Result<KeyPins, KeyPins.Error>?

    init(record: VaultRecord, code: RecoveryCode, db: Database? = nil) throws {
        self.record = record
        self.code = code
        self.keys = try Derivation.unwrap(record: record, code: code)
        self.subkeys = keys.subkeys
        self.db = db
    }

    // MARK: - Audience keys

    /// The key that opens `audienceId`'s rows for this account, with how it
    /// was obtained. Cached. Requires a database.
    func audienceKey(_ audienceId: String) throws -> Resolved {
        if let cached = cache[audienceId] { return cached }
        let resolved = try resolve(audienceId)
        cache[audienceId] = resolved
        return resolved
    }

    /// The key for a block row: the personal key with no audience, else the
    /// audience's (SPEC § 6.2).
    func blockKey(audienceId: String?) throws -> Resolved {
        guard let audienceId else { return Resolved(key: subkeys.personalBlocksKey, resolution: .ownerRow) }
        return try audienceKey(audienceId)
    }

    private func resolve(_ audienceId: String) throws -> Resolved {
        guard let db else { return Resolved(key: nil, resolution: .unavailable("no database")) }
        let mine = try db.query(
            "SELECT wrapped_dek, owner_id FROM keys WHERE audience_id = ? AND peer_id = ?",
            [.text(audienceId), .text(userId)]
        ).first
        if let mine, let wrapped = mine.string("wrapped_dek") {
            switch AudienceKeys.kind(of: wrapped) {
            case .owner:
                do {
                    return Resolved(key: try AudienceKeys.unwrapOwner(wrapped, ownerWrapKey: subkeys.ownerWrapKey), resolution: .ownerRow)
                } catch {
                    return Resolved(key: nil, resolution: .unavailable("own owner row does not open under ownerWrapKey: \(error)"))
                }
            case .peer(let ownerId):
                // The owner's key comes from the pins block, never from
                // user_profiles (SPEC § 6.5). Unpinned is refused, as the app
                // refuses; the published key is tried only to say what it
                // would have done.
                guard let ownerPublic = try pinnedPublicKey(of: ownerId) else {
                    let fallback: String
                    if let published = try publishedPublicKey(of: ownerId) {
                        let opens = (try? AudienceKeys.unwrapPeer(wrapped, privateKey: keys.curvePrivate, ownerPublicKey: published)) != nil
                        fallback = opens ? "the key published in user_profiles would open it" : "the key published in user_profiles would not open it either"
                    } else {
                        fallback = "no user_profiles row either"
                    }
                    return Resolved(key: nil, resolution: .unavailable("peer row wrapped by \(ownerId), who is not pinned; refused as the app refuses (\(fallback))"))
                }
                do {
                    let key = try AudienceKeys.unwrapPeer(wrapped, privateKey: keys.curvePrivate, ownerPublicKey: ownerPublic)
                    return Resolved(key: key, resolution: .peerRow(ownerId: ownerId))
                } catch {
                    return Resolved(key: nil, resolution: .unavailable("peer row wrapped by \(ownerId) does not open through ECDH: \(error)"))
                }
            }
        }
        let owner = try audienceOwner(audienceId)
        if owner == userId {
            return Resolved(key: subkeys.audienceMintKey(audienceId), resolution: .mint)
        }
        return Resolved(key: nil, resolution: .unavailable("no keys row for the account; owner is \(owner ?? "unknown")"))
    }

    /// Who owns an audience: from any keys row, else from any block in it.
    func audienceOwner(_ audienceId: String) throws -> String? {
        guard let db else { return nil }
        if let owner = try db.query("SELECT owner_id FROM keys WHERE audience_id = ? LIMIT 1", [.text(audienceId)]).first?.string("owner_id") {
            return owner
        }
        return try db.query("SELECT owner_id FROM blocks WHERE audience_id = ? LIMIT 1", [.text(audienceId)]).first?.string("owner_id")
    }

    // MARK: - Peer keys

    /// The account's pins block, loaded once (SPEC § 6.5).
    func keyPins() throws -> Result<KeyPins, KeyPins.Error> {
        if let pinsCache { return pinsCache }
        let result = try loadKeyPins()
        pinsCache = result
        return result
    }

    private func loadKeyPins() throws -> Result<KeyPins, KeyPins.Error> {
        guard let db else { return .failure(.notFound(id: KeyPins.blockId(ownerId: userId))) }
        let id = KeyPins.blockId(ownerId: userId)
        guard let row = try db.query("SELECT payload FROM blocks WHERE id = ? AND audience_id IS NULL", [.text(id)]).first,
              let payload = row.string("payload")
        else { return .failure(.notFound(id: id)) }
        let block: DecryptedBlock
        do {
            block = try BlockCrypto.open(payload: payload, with: subkeys.personalBlocksKey)
        } catch {
            return .failure(.cannotOpen("\(error)"))
        }
        do {
            return .success(try KeyPins(decrypted: block))
        } catch let error as KeyPins.Error {
            return .failure(error)
        }
    }

    /// The key pinned for `userId`: the one key for every ECDH. nil when
    /// there is no pins block, no entry, or an unreadable one.
    func pinnedPublicKey(of userId: String) throws -> Curve25519.KeyAgreement.PublicKey? {
        guard case .success(let pins) = try keyPins() else { return nil }
        return pins.publicKey(for: userId)
    }

    /// A user's published Curve25519 public key (`user_profiles.public_key`):
    /// what the server says, a cross-check only.
    func publishedPublicKey(of userId: String) throws -> Curve25519.KeyAgreement.PublicKey? {
        guard let db,
              let base64 = try db.query("SELECT public_key FROM user_profiles WHERE id = ?", [.text(userId)]).first?.string("public_key"),
              let bytes = Data(base64Encoded: base64)
        else { return nil }
        return try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: bytes)
    }
}
