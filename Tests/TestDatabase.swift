import CryptoKit
import Foundation
import SQLite3

/// Builds a small database shaped like the app's for `inspect` tests: the
/// synced tables with upload triggers, the local-only plaintext tables
/// without, and rows taken from the vectors.
final class TestDatabase {
    let path: String
    private var handle: OpaquePointer?

    init(name: String = UUID().uuidString) throws {
        path = NSTemporaryDirectory() + "veri-popt-test-\(name).sqlite"
        try? FileManager.default.removeItem(atPath: path)
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK, let db else {
            fatalError("cannot create test database")
        }
        handle = db
        // PowerSync's extension provides these in the app; the fixture's
        // triggers reference them, and SQLite re-prepares trigger bodies on
        // ALTER TABLE, so they must resolve here too.
        sqlite3_create_function(db, "powersync_in_sync_operation", 0, SQLITE_UTF8, nil, { context, _, _ in
            sqlite3_result_int(context, 0)
        }, nil, nil)
        exec("CREATE TABLE powersync_crud (op TEXT, id TEXT, type TEXT, data TEXT, old_values TEXT);")
    }

    deinit {
        if let handle { sqlite3_close(handle) }
        try? FileManager.default.removeItem(atPath: path)
    }

    func exec(_ sql: String) {
        var message: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(handle, sql, nil, nil, &message) == SQLITE_OK else {
            fatalError("test SQL failed: \(message.map { String(cString: $0) } ?? "?")\n\(sql)")
        }
    }

    func close() {
        if let handle { sqlite3_close(handle) }
        handle = nil
    }

    /// The app's schema, reduced to what `inspect` reads. Upload triggers
    /// fire on UPDATE only so fixture inserts do not queue uploads.
    func createSchema() {
        exec("""
        CREATE TABLE blocks (
            id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, revision INTEGER NOT NULL,
            device_id TEXT NOT NULL, owner_id TEXT NOT NULL, root_id TEXT NOT NULL, audience_id TEXT,
            payload TEXT NOT NULL, storage INTEGER NOT NULL DEFAULT 0, storage_updated_at INTEGER,
            project_id TEXT, storage_key TEXT
        );
        CREATE TABLE keys (id TEXT PRIMARY KEY, audience_id TEXT NOT NULL, owner_id TEXT NOT NULL, peer_id TEXT NOT NULL,
            wrapped_dek TEXT NOT NULL, UNIQUE (audience_id, peer_id));
        CREATE TABLE user_profiles (id TEXT PRIMARY KEY, public_key TEXT NOT NULL, profile_info TEXT,
            created_at INTEGER NOT NULL, updated_at INTEGER);
        CREATE TABLE plain_blocks (id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0, owner_id TEXT NOT NULL,
            root_id TEXT NOT NULL, audience_id TEXT, parent_block_id TEXT, parent_updated_at INTEGER,
            storage INTEGER NOT NULL DEFAULT 0, storage_updated_at INTEGER, block_type INTEGER NOT NULL,
            ui_group INTEGER, ui_group_updated_at INTEGER, payload TEXT NOT NULL, audience_ledger TEXT, storage_key TEXT);
        CREATE VIRTUAL TABLE plain_blocks_fts USING fts5(title, body);
        CREATE TABLE content_previews (block_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE local_info (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE ps_crud (id INTEGER PRIMARY KEY AUTOINCREMENT, tx_id INTEGER, data TEXT);
        CREATE TABLE ps_oplog (bucket INTEGER, op_id INTEGER, row_type TEXT, row_id TEXT, data TEXT);
        CREATE TRIGGER "blocks_UPDATE" AFTER UPDATE ON "blocks" FOR EACH ROW WHEN NOT powersync_in_sync_operation()
            BEGIN INSERT INTO powersync_crud(op,id,type,data) VALUES ('PATCH', NEW.id, 'blocks', '{}'); END;
        CREATE TRIGGER "keys_UPDATE" AFTER UPDATE ON "keys" FOR EACH ROW WHEN NOT powersync_in_sync_operation()
            BEGIN INSERT INTO powersync_crud(op,id,type,data) VALUES ('PATCH', NEW.id, 'keys', '{}'); END;
        CREATE TRIGGER profiles_upload AFTER UPDATE ON user_profiles BEGIN INSERT INTO ps_crud(tx_id, data) VALUES (0, '{}'); END;
        """)
    }

    /// Alice's account as the vectors describe it: two personal blocks, one
    /// shared with Bob, the audience's owner and peer rows, both profiles.
    func seedFromVectors() {
        let blocks = Vectors.object("blocks")
        let personal = Vectors.object("blocks", "personal")
        let shared = Vectors.object("blocks", "shared")
        let attachment = Vectors.object("blocks", "attachment")
        let rows = Vectors.object("keysRows")
        let aid = Vectors.string(shared, "audienceId")
        let alicePub = Vectors.string(Vectors.object("vaults", "alice", "expected"), "curvePublic")
        let bobPub = Vectors.string(Vectors.object("vaults", "bob", "expected"), "curvePublic")
        _ = blocks
        try! insertMirroredBlock(id: "block-personal", owner: "alice-uid", audience: nil,
                                 payload: Vectors.string(personal, "payload"), key: Vectors.key(personal, "key"))
        try! insertMirroredBlock(id: "block-shared", owner: "alice-uid", audience: aid,
                                 payload: Vectors.string(shared, "payload"), key: Vectors.key(shared, "key"))
        try! insertMirroredBlock(id: "block-attachment", owner: "alice-uid", audience: nil,
                                 payload: Vectors.string(attachment, "payload"), key: Vectors.key(attachment, "key"),
                                 storageKey: Vectors.string(attachment, "storageKey"), storage: BlocksReport.attachmentStorageBit)
        exec("""
        INSERT INTO keys VALUES ('k1', '\(aid)', 'alice-uid', 'alice-uid', '\(Vectors.string(Vectors.object("keysRows", "ownerRow"), "wrapped_dek"))');
        INSERT INTO keys VALUES ('k2', '\(aid)', 'alice-uid', 'bob-uid', '\(Vectors.string(Vectors.object("keysRows", "peerRow"), "wrapped_dek"))');
        INSERT INTO user_profiles VALUES ('alice-uid', '\(alicePub)', NULL, 1, NULL);
        INSERT INTO user_profiles VALUES ('bob-uid', '\(bobPub)', NULL, 1, NULL);
        INSERT INTO local_info VALUES ('user_id', 'alice-uid');
        INSERT INTO ps_oplog VALUES (1, 1, 'blocks', 'x', '{}');
        """)
        _ = rows
        // Each account pins itself and the other (docs/key-pins.md).
        let aliceKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(base64Encoded: alicePub)!)
        let bobKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(base64Encoded: bobPub)!)
        try! writeKeyPins(owner: "alice-uid", masterDEK: Vectors.key(Vectors.object("vaults", "alice", "expected"), "masterDEK"),
                          entries: ["alice-uid": aliceKey, "bob-uid": bobKey])
        try! writeKeyPins(owner: "bob-uid", masterDEK: Vectors.key(Vectors.object("vaults", "bob", "expected"), "masterDEK"),
                          entries: ["bob-uid": bobKey, "alice-uid": aliceKey])
    }

    /// Writes (or rewrites) `owner`'s key-pins block: a synced dictionary
    /// at the derived id, sealed under the owner's personal key, with its
    /// mirror.
    func writeKeyPins(owner: String, masterDEK: SymmetricKey, entries: [String: Curve25519.KeyAgreement.PublicKey],
                      unfriended: Set<String> = []) throws {
        let id = KeyPins.blockId(ownerId: owner)
        exec("DELETE FROM blocks WHERE id = '\(id)'; DELETE FROM plain_blocks WHERE id = '\(id)';")
        var dictionary: [String: Any] = [:]
        for (userId, key) in entries {
            var value: [String: Any] = [KeyPins.keyField: key.rawRepresentation.base64EncodedString()]
            if unfriended.contains(userId) { value[KeyPins.unfriendedField] = true }
            dictionary[userId] = ["value": value, "updatedAt": 1]
        }
        let block: [String: Any] = ["payload": ["type": KeyPins.blockTypeTag,
                                                "value": ["type": KeyPins.type, "scope": KeyPins.scope, "entries": dictionary]]]
        let plaintext = try JSONSerialization.data(withJSONObject: block)
        let personal = Derivation.subkeys(masterDEK: masterDEK).personalBlocksKey
        try insertMirroredBlock(id: id, owner: owner, audience: nil, payload: try Envelope(sealing: plaintext, with: personal).json(), key: personal)
    }

    /// Three more audiences for the `keys` tests, wrapped with the tool's
    /// own primitives (the format itself is pinned by the vectors):
    /// - `aid-bob`, owned by Bob with Alice as member, one block;
    /// - `aid-retired`, owned by Alice, her owner row only, no blocks;
    /// - `aid-bad`, owned by Alice: a tampered row for Carol (who has a
    ///   profile) and a sound row for Dave (who has none), one block.
    func seedMoreAudiences() throws {
        let alice = Vectors.object("vaults", "alice", "expected")
        let bob = Vectors.object("vaults", "bob", "expected")
        let aliceTree = Derivation.subkeys(masterDEK: Vectors.key(alice, "masterDEK"))
        let bobTree = Derivation.subkeys(masterDEK: Vectors.key(bob, "masterDEK"))
        let alicePriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Vectors.hex(alice, "curvePrivate"))
        let bobPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Vectors.hex(bob, "curvePrivate"))
        let plaintext = Data("{\"payload\":{\"type\":3,\"value\":{}}}".utf8)

        let bobDEK = bobTree.audienceMintKey("aid-bob")
        exec("""
        INSERT INTO keys VALUES ('kb1', 'aid-bob', 'bob-uid', 'bob-uid', '\(try AudienceKeys.wrapOwner(bobDEK, ownerWrapKey: bobTree.ownerWrapKey))');
        INSERT INTO keys VALUES ('kb2', 'aid-bob', 'bob-uid', 'alice-uid', '\(try AudienceKeys.wrapPeer(bobDEK, ownerPrivateKey: bobPriv, recipientPublicKey: alicePriv.publicKey, ownerId: "bob-uid"))');
        """)
        try insertMirroredBlock(id: "block-bob", owner: "bob-uid", audience: "aid-bob",
                                payload: try Envelope(sealing: plaintext, with: bobDEK).json(), key: bobDEK)

        let retiredDEK = aliceTree.audienceMintKey("aid-retired")
        exec("INSERT INTO keys VALUES ('kr1', 'aid-retired', 'alice-uid', 'alice-uid', '\(try AudienceKeys.wrapOwner(retiredDEK, ownerWrapKey: aliceTree.ownerWrapKey))');")

        let badDEK = aliceTree.audienceMintKey("aid-bad")
        let carol = Curve25519.KeyAgreement.PrivateKey(), dave = Curve25519.KeyAgreement.PrivateKey()
        // Alice pins Carol (whose row is tampered) but not Dave.
        let bobPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Vectors.base64(bob, "curvePublic"))
        try writeKeyPins(owner: "alice-uid", masterDEK: Vectors.key(alice, "masterDEK"),
                         entries: ["alice-uid": alicePriv.publicKey, "bob-uid": bobPublic, "carol-uid": carol.publicKey])
        let carolRow = try Envelope(json: try AudienceKeys.wrapPeer(badDEK, ownerPrivateKey: alicePriv, recipientPublicKey: carol.publicKey, ownerId: "alice-uid"))
        let tampered = try Envelope(nonce: carolRow.nonce, ciphertext: flipped(carolRow.ciphertext, at: 0), tag: carolRow.tag).json(extra: ["peer": "alice-uid"])
        exec("""
        INSERT INTO keys VALUES ('kx1', 'aid-bad', 'alice-uid', 'alice-uid', '\(try AudienceKeys.wrapOwner(badDEK, ownerWrapKey: aliceTree.ownerWrapKey))');
        INSERT INTO keys VALUES ('kx2', 'aid-bad', 'alice-uid', 'carol-uid', '\(tampered)');
        INSERT INTO keys VALUES ('kx3', 'aid-bad', 'alice-uid', 'dave-uid', '\(try AudienceKeys.wrapPeer(badDEK, ownerPrivateKey: alicePriv, recipientPublicKey: dave.publicKey, ownerId: "alice-uid"))');
        INSERT INTO user_profiles VALUES ('carol-uid', '\(carol.publicKey.rawRepresentation.base64EncodedString())', NULL, 1, NULL);
        """)
        try insertMirroredBlock(id: "block-bad", owner: "alice-uid", audience: "aid-bad",
                                payload: try Envelope(sealing: plaintext, with: badDEK).json(), key: badDEK)
    }

    /// The mirror states `blocks` must tell apart: a mirror behind the
    /// block's revision, a block with no mirror, a deep-link seed, an orphan
    /// mirror, a tampered payload, a mirror the app would never have
    /// written, and a row still under the share-extension sentinel.
    func seedBlockCases() throws {
        let alice = Vectors.object("vaults", "alice", "expected")
        let tree = Derivation.subkeys(masterDEK: Vectors.key(alice, "masterDEK"))
        let plaintext = Data("{\"payload\":{\"type\":3,\"value\":{\"text\":\"x\"}}}".utf8)
        let personal = tree.personalBlocksKey

        try insertMirroredBlock(id: "case-stale", owner: "alice-uid", audience: nil,
                                payload: try Envelope(sealing: plaintext, with: personal).json(), key: personal, revision: 2, mirrorRevision: 1)
        insertBlock(id: "case-nomirror", owner: "alice-uid", audience: nil, payload: try Envelope(sealing: plaintext, with: personal).json())
        exec("""
        INSERT INTO plain_blocks (id, revision, owner_id, root_id, block_type, payload) VALUES ('case-seed', -1, 'alice-uid', 'case-seed', 3, '{}');
        INSERT INTO plain_blocks (id, revision, owner_id, root_id, block_type, payload) VALUES ('case-orphan', 1, 'alice-uid', 'case-orphan', 3, '{}');
        """)
        let sealed = try Envelope(sealing: plaintext, with: personal)
        let tampered = try Envelope(nonce: sealed.nonce, ciphertext: flipped(sealed.ciphertext, at: 0), tag: sealed.tag).json()
        try insertMirroredBlock(id: "case-tampered", owner: "alice-uid", audience: nil, payload: try sealed.json(), key: personal)
        exec("UPDATE blocks SET payload = '\(tampered.replacingOccurrences(of: "'", with: "''"))' WHERE id = 'case-tampered';")
        try insertMirroredBlock(id: "case-edited", owner: "alice-uid", audience: nil,
                                payload: try Envelope(sealing: plaintext, with: personal).json(), key: personal)
        exec("UPDATE plain_blocks SET payload = '{\"text\":\"edited\"}' WHERE id = 'case-edited';")
        insertBlock(id: "case-sentinel", owner: "alice-uid", audience: BlocksReport.sentinelAudience,
                    payload: try Envelope(sealing: plaintext, with: tree.shareExtensionKey).json())
    }

    /// Inserts a block and the mirror row the app would write for it,
    /// decrypted with `key` (`PlainBlocksRow.fromSyncedBlock`'s columns).
    /// The vault vectors as Alice's blocks: the secret config block at its
    /// derived id and one wrapper, both personal rows with real mirrors.
    func seedVault() throws {
        let vault = Vectors.object("vault")
        let personal = Vectors.key(Vectors.object("blocks", "personal"), "key")
        try insertMirroredBlock(id: Vectors.string(vault, "configBlockId"), owner: "alice-uid", audience: nil,
                                payload: Vectors.string(vault, "configPayload"), key: personal)
        let wrapper = Vectors.object("vault", "wrapper")
        try insertMirroredBlock(id: Vectors.string(wrapper, "id"), owner: "alice-uid", audience: nil,
                                payload: Vectors.string(wrapper, "payload"), key: personal)
    }

    func insertMirroredBlock(
        id: String, owner: String, audience: String?, payload: String, key: SymmetricKey,
        revision: Int64 = 1, mirrorRevision: Int64? = nil, storageKey: String? = nil, storage: Int64 = 0
    ) throws {
        insertBlock(id: id, owner: owner, audience: audience, payload: payload, storageKey: storageKey, revision: revision, storage: storage)
        let block = try BlockCrypto.open(payload: payload, with: key)
        insertMirror(id: id, owner: owner, audience: audience, revision: mirrorRevision ?? revision, storageKey: storageKey, storage: storage, block: block)
    }

    /// A mirror row alone, the shape `PlainBlocksRow.fromSyncedBlock` writes.
    func insertMirror(id: String, owner: String, audience: String?, revision: Int64, storageKey: String? = nil, storage: Int64 = 0, block: DecryptedBlock) {
        func sql(_ value: Any?) -> String {
            switch value {
            case nil: return "NULL"
            case let n as Int64: return String(n)
            case let n as Int: return String(n)
            case let s as String: return "'" + s.replacingOccurrences(of: "'", with: "''") + "'"
            default: return "'" + String(decoding: try! JSONSerialization.data(withJSONObject: value!), as: UTF8.self).replacingOccurrences(of: "'", with: "''") + "'"
            }
        }
        exec("""
        INSERT INTO plain_blocks (id, revision, owner_id, root_id, audience_id, parent_block_id, parent_updated_at,
            storage, storage_updated_at, block_type, ui_group, ui_group_updated_at, payload, audience_ledger, storage_key)
        VALUES (\(sql(id)), \(revision), \(sql(owner)), \(sql(id)), \(sql(audience)), \(sql(block.parentBlockId)),
            \(sql(block.parentUpdatedAt)), \(storage), NULL, \(block.type), \(sql(block.uiGroup)), \(sql(block.uiGroupUpdatedAt)),
            \(sql(block.value)), \(sql(block.audienceLedger)), \(sql(storageKey)));
        """)
    }

    func insertBlock(id: String, owner: String, audience: String?, payload: String, storageKey: String? = nil, revision: Int64 = 1, storage: Int64 = 0) {
        let audienceSQL = audience.map { "'\($0)'" } ?? "NULL"
        let keySQL = storageKey.map { "'\($0)'" } ?? "NULL"
        exec("""
        INSERT INTO blocks (id, created_at, updated_at, revision, device_id, owner_id, root_id, audience_id, payload, storage, storage_key)
        VALUES ('\(id)', 1, 1, \(revision), 'dev', '\(owner)', '\(id)', \(audienceSQL), '\(payload.replacingOccurrences(of: "'", with: "''"))', \(storage), \(keySQL));
        """)
    }

    func queueUpload(op: String, table: String, id: String, data: [String: Any]) {
        let entry: [String: Any] = ["op": op, "type": table, "id": id, "data": data]
        let json = String(decoding: try! JSONSerialization.data(withJSONObject: entry), as: UTF8.self)
        exec("INSERT INTO ps_crud (tx_id, data) VALUES (1, '\(json.replacingOccurrences(of: "'", with: "''"))');")
    }
}
