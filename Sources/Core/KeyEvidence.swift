import CryptoKit
import Foundation

/// `derive`'s evidence pass: for every derived key, one example from the
/// database that only that key can produce, or an explicit "not checked"
/// when the database holds no example. A key that merely matches a
/// fingerprint proves nothing about the app; a key that opens the app's
/// own data does.
enum KeyEvidence {

    static func run(session: Session, into report: inout Report) throws {
        guard let db = session.db else {
            report.section("Keys against the data") { s in
                s.note("skipped: no database given (--db). Each key was derived but not shown to open anything the app wrote")
            }
            return
        }
        try report.section("Key pins") { s in
            try keyPins(session, &s)
        }
        try report.section("Published key") { s in
            if let published = try session.publishedPublicKey(of: session.userId) {
                if published.rawRepresentation == session.keys.curvePublic {
                    s.ok("the derived Curve25519 public key is the one published in the account's user_profiles row")
                } else {
                    s.fail("the derived Curve25519 public key differs from the account's user_profiles row")
                }
            } else {
                s.warning("no user_profiles row for the account; the Curve25519 public key could not be checked against the database")
            }
        }
        try report.section("Keys against the data") { s in
            try personalBlocksKey(session, db, &s)
            try ownerWrapAndMint(session, db, &s)
            try curvePrivate(session, db, &s)
            s.note("signingKey: nothing in the database is signed; it only signs vault-rotation requests to the server. Proven against the record's public half only")
            s.note("shareExtensionKey: not checked. Blocks written by the Share Extension are promoted to the personal key as soon as the app runs, so a copy never holds one; this needs its own flow")
            s.line("masterDEK and sharedRootKey are never used as cipher keys; they are proven through the keys derived from them")
        }
    }

    // MARK: - The pins block (SPEC § 6.5)

    private static func keyPins(_ session: Session, _ s: inout Report.Section) throws {
        let pins: KeyPins
        switch try session.keyPins() {
        case .failure(let error):
            s.warning("\(error); every peer is unpinned, so no ECDH row can be opened")
            return
        case .success(let loaded):
            pins = loaded
        }
        s.ok("the key pins block opens under personalBlocksKey and echoes its tenant \(KeyPins.type)/\(KeyPins.scope)")
        if let own = pins.publicKey(for: session.userId) {
            if own.rawRepresentation == session.keys.curvePublic {
                s.ok("the self entry holds the derived Curve25519 public key")
            } else {
                s.fail("the self entry holds a different key than the derived Curve25519 public key")
            }
        } else {
            s.warning("the pins block has no readable self entry")
        }
        let peers = pins.pinnedIds.filter { $0 != session.userId }
        var agree = 0, missing: [String] = [], diverge: [String] = []
        for peer in peers {
            guard let pinned = pins.publicKey(for: peer) else { continue }
            guard let published = try session.publishedPublicKey(of: peer) else { missing.append(peer); continue }
            if published.rawRepresentation == pinned.rawRepresentation { agree += 1 } else { diverge.append(peer) }
        }
        s.line("pinned peers: \(peers.count)\(pins.unreadableIds.isEmpty ? "" : "; unreadable entries: \(pins.unreadableIds.count)")")
        if agree > 0 { s.ok("\(agree) pinned peer key(s) agree with the key the server publishes in user_profiles") }
        if !missing.isEmpty { s.note("\(missing.count) pinned peer(s) have no user_profiles row to compare with") }
        for peer in diverge {
            s.fail("the server publishes a different key for \(peer) (\(Fingerprint.of(try session.publishedPublicKey(of: peer)!.rawRepresentation))) than the one pinned (\(Fingerprint.of(pins.publicKey(for: peer)!.rawRepresentation))); the pin is what the app uses")
        }
    }

    // MARK: - personalBlocksKey

    private static func personalBlocksKey(_ session: Session, _ db: Database, _ s: inout Report.Section) throws {
        guard let row = try db.query("SELECT id, payload FROM blocks WHERE audience_id IS NULL AND owner_id = ? LIMIT 1", [.text(session.userId)]).first,
              let id = row.string("id"), let payload = row.string("payload")
        else {
            s.note("personalBlocksKey: not checked, the database has no personal block")
            return
        }
        do {
            let block = try BlockCrypto.open(payload: payload, with: session.subkeys.personalBlocksKey)
            s.ok("personalBlocksKey opens personal block \(short(id)) (type \(block.type))")
        } catch {
            s.fail("personalBlocksKey does not open personal block \(short(id)): \(error)")
        }
    }

    // MARK: - ownerWrapKey + audienceMintKey

    private static func ownerWrapAndMint(_ session: Session, _ db: Database, _ s: inout Report.Section) throws {
        let ownRows = try db.query(
            "SELECT audience_id, wrapped_dek FROM keys WHERE peer_id = ? AND owner_id = ?",
            [.text(session.userId), .text(session.userId)]
        ).filter { AudienceKeys.kind(of: $0.string("wrapped_dek") ?? "") == .owner }

        if let row = ownRows.first, let audience = row.string("audience_id"), let wrapped = row.string("wrapped_dek") {
            let dek: SymmetricKey
            do {
                dek = try AudienceKeys.unwrapOwner(wrapped, ownerWrapKey: session.subkeys.ownerWrapKey)
            } catch {
                s.fail("ownerWrapKey does not open the account's owner row for audience \(short(audience)): \(error)")
                return
            }
            if let (id, type) = try openOneBlock(db, audience: audience, key: dek) {
                s.ok("ownerWrapKey opens the owner row of audience \(short(audience)), and that DEK opens its block \(short(id)) (type \(type))")
            } else {
                s.ok("ownerWrapKey opens the owner row of audience \(short(audience)); the audience has no block to open with it")
            }
            if dek.bytes == session.subkeys.audienceMintKey(audience).bytes {
                s.ok("audienceMintKey(\(short(audience))) equals that audience's DEK: the mint rule holds")
            } else {
                s.warning("audienceMintKey(\(short(audience))) differs from the stored DEK: that audience was not minted by the deterministic rule (SPEC § 6.3)")
            }
            return
        }

        // No owner row at all: an owned audience with blocks and no row
        // exercises the mint directly.
        let owned = try db.query(
            "SELECT DISTINCT audience_id FROM blocks WHERE owner_id = ? AND audience_id IS NOT NULL",
            [.text(session.userId)]
        ).compactMap { $0.string("audience_id") }
        s.note("ownerWrapKey: not checked, the account holds no owner-wrapped keys row")
        for audience in owned {
            let hasRow = try db.count("keys", where: "audience_id = '\(audience)' AND peer_id = '\(session.userId)'") > 0
            if hasRow { continue }
            if let (id, type) = try openOneBlock(db, audience: audience, key: session.subkeys.audienceMintKey(audience)) {
                s.ok("audienceMintKey(\(short(audience))) opens block \(short(id)) (type \(type)) of an owned audience that has no keys row")
            } else {
                s.fail("audienceMintKey(\(short(audience))) does not open the blocks of an owned audience that has no keys row")
            }
            return
        }
        s.note("audienceMintKey: not checked, the account owns no audience with blocks")
    }

    // MARK: - Curve25519 private key

    private static func curvePrivate(_ session: Session, _ db: Database, _ s: inout Report.Section) throws {
        // A row another owner wrapped for the account.
        let forMe = try db.query("SELECT audience_id, owner_id, wrapped_dek FROM keys WHERE peer_id = ? AND owner_id != ?",
                                 [.text(session.userId), .text(session.userId)])
        if let row = forMe.first, let audience = row.string("audience_id"), let owner = row.string("owner_id") {
            let resolved = try session.audienceKey(audience)
            if let key = resolved.key, case .peerRow = resolved.resolution {
                if let (id, type) = try openOneBlock(db, audience: audience, key: key) {
                    s.ok("the Curve25519 key opens the row \(short(owner)) wrapped for the account (audience \(short(audience))), and that DEK opens block \(short(id)) (type \(type))")
                } else {
                    s.ok("the Curve25519 key opens the row \(short(owner)) wrapped for the account (audience \(short(audience))); no block of that audience to open")
                }
            } else {
                s.fail("the Curve25519 key does not open the row \(short(owner)) wrapped for the account: \(resolved.resolution.description)")
            }
        } else {
            s.note("Curve25519 key as recipient: not checked, no other owner has wrapped a row for the account")
        }

        // A row the account wrapped for a member.
        let forOthers = try db.query("SELECT audience_id, peer_id, wrapped_dek FROM keys WHERE owner_id = ? AND peer_id != ?",
                                     [.text(session.userId), .text(session.userId)])
        guard let row = forOthers.first, let audience = row.string("audience_id"), let member = row.string("peer_id"),
              let wrapped = row.string("wrapped_dek")
        else {
            s.note("Curve25519 key as owner: not checked, the account has wrapped no row for a member")
            return
        }
        guard let memberPublic = try session.pinnedPublicKey(of: member) else {
            s.warning("Curve25519 key as owner: member \(short(member)) is not pinned, so the row the account wrapped for them cannot be checked")
            return
        }
        do {
            let dek = try AudienceKeys.unwrapPeer(wrapped, privateKey: session.keys.curvePrivate, ownerPublicKey: memberPublic)
            let own = try session.audienceKey(audience)
            if let ownKey = own.key, ownKey.bytes == dek.bytes {
                s.ok("the Curve25519 key re-opens the row the account wrapped for \(short(member)) (audience \(short(audience))), and it holds the same DEK as the account's own row")
            } else {
                s.ok("the Curve25519 key re-opens the row the account wrapped for \(short(member)) (audience \(short(audience)))")
            }
        } catch {
            s.fail("the Curve25519 key does not re-open the row the account wrapped for \(short(member)): \(error)")
        }
    }

    // MARK: - Helpers

    private static func openOneBlock(_ db: Database, audience: String, key: SymmetricKey) throws -> (String, Int)? {
        guard let row = try db.query("SELECT id, payload FROM blocks WHERE audience_id = ? LIMIT 1", [.text(audience)]).first,
              let id = row.string("id"), let payload = row.string("payload")
        else { return nil }
        let block = try BlockCrypto.open(payload: payload, with: key)
        return (id, block.type)
    }

    static func short(_ id: String) -> String {
        id.count > 12 ? String(id.prefix(8)) + "…" : id
    }
}
