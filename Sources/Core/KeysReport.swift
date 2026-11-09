import CryptoKit
import Foundation

/// `keys`: every audience and every `keys` row, the exhaustive form of
/// what `derive` samples (SPEC § 6.3). One section per audience, then a
/// summary.
enum KeysReport {

    enum Error: Swift.Error, CustomStringConvertible {
        case noDatabase
        var description: String { "keys needs the database copy in the folder" }
    }

    struct Totals {
        var audiences = 0, readable = 0, owned = 0, memberOf = 0
        var rowsForAccount = 0, rowsByAccount = 0, rowsByAccountOpened = 0
    }

    static func run(session: Session) throws -> Report {
        guard let db = session.db else { throw Error.noDatabase }
        var report = Report(title: "veri-popt keys")
        let me = session.userId
        var totals = Totals()

        let withBlocks = try db.query("SELECT DISTINCT audience_id FROM blocks WHERE audience_id IS NOT NULL").compactMap { $0.string("audience_id") }
        let withRows = try db.query("SELECT DISTINCT audience_id FROM keys").compactMap { $0.string("audience_id") }
        let audiences = Array(Set(withBlocks).union(withRows)).sorted()

        for audience in audiences {
            totals.audiences += 1
            let rows = try db.query(
                "SELECT owner_id, peer_id, wrapped_dek FROM keys WHERE audience_id = ? ORDER BY peer_id", [.text(audience)]
            )
            let blocks = try db.count("blocks", where: "audience_id = '\(audience)'")
            let owner = try session.audienceOwner(audience)
            let members = rows.compactMap { $0.string("peer_id") }
            let resolved = try session.audienceKey(audience)
            let owned = owner == me
            if owned { totals.owned += 1 }
            if members.contains(me), !owned { totals.memberOf += 1 }
            if members.contains(me) { totals.rowsForAccount += 1 }

            try report.section("Audience \(audience)") { s in
                let others = members.filter { $0 != me }
                s.line("owner: \(owner.map { $0 == me ? "the account" : $0 } ?? "unknown"); blocks: \(blocks); rows held: \(members.contains(me) ? "the account's" : "none for the account")\(others.isEmpty ? "" : ", plus rows for " + others.joined(separator: ", "))")
                s.line("account's key: \(resolved.resolution.description)")
                if let key = resolved.key {
                    totals.readable += 1
                    s.line("DEK fingerprint: \(Fingerprint.of(key))")
                    if blocks > 0 {
                        s.ok("the account can read this audience's \(blocks) block(s)")
                    } else {
                        s.note("no blocks under this audience; its rows outlive the content (keys are never deleted)")
                    }
                    if owned {
                        if key.bytes == session.subkeys.audienceMintKey(audience).bytes {
                            s.ok("the stored DEK equals audienceMintKey: the mint rule holds")
                        } else {
                            s.warning("the stored DEK differs from audienceMintKey: not minted by the deterministic rule (SPEC § 6.3)")
                        }
                    }
                } else if blocks > 0 {
                    s.fail("the account cannot obtain this audience's DEK, yet holds \(blocks) block(s) under it")
                } else {
                    s.warning("the account cannot obtain this audience's DEK (no blocks under it)")
                }

                // The owner's side: every row the account wrapped for a member.
                guard owned, let ownKey = resolved.key else { return }
                for row in rows {
                    guard let member = row.string("peer_id"), member != me, let wrapped = row.string("wrapped_dek") else { continue }
                    totals.rowsByAccount += 1
                    guard case .peer(let wrapper) = AudienceKeys.kind(of: wrapped), wrapper == me else {
                        s.fail("the row for \(member) is not a peer row wrapped by the account")
                        continue
                    }
                    guard let memberPublic = try session.pinnedPublicKey(of: member) else {
                        s.warning("the row for \(member) cannot be checked: \(member) is not pinned")
                        continue
                    }
                    do {
                        let dek = try AudienceKeys.unwrapPeer(wrapped, privateKey: session.keys.curvePrivate, ownerPublicKey: memberPublic)
                        if dek.bytes == ownKey.bytes {
                            totals.rowsByAccountOpened += 1
                            s.ok("the row the account wrapped for \(member) opens through ECDH with their published key and holds the same DEK")
                        } else {
                            s.fail("the row the account wrapped for \(member) opens but holds a different DEK")
                        }
                    } catch {
                        s.fail("the row the account wrapped for \(member) does not open through ECDH with their published key: \(error)")
                    }
                }
            }
        }

        try report.section("Summary") { s in
            switch try session.keyPins() {
            case .success(let pins):
                let peers = pins.entries.values.filter { $0.userId != me && $0.publicKey != nil }
                s.line("pinned peers: \(peers.count) (\(peers.filter(\.unfriended).count) unfriended); every ECDH above used the pinned key, never user_profiles")
            case .failure(let error):
                s.warning("\(error); no peer row could be opened")
            }
            s.line("audiences: \(totals.audiences) (\(totals.owned) owned, \(totals.memberOf) as a member, \(totals.audiences - totals.owned - totals.memberOf) neither)")
            s.line("readable by the account: \(totals.readable) of \(totals.audiences)")
            s.line("rows wrapped for the account by others: \(totals.rowsForAccount - totals.owned)")
            if totals.rowsByAccount > 0 {
                s.line("rows the account wrapped for members: \(totals.rowsByAccount), \(totals.rowsByAccountOpened) re-opened with the member's published key")
            } else {
                s.note("no rows the account wrapped for members are held locally. The sync stream serves each user only their own keys rows, so an owner keeps the rows it wrapped for members only until they upload; a synced copy never has them. Checking the member side of a share needs the server's rows (not covered)")
            }
            if totals.audiences == 0 { s.note("no audiences: nothing is shared with or by this account") }
        }
        return report
    }
}
