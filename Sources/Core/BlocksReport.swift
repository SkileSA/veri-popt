import CryptoKit
import Foundation

/// `blocks`: every `blocks` row opened under the rule in SPEC § 6.2 and
/// compared with the app's own decryption in `plain_blocks` (§ 6.4).
///
/// The app re-mirrors a row exactly when `blocks.revision` differs from the
/// mirror's (a missing mirror counts as 0; a mirror at -1 is a deep-link
/// seed awaiting its block). The comparison therefore runs only when the
/// two revisions are equal; otherwise the row is opened and counted as
/// pending.
enum BlocksReport {
    static let sentinelAudience = "share_ext"
    /// The plaintext `blocks.storage` bit that marks an attachment row
    /// (`storageAttachmentRef`, docs/attachments.md).
    static let attachmentStorageBit: Int64 = 8
    static let seedRevision: Int64 = -1
    static let maxListed = 15

    enum Error: Swift.Error, CustomStringConvertible {
        case noDatabase
        var description: String { "blocks needs the database copy in the folder" }
    }

    struct Tally {
        var rows = 0, opened = 0, compared = 0, matched = 0, pending = 0, failed = 0
    }

    static func run(session: Session, audience filter: String? = nil) throws -> Report {
        guard let db = session.db else { throw Error.noDatabase }
        var report = Report(title: "veri-popt blocks")
        var total = Tally()
        var perAudience: [String: Tally] = [:]
        var problems: [String] = []
        var attachments = 0, sentinels = 0, foreign = 0

        let rows = try db.query(
            """
            SELECT id, revision, audience_id, owner_id, root_id, storage, storage_updated_at, storage_key, payload
            FROM blocks \(filter == nil ? "" : "WHERE audience_id = ?") ORDER BY id
            """,
            filter.map { [.text($0)] } ?? []
        )

        for row in rows {
            let id = row.string("id") ?? "?"
            let audience = row.string("audience_id")
            let label = audience ?? "personal"
            // A personal row of another owner can never open here, and the
            // sync stream never serves one (SPEC § 6.1).
            if audience == nil, row.string("owner_id") != session.userId {
                foreign += 1
                continue
            }
            total.rows += 1
            perAudience[label, default: Tally()].rows += 1

            // The key (SPEC § 6.2).
            let key: SymmetricKey
            if audience == Self.sentinelAudience {
                key = session.subkeys.shareExtensionKey
            } else {
                let resolved = try session.blockKey(audienceId: audience)
                guard let k = resolved.key else {
                    total.failed += 1; perAudience[label, default: Tally()].failed += 1
                    problems.append("\(id): no key for audience \(label) (\(resolved.resolution.description))")
                    continue
                }
                key = k
            }

            // Open.
            let block: DecryptedBlock
            do {
                block = try BlockCrypto.open(payload: row.string("payload") ?? "", with: key)
            } catch {
                total.failed += 1; perAudience[label, default: Tally()].failed += 1
                problems.append("\(id): does not open under the \(audience == nil ? "personal key" : "audience key") (\(error))")
                continue
            }
            total.opened += 1; perAudience[label, default: Tally()].opened += 1
            if audience == Self.sentinelAudience { sentinels += 1 }

            // Attachment rows (the plaintext storage bit) carry their file key.
            if (row.int("storage") ?? 0) & Self.attachmentStorageBit != 0 {
                attachments += 1
                let ref = (block.value as? [String: Any])?["attachmentRef"] as? [String: Any]
                if let dek = ref?["fileDEK"] as? String, (try? FileBlob.dek(from: dek)) != nil {
                    if row.isNull("storage_key") {
                        total.failed += 1
                        problems.append("\(id): attachment row without a storage_key")
                    }
                } else {
                    total.failed += 1
                    problems.append("\(id): attachment row whose attachmentRef.fileDEK is not a 32-byte key")
                }
            }

            // Compare with the mirror, only at the same revision.
            guard let mirror = try db.query("SELECT * FROM plain_blocks WHERE id = ?", [.text(id)]).first,
                  mirror.int("revision") == row.int("revision")
            else {
                total.pending += 1; perAudience[label, default: Tally()].pending += 1
                continue
            }
            total.compared += 1; perAudience[label, default: Tally()].compared += 1
            let differences = Self.differences(block: block, blocksRow: row, mirror: mirror)
            if differences.isEmpty {
                total.matched += 1; perAudience[label, default: Tally()].matched += 1
            } else {
                total.failed += 1; perAudience[label, default: Tally()].failed += 1
                problems.append("\(id): mirror differs in \(differences.joined(separator: ", "))")
            }
        }

        // Mirror rows without a block.
        let unmatched = try db.query("SELECT pb.id, pb.revision FROM plain_blocks pb LEFT JOIN blocks b ON b.id = pb.id WHERE b.id IS NULL")
        let seeds = unmatched.filter { $0.int("revision") == Self.seedRevision }.count
        let orphans = unmatched.filter { $0.int("revision") != Self.seedRevision }.compactMap { $0.string("id") }

        report.section("Totals") { s in
            s.line("blocks rows: \(total.rows)\(filter.map { " (audience \($0))" } ?? ""); opened: \(total.opened); compared with the mirror: \(total.compared); matching: \(total.matched); pending (not yet mirrored at this revision): \(total.pending); failed: \(total.failed)")
            if total.rows == 0 {
                s.note("no block rows\(filter == nil ? "" : " under that audience")")
            } else if total.failed == 0 {
                s.ok("every block opened under the documented key, and every one the app had mirrored at this revision decrypts to what the app wrote")
            } else {
                s.fail("\(total.failed) row(s) failed; listed below")
            }
            if total.pending > 0 {
                s.note("\(total.pending) row(s) are at a revision the app has not mirrored yet; opened but not compared (SPEC § 6.4)")
            }
            if attachments > 0 { s.line("attachment rows: \(attachments), each carrying a 32-byte file key") }
            if sentinels > 0 {
                s.ok("shareExtensionKey opened \(sentinels) row(s) still under the share_ext sentinel")
            }
            if seeds > 0 { s.note("\(seeds) mirror row(s) at revision -1 are deep-link seeds awaiting their block") }
            if foreign > 0 {
                s.warning("\(foreign) personal row(s) belong to another account and were skipped; the sync stream never serves those, so this copy is not what the app would hold")
            }
            if !orphans.isEmpty {
                s.warning("\(orphans.count) mirror row(s) have no blocks row (the app's orphan sweep removes these): \(orphans.prefix(Self.maxListed).joined(separator: ", "))")
            }
        }
        report.section("By audience") { s in
            for (label, t) in perAudience.sorted(by: { $0.key < $1.key }) {
                s.line("\(label): \(t.rows) rows, \(t.opened) opened, \(t.matched) matching, \(t.pending) pending, \(t.failed) failed")
            }
        }
        if !problems.isEmpty {
            report.section("Problems") { s in
                for line in problems.prefix(Self.maxListed) { s.line(line) }
                if problems.count > Self.maxListed { s.line("… and \(problems.count - Self.maxListed) more") }
            }
        }
        return report
    }

    /// The mirror columns the app writes from a decrypted block
    /// (`PlainBlocksRow.fromSyncedBlock`), each compared to the tool's own
    /// decryption, plus the plaintext columns the mirror copies.
    static func differences(block: DecryptedBlock, blocksRow: Database.Row, mirror: Database.Row) -> [String] {
        var out: [String] = []
        let mirrorPayload = mirror.string("payload").flatMap { try? JSON.parse($0) }
        if !JSON.equal(block.value, mirrorPayload) { out.append("payload") }
        if Int64(block.type) != mirror.int("block_type") { out.append("block_type") }
        if block.parentBlockId != mirror.string("parent_block_id") { out.append("parent_block_id") }
        if block.parentUpdatedAt != mirror.int("parent_updated_at") { out.append("parent_updated_at") }
        if block.uiGroup.map(Int64.init) != mirror.int("ui_group") { out.append("ui_group") }
        if block.uiGroupUpdatedAt != mirror.int("ui_group_updated_at") { out.append("ui_group_updated_at") }
        let mirrorLedger = mirror.string("audience_ledger").flatMap { try? JSON.parse($0) }
        if !JSON.equal(block.audienceLedger, mirrorLedger) { out.append("audience_ledger") }
        for column in ["owner_id", "root_id", "audience_id", "storage_key"] where blocksRow.string(column) != mirror.string(column) {
            out.append(column)
        }
        for column in ["storage", "storage_updated_at"] where blocksRow.int(column) != mirror.int(column) {
            out.append(column)
        }
        return out
    }
}
