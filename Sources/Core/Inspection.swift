import Foundation

/// `inspect`: what a copy of the database says without any secret
/// (SPEC § 6.1, § 6.3). Pure over `Database`, so tests run it on a
/// synthetic file.
struct Inspection {
    /// The plaintext columns of `blocks` the spec lists (§ 6.1), plus the
    /// one content column.
    static let expectedBlockColumns: [String] = [
        "id", "created_at", "updated_at", "revision", "device_id", "owner_id", "root_id",
        "audience_id", "payload", "storage", "storage_updated_at", "project_id", "storage_key",
    ]
    static let contentColumn = "payload"

    /// Columns an older install may still carry, retired from both schemas
    /// (the v1 conflict slots, Oct 2026). SQLite never drops a column, so
    /// they linger, always NULL, and the server has no such column.
    static let retiredLocalColumns: Set<String> = ["conflicts", "conflict_id"]

    /// Local-only tables that hold plaintext. None may carry an upload
    /// trigger. Prefix match, so FTS shadow tables are covered.
    static let localPlaintextTables: [String] = [
        "plain_blocks", "content_previews", "content_preview_dirty", "local_info",
        "sensitivity_cache", "push_notifs_queue", "spotlight_dirty", "op_gate",
    ]

    static let nonceLength = 12
    static let tagLength = 16
    static let maxListed = 10

    let db: Database
    /// The account to judge audiences against. From `local_info` unless
    /// overridden.
    let userId: String?

    init(db: Database, userOverride: String? = nil) throws {
        self.db = db
        self.userId = try userOverride ?? db.userId()
    }

    func run() throws -> Report {
        var report = Report(title: "veri-popt inspect")
        try file(&report)
        try schema(&report)
        guard try db.hasTable("blocks") else { return report }
        try payloads(&report)
        try uploadQueue(&report)
        try audiences(&report)
        try profiles(&report)
        try localOnly(&report)
        return report
    }

    // MARK: - Sections

    private func file(_ report: inout Report) throws {
        try report.section("File") { s in
            s.line("path: \(db.path)")
            s.line("size: \(db.fileSize) bytes")
            let sidecars = db.sidecarsPresent
            s.line("sidecars: \(sidecars.isEmpty ? "none" : sidecars.joined(separator: ", "))")
            if Database.looksLive(db.path) {
                s.warning("this path is inside the app's container: work on a copy, never the live file")
            }
            if sidecars.contains("-wal") {
                s.note("a write-ahead log came with the copy; it is read, nothing is written back")
            } else {
                s.note("no -wal file beside the copy. Fine if Popt had quit before the copy (the log is folded into the file on close); if a -wal existed and was not copied, recent edits are missing here")
            }
            if let userId {
                s.line("account: \(userId)")
            } else {
                s.warning("no account id in local_info; pass --user to judge audiences")
            }
        }
    }

    private func schema(_ report: inout Report) throws {
        try report.section("What leaves the device") { s in
            let uploaded = try db.uploadedTables().sorted()
            s.line("tables with an upload trigger: \(uploaded.isEmpty ? "none" : uploaded.joined(separator: ", "))")
            guard try db.hasTable("blocks") else {
                s.fail("no blocks table; this is not a Popt database")
                return
            }
            if uploaded.isEmpty {
                s.fail("no table has an upload trigger; either this is not a PowerSync database or the tool no longer recognizes the trigger shape, so the never-synced check below proves nothing")
            } else if !uploaded.contains("blocks") {
                s.fail("blocks has no upload trigger; the tool no longer recognizes PowerSync's trigger shape")
            }
            let columns = try db.columns(of: "blocks")
            s.line("blocks columns: \(columns.joined(separator: ", "))")
            let extra = columns.filter { !Self.expectedBlockColumns.contains($0) }
            let missing = Self.expectedBlockColumns.filter { !columns.contains($0) }
            if extra.isEmpty, missing.isEmpty {
                s.ok("blocks has exactly the columns SPEC § 6.1 lists; \(Self.contentColumn) is the only content column")
            }
            for column in extra {
                if Self.retiredLocalColumns.contains(column) {
                    let used = try db.count("blocks", where: "\(column) IS NOT NULL")
                    if used == 0 {
                        s.note("blocks still has the retired column \(column) (NULL on every row; older installs keep it, the server never had it)")
                    } else {
                        s.warning("blocks has the retired column \(column) with \(used) non-NULL value(s); it should be empty")
                    }
                } else {
                    s.warning("blocks has a column the spec does not list: \(column). If the server's table has it too, the spec needs updating")
                }
            }
            for column in missing {
                s.fail("blocks lacks the column \(column) the spec lists")
            }
            if try db.hasTable("ps_oplog") {
                let types = try db.query("SELECT DISTINCT row_type FROM ps_oplog ORDER BY row_type").compactMap { $0.string("row_type") }
                if !types.isEmpty { s.line("tables seen coming down from the server: \(types.joined(separator: ", "))") }
            }
        }
    }

    private func payloads(_ report: inout Report) throws {
        guard try db.hasTable("blocks") else { return }
        try report.section("Block payloads") { s in
            let rows = try db.query("SELECT id, audience_id, payload FROM blocks")
            var personal = 0, shared = 0, bytes = 0
            var bad: [String] = []
            for row in rows {
                if row.isNull("audience_id") { personal += 1 } else { shared += 1 }
                let payload = row.string("payload") ?? ""
                bytes += payload.utf8.count
                if let why = Self.envelopeProblem(payload) {
                    bad.append("\(row.string("id") ?? "?"): \(why)")
                }
            }
            s.line("rows: \(rows.count) (\(personal) personal, \(shared) shared), \(bytes) bytes of payload")
            if rows.isEmpty {
                s.note("no block rows to scan")
            } else if bad.isEmpty {
                s.ok("every payload is an AES-GCM envelope (12-byte nonce, 16-byte tag) and its ciphertext is not text")
            } else {
                s.fail("\(bad.count) payload(s) are not ciphertext envelopes")
                for line in bad.prefix(Self.maxListed) { s.line(line) }
                if bad.count > Self.maxListed { s.line("… and \(bad.count - Self.maxListed) more") }
            }
        }
    }

    private func uploadQueue(_ report: inout Report) throws {
        guard try db.hasTable("ps_crud") else { return }
        try report.section("Pending uploads") { s in
            let rows = try db.query("SELECT id, data FROM ps_crud ORDER BY id")
            s.line("queued operations: \(rows.count)")
            if rows.isEmpty {
                s.ok("the upload queue is empty")
                return
            }
            var byTable: [String: Int] = [:]
            var problems: [String] = []
            var plaintextPatches = 0
            for row in rows {
                let entry = CrudEntry(json: row.string("data") ?? "")
                byTable[entry.table, default: 0] += 1
                switch entry.table {
                case "blocks":
                    if let payload = entry.data["payload"] {
                        if let text = payload as? String {
                            if let why = Self.envelopeProblem(text) { problems.append("op \(row.int("id") ?? 0): payload \(why)") }
                        } else {
                            problems.append("op \(row.int("id") ?? 0): payload is not a string")
                        }
                    } else if entry.op != "DELETE" {
                        plaintextPatches += 1
                    }
                    let unexpected = entry.data.keys.filter { !Self.expectedBlockColumns.contains($0) }
                    for column in unexpected { problems.append("op \(row.int("id") ?? 0): writes a column the spec does not list: \(column)") }
                case "keys":
                    if let wrapped = entry.data["wrapped_dek"] as? String, let why = Self.envelopeProblem(wrapped) {
                        problems.append("op \(row.int("id") ?? 0): wrapped_dek \(why)")
                    }
                default:
                    break
                }
            }
            s.line("by table: " + byTable.keys.sorted().map { "\($0) \(byTable[$0]!)" }.joined(separator: ", "))
            if plaintextPatches > 0 {
                s.note("\(plaintextPatches) block patch(es) touch only plaintext columns (storage, project link, audience); expected")
            }
            if problems.isEmpty {
                s.ok("every queued block payload and audience key is an envelope")
            } else {
                s.fail("\(problems.count) queued operation(s) would upload something the spec does not allow")
                for line in problems.prefix(Self.maxListed) { s.line(line) }
            }
        }
    }

    private func audiences(_ report: inout Report) throws {
        guard try db.hasTable("blocks"), try db.hasTable("keys") else { return }
        try report.section("Audiences") { s in
            let blockCounts = Dictionary(uniqueKeysWithValues: try db.query(
                "SELECT audience_id, COUNT(*) AS n FROM blocks WHERE audience_id IS NOT NULL GROUP BY audience_id"
            ).compactMap { row -> (String, Int)? in
                guard let id = row.string("audience_id"), let n = row.int("n") else { return nil }
                return (id, Int(n))
            })
            let keyRows = try db.query("SELECT audience_id, owner_id, peer_id, wrapped_dek FROM keys")
            let rowsByAudience = Dictionary(grouping: keyRows, by: { $0.string("audience_id") ?? "" })
            s.line("audiences with blocks: \(blockCounts.count); keys rows: \(keyRows.count)")

            var badEnvelopes = 0
            var ownerRows = 0, peerRows = 0
            for row in keyRows {
                let wrapped = row.string("wrapped_dek") ?? ""
                if Self.envelopeProblem(wrapped) != nil { badEnvelopes += 1 }
                switch AudienceKeys.kind(of: wrapped) {
                case .owner: ownerRows += 1
                case .peer: peerRows += 1
                }
            }
            s.line("keys rows by kind: \(ownerRows) owner-wrapped, \(peerRows) peer-wrapped (ECDH)")
            if badEnvelopes == 0, !keyRows.isEmpty {
                s.ok("every wrapped_dek is an envelope")
            } else if badEnvelopes > 0 {
                s.fail("\(badEnvelopes) wrapped_dek value(s) are not envelopes")
            }

            var unreadable: [String] = []
            var ownerMint = 0
            for (audience, count) in blockCounts.sorted(by: { $0.key < $1.key }) {
                let rows = rowsByAudience[audience] ?? []
                let mine = rows.first { $0.string("peer_id") == userId }
                var owner = rows.first?.string("owner_id")
                if owner == nil {
                    owner = try db.query("SELECT owner_id FROM blocks WHERE audience_id = ? LIMIT 1", [.text(audience)])
                        .first?.string("owner_id")
                }
                if mine != nil {
                    continue
                } else if owner == userId {
                    ownerMint += 1
                } else {
                    unreadable.append("\(audience) (\(count) blocks, owner \(owner ?? "?"), \(rows.count) keys rows)")
                }
            }
            if ownerMint > 0 {
                s.note("\(ownerMint) owned audience(s) have no keys row for the account; the app derives their DEK from the mint rule (SPEC § 6.2)")
            }
            if unreadable.isEmpty {
                if !blockCounts.isEmpty, userId != nil { s.ok("the account holds a keys row, or owns, every audience its blocks use") }
            } else if userId == nil {
                s.note("cannot judge audience coverage without an account id")
            } else {
                s.warning("\(unreadable.count) audience(s) have blocks the account holds no key for")
                for line in unreadable.prefix(Self.maxListed) { s.line(line) }
            }
            let orphans = rowsByAudience.keys.filter { blockCounts[$0] == nil }.sorted()
            if !orphans.isEmpty {
                s.note("\(orphans.count) audience(s) have keys rows but no blocks: \(orphans.prefix(Self.maxListed).joined(separator: ", "))")
            }
        }
    }

    private func profiles(_ report: inout Report) throws {
        guard try db.hasTable("user_profiles") else { return }
        try report.section("Profiles") { s in
            let rows = try db.query("SELECT id, public_key FROM user_profiles")
            s.line("rows: \(rows.count)")
            var bad: [String] = []
            for row in rows {
                let key = row.string("public_key").flatMap { Data(base64Encoded: $0) }
                if key?.count != 32 { bad.append(row.string("id") ?? "?") }
            }
            if bad.isEmpty, !rows.isEmpty {
                s.ok("every public_key is base64 of 32 bytes (a raw Curve25519 public key)")
            } else if !bad.isEmpty {
                s.fail("\(bad.count) public_key value(s) are not 32-byte keys: \(bad.prefix(Self.maxListed).joined(separator: ", "))")
            }
            if let userId {
                if rows.contains(where: { $0.string("id") == userId }) {
                    s.ok("the account's own profile row is present")
                } else {
                    s.warning("no profile row for the account \(userId)")
                }
            }
        }
    }

    private func localOnly(_ report: inout Report) throws {
        try report.section("Local-only plaintext") { s in
            let tables = try db.tables()
            let uploaded = try db.uploadedTables()
            let local = tables.filter { table in Self.localPlaintextTables.contains { table == $0 || table.hasPrefix($0 + "_") } }
            s.line("present: \(local.joined(separator: ", "))")
            if try db.hasTable("plain_blocks"), try db.hasTable("blocks") {
                s.line("plain_blocks rows: \(try db.count("plain_blocks")) (blocks rows: \(try db.count("blocks")))")
            }
            let leaking = local.filter { uploaded.contains($0) }
            if leaking.isEmpty {
                s.ok("none of these tables has an upload trigger: they never sync (SPEC § 6.1)")
            } else {
                s.fail("local plaintext table(s) have an upload trigger: \(leaking.joined(separator: ", "))")
            }
        }
    }

    // MARK: - Helpers

    /// Why `text` is not a stored ciphertext envelope, or nil when it is.
    static func envelopeProblem(_ text: String) -> String? {
        let envelope: Envelope
        do {
            envelope = try Envelope(json: text)
        } catch {
            return "is not an envelope (\(error))"
        }
        if envelope.nonce.count != nonceLength { return "has a \(envelope.nonce.count)-byte nonce" }
        if envelope.tag.count != tagLength { return "has a \(envelope.tag.count)-byte tag" }
        if looksLikeText(envelope.ciphertext) { return "has ciphertext that reads as text" }
        return nil
    }

    /// AES-GCM output is uniformly random; readable UTF-8 of any length
    /// beyond a few bytes is not.
    static func looksLikeText(_ bytes: Data) -> Bool {
        guard bytes.count >= 8, let string = String(data: bytes, encoding: .utf8) else { return false }
        let printable = string.unicodeScalars.filter { $0.value >= 0x20 && $0.value < 0x7F || $0 == "\n" || $0 == "\t" }.count
        return printable * 10 >= string.unicodeScalars.count * 9
    }
}

/// One `ps_crud` row: PowerSync's queued operation, `{"op","type","id","data"}`.
struct CrudEntry {
    let op: String
    let table: String
    let id: String
    let data: [String: Any]

    init(json: String) {
        let object = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
        op = object["op"] as? String ?? "?"
        table = object["type"] as? String ?? "?"
        id = object["id"] as? String ?? "?"
        data = object["data"] as? [String: Any] ?? [:]
    }
}
