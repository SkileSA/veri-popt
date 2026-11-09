import CryptoKit
import Foundation

/// A structural difference between two parsed JSON values, located by a
/// dotted path (`alerts[0].offset`). Objects are compared key by key,
/// arrays element by element; a `null` counts as a present value, so
/// `"x": null` against a missing `x` is a difference.
struct JSONDiff: Equatable {
    enum Kind: String, Codable {
        /// The key exists in the decrypted ciphertext only.
        case onlyInCiphertext = "only in the ciphertext"
        /// The key exists in the mirror only.
        case onlyInMirror = "only in the mirror"
        /// Both sides have the key with different values.
        case differentValue = "differs"
    }

    let path: String
    let kind: Kind
    let ciphertext: Any?
    let mirror: Any?

    static func == (a: JSONDiff, b: JSONDiff) -> Bool {
        a.path == b.path && a.kind == b.kind && JSON.equal(a.ciphertext, b.ciphertext) && JSON.equal(a.mirror, b.mirror)
    }

    /// Every difference between `ciphertext` and `mirror`, deepest paths
    /// first where the shapes agree, the whole value where they do not.
    static func diff(ciphertext: Any?, mirror: Any?, path: String = "") -> [JSONDiff] {
        switch (ciphertext, mirror) {
        case (nil, nil):
            return []
        case (let c?, nil):
            return [JSONDiff(path: path, kind: .onlyInCiphertext, ciphertext: c, mirror: nil)]
        case (nil, let m?):
            return [JSONDiff(path: path, kind: .onlyInMirror, ciphertext: nil, mirror: m)]
        case (let c?, let m?):
            if let co = c as? [String: Any], let mo = m as? [String: Any] {
                var out: [JSONDiff] = []
                for key in Set(co.keys).union(mo.keys).sorted() {
                    out += diff(ciphertext: co[key], mirror: mo[key], path: path.isEmpty ? key : "\(path).\(key)")
                }
                return out
            }
            if let ca = c as? [Any], let ma = m as? [Any], ca.count == ma.count {
                var out: [JSONDiff] = []
                for (i, pair) in zip(ca, ma).enumerated() {
                    out += diff(ciphertext: pair.0, mirror: pair.1, path: "\(path)[\(i)]")
                }
                return out
            }
            if JSON.equal(c, m) { return [] }
            return [JSONDiff(path: path, kind: .differentValue, ciphertext: c, mirror: m)]
        }
    }

    /// The JSON type of a value, for a report that must not show content.
    static func typeName(_ value: Any?) -> String {
        switch value {
        case nil: return "absent"
        case is NSNull: return "null"
        case is String: return "string"
        case is [String: Any]: return "object"
        case is [Any]: return "array"
        case let n as NSNumber:
            return CFGetTypeID(n) == CFBooleanGetTypeID() ? "boolean" : "number"
        default: return "value"
        }
    }

    /// The value as compact JSON with sorted keys, for `--reveal`.
    static func render(_ value: Any?) -> String {
        guard let value else { return "absent" }
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed]) else {
            return String(describing: value)
        }
        return String(decoding: data, as: UTF8.self)
    }
}

/// `blocks-diff`: for every row `blocks` would report as "mirror differs",
/// or for one row named with `--id`, the difference between the tool's
/// decryption and the app's mirror, field by field and key by key. The
/// app writes the mirror by decoding the ciphertext into its typed model
/// and encoding that model again (`PlainBlocksRow.fromSyncedBlock`), so a
/// row written by an older app version can carry keys the current model
/// drops, or lack keys it now adds, until the row is next edited. Such
/// key-set differences are reported as notes; a key present on both sides
/// with different values is a warning, since nothing in the app explains
/// it. Content never appears without `--reveal`: each side is named by
/// its JSON type.
enum BlocksDiffReport {
    static let maxRows = 50

    enum Error: Swift.Error, CustomStringConvertible {
        case noDatabase
        case noSuchRow(String)
        case foreignRow(String)
        var description: String {
            switch self {
            case .noDatabase: return "blocks-diff needs the database copy in the folder"
            case .noSuchRow(let id): return "no blocks row with id \(id)"
            case .foreignRow(let id): return "row \(id) is a personal row of another account; no key here can open it"
            }
        }
    }

    struct RowDiff {
        let id: String
        let audience: String?
        let type: Int
        let revision: Int64
        /// Mirror columns other than `payload` that differ
        /// (`BlocksReport.differences` minus "payload").
        let columns: [String]
        let payload: [JSONDiff]
        var valuesDiffer: Bool { payload.contains { $0.kind == .differentValue } }
    }

    static func run(session: Session, id: String?, reveal: Bool) throws -> Report {
        guard let db = session.db else { throw Error.noDatabase }
        var report = Report(title: "veri-popt blocks-diff")

        let rows = try db.query(
            """
            SELECT id, revision, audience_id, owner_id, root_id, storage, storage_updated_at, storage_key, payload
            FROM blocks \(id == nil ? "" : "WHERE id = ?") ORDER BY id
            """,
            id.map { [.text($0)] } ?? []
        )
        if let id, rows.isEmpty { throw Error.noSuchRow(id) }

        var considered = 0, compared = 0, unopened: [String] = [], diffs: [RowDiff] = []
        var identical: String?, notMirrored: String?

        for row in rows {
            let rowId = row.string("id") ?? "?"
            let audience = row.string("audience_id")
            if audience == nil, row.string("owner_id") != session.userId {
                if id != nil { throw Error.foreignRow(rowId) }
                continue
            }
            considered += 1

            let key: SymmetricKey
            if audience == BlocksReport.sentinelAudience {
                key = session.subkeys.shareExtensionKey
            } else if let k = try session.blockKey(audienceId: audience).key {
                key = k
            } else {
                unopened.append("\(rowId): no key for audience \(audience ?? "personal")")
                continue
            }
            let block: DecryptedBlock
            do {
                block = try BlockCrypto.open(payload: row.string("payload") ?? "", with: key)
            } catch {
                unopened.append("\(rowId): does not open (\(error))")
                continue
            }

            guard let mirror = try db.query("SELECT * FROM plain_blocks WHERE id = ?", [.text(rowId)]).first,
                  mirror.int("revision") == row.int("revision")
            else {
                if id != nil { notMirrored = rowId }
                continue
            }
            compared += 1
            let columns = BlocksReport.differences(block: block, blocksRow: row, mirror: mirror).filter { $0 != "payload" }
            let mirrorPayload = mirror.string("payload").flatMap { try? JSON.parse($0) }
            let payload = JSONDiff.diff(ciphertext: block.value, mirror: mirrorPayload)
            if columns.isEmpty && payload.isEmpty {
                if id != nil { identical = rowId }
                continue
            }
            diffs.append(RowDiff(id: rowId, audience: audience, type: block.type, revision: row.int("revision") ?? 0, columns: columns, payload: payload))
        }

        let keySetOnly = diffs.filter { !$0.valuesDiffer && $0.columns.isEmpty }.count
        let withValues = diffs.count - keySetOnly

        report.section("Summary") { s in
            s.line("rows considered: \(considered)\(id.map { " (id \($0))" } ?? ""); compared with the mirror: \(compared); differing: \(diffs.count)")
            s.line("the app writes the mirror from its typed model, decoded from the ciphertext and encoded again; a row from an older app version differs in the keys that model dropped or added until the row is next edited")
            if let identical { s.ok("row \(identical) decrypts to exactly what the mirror holds") }
            if let notMirrored { s.note("row \(notMirrored) has no mirror at its revision; nothing to compare (the app has not mirrored it yet)") }
            if !unopened.isEmpty {
                s.fail("\(unopened.count) row(s) could not be opened; `blocks` reports these: \(unopened.prefix(5).joined(separator: "; "))")
            }
            if diffs.isEmpty, identical == nil, notMirrored == nil, unopened.isEmpty {
                s.ok("no mirror row differs from the ciphertext")
            }
            if keySetOnly > 0 {
                s.note("\(keySetOnly) row(s) differ only in which keys are present: fields the current app's model does not carry, or now adds (a legacy row)")
            }
            if withValues > 0 {
                s.warning("\(withValues) row(s) carry a key whose value differs between the ciphertext and the mirror, or a differing mirror column; nothing in the app explains that")
            }
            if !reveal, !diffs.isEmpty { s.line("values are shown by JSON type only; add --reveal to print them") }
        }

        for d in diffs.prefix(Self.maxRows) {
            report.section("Row \(d.id)") { s in
                s.line("\(d.audience.map { "audience \($0)" } ?? "personal"); type \(d.type); revision \(d.revision)")
                for column in d.columns { s.line("mirror column \(column) differs from the ciphertext") }
                for entry in d.payload {
                    let where_ = entry.path.isEmpty ? "(whole payload)" : entry.path
                    if reveal {
                        s.line("\(entry.kind.rawValue): \(where_)  ciphertext = \(JSONDiff.render(entry.ciphertext))  mirror = \(JSONDiff.render(entry.mirror))")
                    } else {
                        s.line("\(entry.kind.rawValue): \(where_)  (\(JSONDiff.typeName(entry.ciphertext)) vs \(JSONDiff.typeName(entry.mirror)))")
                    }
                }
                if d.valuesDiffer || !d.columns.isEmpty {
                    s.warning("a value differs between the ciphertext and the mirror")
                } else {
                    s.note("key-set difference only: the mirror is the current model's re-encoding of this row")
                }
            }
        }
        if diffs.count > Self.maxRows {
            report.section("More") { s in s.line("… and \(diffs.count - Self.maxRows) more row(s); narrow with --id") }
        }
        return report
    }
}
