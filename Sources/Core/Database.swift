import Foundation
import SQLite3

/// A read-only view of a copy of the app's PowerSync database.
///
/// Opened with `SQLITE_OPEN_READONLY`, never with `immutable=1`: the
/// immutable flag makes SQLite ignore the write-ahead log, and a copy taken
/// with its `-wal` sidecar would then read stale. Read-only mode reads the
/// WAL and writes nothing.
final class Database {
    /// The file name the app uses (`SystemManager.dbFilenameAccount`).
    static let appFileName = "powersync-popt-it.sqlite"
    static let sidecarSuffixes = ["-wal", "-shm"]

    enum Error: Swift.Error, CustomStringConvertible {
        case noSuchFile(String)
        case cannotOpen(path: String, message: String, permissionDenied: Bool)
        case query(sql: String, message: String)

        var description: String {
            switch self {
            case .noSuchFile(let path): "no such file: \(path.isEmpty ? "(empty path)" : path)"
            case .cannotOpen(let path, let message, let denied):
                denied
                    ? "cannot open \(path): permission denied. That is the live file inside the app's container; "
                      + "copy it to a folder of yours (see `veri-popt find-db`)."
                    : "cannot open \(path): \(message)"
            case .query(let sql, let message): "query failed: \(message)\n  \(sql)"
            }
        }
    }

    enum Value: Equatable {
        case null
        case integer(Int64)
        case real(Double)
        case text(String)
        case blob(Data)
    }

    /// One result row, by column name.
    struct Row {
        let values: [String: Value]

        func string(_ column: String) -> String? {
            if case .text(let s)? = values[column] { return s }
            return nil
        }

        func int(_ column: String) -> Int64? {
            switch values[column] {
            case .integer(let i)?: return i
            case .real(let d)?: return Int64(d)
            default: return nil
            }
        }

        func isNull(_ column: String) -> Bool {
            if case .null? = values[column] { return true }
            return values[column] == nil
        }
    }

    let path: String
    private var handle: OpaquePointer?

    init(path: String) throws {
        self.path = path
        // SQLite opens an empty path as a temporary database and a missing
        // one as nothing useful; both would produce a meaningless report.
        var isDirectory: ObjCBool = false
        guard !path.isEmpty, FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            throw Error.noSuchFile(path)
        }
        var db: OpaquePointer?
        let status = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard status == SQLITE_OK, let db else {
            let message = db.map { String(cString: sqlite3_errmsg($0)) } ?? "SQLite error \(status)"
            if let db { sqlite3_close(db) }
            let denied = !FileManager.default.isReadableFile(atPath: path) && FileManager.default.fileExists(atPath: path)
                || message.lowercased().contains("permission") || status == SQLITE_CANTOPEN && Self.looksLive(path)
            throw Error.cannotOpen(path: path, message: message, permissionDenied: denied)
        }
        handle = db
    }

    deinit {
        if let handle { sqlite3_close(handle) }
    }

    /// Whether `path` is where the app keeps its live database.
    static func looksLive(_ path: String) -> Bool {
        path.contains("/Library/Containers/") && path.contains("/Application Support/databases/")
    }

    // MARK: - Queries

    func query(_ sql: String, _ parameters: [Value] = []) throws -> [Row] {
        guard let handle else { return [] }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw Error.query(sql: sql, message: String(cString: sqlite3_errmsg(handle)))
        }
        defer { sqlite3_finalize(statement) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (index, parameter) in parameters.enumerated() {
            let position = Int32(index + 1)
            switch parameter {
            case .null: sqlite3_bind_null(statement, position)
            case .integer(let i): sqlite3_bind_int64(statement, position, i)
            case .real(let d): sqlite3_bind_double(statement, position, d)
            case .text(let s): sqlite3_bind_text(statement, position, s, -1, transient)
            case .blob(let b): b.withUnsafeBytes { sqlite3_bind_blob(statement, position, $0.baseAddress, Int32(b.count), transient) }
            }
        }

        let columnCount = Int(sqlite3_column_count(statement))
        let names = (0 ..< columnCount).map { String(cString: sqlite3_column_name(statement, Int32($0))) }
        var rows: [Row] = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { break }
            guard step == SQLITE_ROW else {
                throw Error.query(sql: sql, message: String(cString: sqlite3_errmsg(handle)))
            }
            var values: [String: Value] = [:]
            for i in 0 ..< columnCount {
                let column = Int32(i)
                switch sqlite3_column_type(statement, column) {
                case SQLITE_INTEGER: values[names[i]] = .integer(sqlite3_column_int64(statement, column))
                case SQLITE_FLOAT: values[names[i]] = .real(sqlite3_column_double(statement, column))
                case SQLITE_TEXT: values[names[i]] = .text(String(cString: sqlite3_column_text(statement, column)))
                case SQLITE_BLOB:
                    let count = Int(sqlite3_column_bytes(statement, column))
                    let base = sqlite3_column_blob(statement, column)
                    values[names[i]] = .blob(base.map { Data(bytes: $0, count: count) } ?? Data())
                default: values[names[i]] = .null
                }
            }
            rows.append(Row(values: values))
        }
        return rows
    }

    func scalar(_ sql: String, _ parameters: [Value] = []) throws -> Value? {
        try query(sql, parameters).first?.values.values.first
    }

    func count(_ table: String, where clause: String = "1") throws -> Int {
        guard case .integer(let n)? = try scalar("SELECT COUNT(*) FROM \(table) WHERE \(clause)") else { return 0 }
        return Int(n)
    }

    // MARK: - Schema

    func tables() throws -> [String] {
        try query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").compactMap { $0.string("name") }
    }

    func hasTable(_ name: String) throws -> Bool {
        try tables().contains(name)
    }

    func columns(of table: String) throws -> [String] {
        try query("SELECT name FROM pragma_table_xinfo(?) ORDER BY cid", [.text(table)]).compactMap { $0.string("name") }
    }

    struct Trigger {
        let name: String
        let table: String
        let sql: String
    }

    func triggers() throws -> [Trigger] {
        try query("SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name").compactMap {
            guard let name = $0.string("name"), let table = $0.string("tbl_name"), let sql = $0.string("sql") else { return nil }
            return Trigger(name: name, table: table, sql: sql)
        }
    }

    /// Tables whose triggers write the upload queue: the ones PowerSync
    /// uploads. A table without such a trigger never leaves the device
    /// through sync (SPEC § 6.1).
    ///
    /// PowerSync's raw-table triggers insert into `powersync_crud`, a
    /// virtual table of its extension that lands rows in `ps_crud`; an
    /// older SDK wrote `ps_crud` directly. Both spellings count.
    static let uploadQueueNames = ["powersync_crud", "ps_crud"]

    func uploadedTables() throws -> Set<String> {
        Set(try triggers().filter { trigger in Self.uploadQueueNames.contains { trigger.sql.contains($0) } }.map(\.table))
    }

    // MARK: - The account

    /// The account this database was built for (`local_info.user_id`).
    func userId() throws -> String? {
        guard try hasTable("local_info") else { return nil }
        return try query("SELECT value FROM local_info WHERE key = 'user_id'").first?.string("value")
    }

    // MARK: - Sidecars

    /// Which WAL / SHM sidecars sit next to the file.
    var sidecarsPresent: [String] {
        Self.sidecarSuffixes.filter { FileManager.default.fileExists(atPath: path + $0) }
    }

    var fileSize: Int64 {
        (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int64) ?? 0
    }
}
