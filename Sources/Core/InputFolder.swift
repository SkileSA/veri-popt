import Foundation

/// The one input every command takes: a folder holding what the user
/// copied and exported, found by their fixed names.
///
/// - `powersync-popt-it.sqlite` with its `-wal` sidecar, copied
///   from where `find-db` pointed;
/// - `popt-locked-keys.json`, from My Account ▸ Security ▸ Export Locked
///   Keys.
///
/// A path to the database file itself is accepted too, for `inspect`.
struct InputFolder {
    static let keysFileName = "popt-locked-keys.json"
    /// The vault database, present only in a copy taken while a vault was
    /// unlocked (the app wipes it at lock).
    static let vaultDatabaseFileName = "popt-vault.sqlite"

    let path: String
    let databasePath: String?
    let keysPath: String?
    let vaultDatabasePath: String?

    enum Error: Swift.Error, CustomStringConvertible {
        case noSuchFolder(String)
        case noDatabase(String)
        case noKeys(String)

        var description: String {
            switch self {
            case .noSuchFolder(let p): "no such folder: \(p)"
            case .noDatabase(let p):
                "no \(Database.appFileName) in \(p). Copy it there with its -wal file (see `veri-popt find-db`)"
            case .noKeys(let p):
                "no \(InputFolder.keysFileName) in \(p). Export it from My Account ▸ Security ▸ Export Locked Keys and save it there"
            }
        }
    }

    init(path: String) throws {
        var isDirectory: ObjCBool = false
        let fm = FileManager.default
        guard fm.fileExists(atPath: path, isDirectory: &isDirectory) else { throw Error.noSuchFolder(path) }
        if isDirectory.boolValue {
            self.path = path
            let db = (path as NSString).appendingPathComponent(Database.appFileName)
            let keys = (path as NSString).appendingPathComponent(Self.keysFileName)
            databasePath = fm.fileExists(atPath: db) ? db : nil
            keysPath = fm.fileExists(atPath: keys) ? keys : nil
            let vault = (path as NSString).appendingPathComponent(Self.vaultDatabaseFileName)
            vaultDatabasePath = fm.fileExists(atPath: vault) ? vault : nil
        } else {
            // A database file given directly.
            self.path = (path as NSString).deletingLastPathComponent
            databasePath = path
            let keys = (self.path as NSString).appendingPathComponent(Self.keysFileName)
            keysPath = fm.fileExists(atPath: keys) ? keys : nil
            let vault = (self.path as NSString).appendingPathComponent(Self.vaultDatabaseFileName)
            vaultDatabasePath = fm.fileExists(atPath: vault) ? vault : nil
        }
    }

    func vaultDatabase() throws -> Database? {
        try vaultDatabasePath.map { try Database(path: $0) }
    }

    func database() throws -> Database {
        guard let databasePath else { throw Error.noDatabase(path) }
        return try Database(path: databasePath)
    }

    func keys() throws -> VaultRecord {
        guard let keysPath else { throw Error.noKeys(path) }
        return try VaultRecord(contentsOf: URL(fileURLWithPath: keysPath))
    }
}
