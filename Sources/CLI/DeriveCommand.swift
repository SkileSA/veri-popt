import Foundation

/// `veri-popt derive --vault record.json [--db copy] [--code-file F] [--reveal] [--json]`
enum DeriveCommand {
    static let usage = """
    usage: veri-popt derive <folder> [--code-file <file>] [--reveal] [--json]

      Walks the chain from your recovery code and your exported locked keys
      to every key (SPEC § 5), then shows each key opening something the app
      wrote, or says it found nothing to check.

      <folder> holds popt-locked-keys.json (My Account ▸ Security ▸ Export
      Locked Keys) and, for the checks against your data, the database copy
      powersync-popt-it.sqlite with its -wal file (`veri-popt find-db`).

      --code-file FILE  read the recovery code from a file instead of prompting
      --reveal          print the keys themselves (hex) at the end
      --json            machine-readable report
    """

    static func run(_ args: Arguments) -> Int32 {
        guard args.positionals.count == 1 else {
            warn(usage)
            return 2
        }
        do {
            let folder = try InputFolder(path: args.positionals[0])
            let record = try folder.keys()
            let db = folder.databasePath == nil ? nil : try folder.database()
            let code = try SessionLoader.readCode(from: args.option("code-file"))
            let report = try DeriveReport.run(record: record, code: code, db: db, reveal: args.flag("reveal"))
            return try SessionLoader.emit(report, json: args.flag("json"))
        } catch {
            warn("derive: \(error)")
            return 2
        }
    }
}
