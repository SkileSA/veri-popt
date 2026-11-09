import Foundation

/// `veri-popt inspect <db-copy> [--user ID] [--json]`
enum InspectCommand {
    static let usage = """
    usage: veri-popt inspect <folder> [--user ID] [--json]

      Reads the COPY of the app's database in <folder> (powersync-popt-it.sqlite
      with its -wal file, see `veri-popt find-db`) with no secret and
      reports what the server sees, that every stored payload is ciphertext,
      and that the plaintext mirror never syncs. A path to the .sqlite file
      itself works too. Exit status is 1 when any check fails.

      --user ID   judge audiences for this account instead of the one the
                  database names
      --json      machine-readable report
    """

    static func run(_ args: Arguments) -> Int32 {
        guard args.positionals.count == 1 else {
            warn(usage)
            return 2
        }
        do {
            let db = try InputFolder(path: args.positionals[0]).database()
            let report = try Inspection(db: db, userOverride: args.option("user")).run()
            if args.flag("json") {
                print(String(decoding: try report.json(), as: UTF8.self))
            } else {
                print(report.text(), terminator: "")
            }
            return report.hasFailures ? 1 : 0
        } catch {
            warn("inspect: \(error)")
            return 2
        }
    }
}
