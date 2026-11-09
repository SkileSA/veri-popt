import Foundation

/// `veri-popt keys <folder> [--code-file <file>] [--json]`
enum KeysCommand {
    static let usage = """
    usage: veri-popt keys <folder> [--code-file <file>] [--json]

      Every audience the account's data refers to, with the keys row it
      holds, how its DEK is obtained, and, for audiences the account owns,
      every row it wrapped for a member re-opened with that member's
      published key (SPEC § 6.3).

      <folder> holds popt-locked-keys.json and the database copy
      (powersync-popt-it.sqlite with its -wal file).

      --code-file FILE  read the recovery code from a file instead of prompting
      --json            machine-readable report
    """

    static func run(_ args: Arguments) -> Int32 {
        guard args.positionals.count == 1 else {
            warn(usage)
            return 2
        }
        do {
            let session = try SessionLoader.open(args, requireDatabase: true)
            return try SessionLoader.emit(try KeysReport.run(session: session), json: args.flag("json"))
        } catch {
            warn("keys: \(error)")
            return 2
        }
    }
}
