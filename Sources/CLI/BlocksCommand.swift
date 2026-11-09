import Foundation

/// `veri-popt blocks <folder> [--audience ID] [--code-file <file>] [--json]`
enum BlocksCommand {
    static let usage = """
    usage: veri-popt blocks <folder> [--audience ID] [--code-file <file>] [--json]

      Opens every blocks row under the documented key and compares it with
      the app's own decryption in plain_blocks, wherever the app has mirrored
      that revision (SPEC § 6.2, § 6.4). Failures are listed; the run never
      stops at one.

      <folder> holds popt-locked-keys.json and the database copy
      (powersync-popt-it.sqlite with its -wal file).

      --audience ID     only the rows of that audience
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
            let report = try BlocksReport.run(session: session, audience: args.option("audience"))
            return try SessionLoader.emit(report, json: args.flag("json"))
        } catch {
            warn("blocks: \(error)")
            return 2
        }
    }
}
