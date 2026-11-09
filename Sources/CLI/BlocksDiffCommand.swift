import Foundation

/// `veri-popt blocks-diff <folder> [--id BLOCK] [--reveal] [--code-file <file>] [--json]`
enum BlocksDiffCommand {
    static let usage = """
    usage: veri-popt blocks-diff <folder> [--id BLOCK] [--reveal] [--code-file <file>] [--json]

      For every row that `blocks` reports as "mirror differs", or for the
      one row named with --id, shows where the tool's decryption and the
      app's mirror in plain_blocks differ: key by key inside the payload,
      and any other mirror column. The app writes the mirror from its typed
      model, so a row from an older app version can differ in the keys that
      model no longer carries; those are notes. A key whose value differs is
      a warning.

      <folder> holds popt-locked-keys.json and the database copy
      (powersync-popt-it.sqlite with its -wal file).

      --id BLOCK        one blocks row, shown whether or not it differs
      --reveal          print the differing values (your content) instead of their JSON types
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
            let report = try BlocksDiffReport.run(session: session, id: args.option("id"), reveal: args.flag("reveal"))
            return try SessionLoader.emit(report, json: args.flag("json"))
        } catch {
            warn("blocks-diff: \(error)")
            return 2
        }
    }
}
