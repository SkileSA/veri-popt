import Foundation

/// veri-popt: checks Popt's cryptographic claims against a user's own data.
/// See docs/SPEC.md for what is checked and README.md for how to run it.

let usage = """
usage: veri-popt <command> [options]

commands:
  find-db     locate the running app's database and reveal it in Finder
  inspect     check a database copy without any secret
  derive      derive every key from your recovery code and locked keys
  keys        every audience and keys row, opened with the account's keys
  blocks      every block opened and compared with the app's own decryption
  file        attachment objects fetched from the bucket and opened (network)
  vault-list  every secret vault slot, from the recovery code alone
  vault       a vault opened with its passphrase, every block in it checked
  help        this text, or `veri-popt <command> --help`

Every command but find-db takes one folder: the database copy
(powersync-popt-it.sqlite + -wal) and popt-locked-keys.json.
See docs/VERIFYING.md for the walk-through and docs/SPEC.md for what
each check means.
"""

let status: Int32
do {
    let args = try Arguments(CommandLine.arguments, flags: ["json", "help", "reveal"], options: ["user", "code-file", "audience", "env", "id", "limit", "out", "vault", "name", "passphrase-file"])
    switch args.command {
    case "inspect":
        status = args.flag("help") ? { print(InspectCommand.usage); return 0 }() : InspectCommand.run(args)
    case "derive":
        status = args.flag("help") ? { print(DeriveCommand.usage); return 0 }() : DeriveCommand.run(args)
    case "keys":
        status = args.flag("help") ? { print(KeysCommand.usage); return 0 }() : KeysCommand.run(args)
    case "blocks":
        status = args.flag("help") ? { print(BlocksCommand.usage); return 0 }() : BlocksCommand.run(args)
    case "file":
        status = args.flag("help") ? { print(FileCommand.usage); return 0 }() : FileCommand.run(args)
    case "vault-list":
        status = args.flag("help") ? { print(VaultListCommand.usage); return 0 }() : VaultListCommand.run(args)
    case "vault":
        status = args.flag("help") ? { print(VaultCommand.usage); return 0 }() : VaultCommand.run(args)
    case "find-db":
        status = args.flag("help") ? { print(FindDBCommand.usage); return 0 }() : FindDBCommand.run(args)
    case nil, "help":
        print(usage)
        status = args.command == nil && !args.flag("help") ? 2 : 0
    case let other?:
        warn("veri-popt: unknown command \(other)\n\(usage)")
        status = 2
    }
} catch {
    warn("veri-popt: \(error)\n\(usage)")
    status = 2
}
exit(status)
