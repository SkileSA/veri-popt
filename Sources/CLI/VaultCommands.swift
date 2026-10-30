import Foundation

/// `veri-popt vault-list <folder> [--code-file F] [--json]`
enum VaultListCommand {
    static let usage = """
    usage: veri-popt vault-list <folder> [--code-file <file>] [--json]

      Finds the secret config block at its id derived from the Master DEK,
      opens it with the recovery code's keys, and lists every vault slot,
      hidden ones included (SPEC § 8). No passphrase needed.
    """

    static func run(_ args: Arguments) -> Int32 {
        guard args.positionals.count == 1 else { warn(usage); return 2 }
        do {
            let session = try SessionLoader.open(args, requireDatabase: true)
            return try SessionLoader.emit(try VaultReport.list(session: session), json: args.flag("json"))
        } catch {
            warn("vault-list: \(error)")
            return 2
        }
    }
}

/// `veri-popt vault <folder> [--vault ID | --name NAME] [--code-file F] [--passphrase-file F] [--json]`
enum VaultCommand {
    static let usage = """
    usage: veri-popt vault <folder> [--vault <id> | --name <name>] [--code-file <file>] [--passphrase-file <file>] [--json]

      Opens a vault with its passphrase and checks every block in it: the
      per-row inner keys, containment, the opaque mirror in the main
      database, the ids derived from the vault DEK, and, when the folder
      holds popt-vault.sqlite copied while the vault was unlocked, the
      app's own decryption (SPEC § 8). Without --vault or --name every slot
      is tried with the one passphrase; slots it does not open are noted.

      --vault ID            one vault, by the id `vault-list` shows
      --name NAME           one vault by name; ambiguous names ask for --vault
      --code-file FILE      the recovery code from a file instead of a prompt
      --passphrase-file FILE  the vault passphrase from a file instead of a prompt
      --json                machine-readable report
    """

    static func run(_ args: Arguments) -> Int32 {
        guard args.positionals.count == 1, !(args.option("vault") != nil && args.option("name") != nil) else { warn(usage); return 2 }
        do {
            let folder = try InputFolder(path: args.positionals[0])
            let session = try SessionLoader.open(args, requireDatabase: true)
            let passphrase = try SessionLoader.readSecret(prompt: "Vault passphrase: ", file: args.option("passphrase-file"))
            let selector: VaultReport.Selector = args.option("vault").map { .id($0) } ?? args.option("name").map { .name($0) } ?? .all
            let report = try VaultReport.check(session: session, selector: selector, passphrase: passphrase, vaultDb: try folder.vaultDatabase())
            return try SessionLoader.emit(report, json: args.flag("json"))
        } catch {
            warn("vault: \(error)")
            return 2
        }
    }
}
