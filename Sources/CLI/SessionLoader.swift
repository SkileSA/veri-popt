import Foundation

/// What the secret-taking commands share: the folder, the locked keys, the
/// code from a file or a hidden prompt, and the optional database.
enum SessionLoader {
    enum Error: Swift.Error, CustomStringConvertible {
        case noTerminal
        var description: String { "no terminal to prompt on; pass --code-file" }
    }

    static func open(_ args: Arguments, requireDatabase: Bool) throws -> Session {
        let folder = try InputFolder(path: args.positionals[0])
        let record = try folder.keys()
        let db = (requireDatabase || folder.databasePath != nil) ? try folder.database() : nil
        let code = try readCode(from: args.option("code-file"))
        return try Session(record: record, code: code, db: db)
    }

    /// The code from a file, or from a prompt with echo off. Never from an
    /// argument: those sit in shell history and process lists.
    static func readCode(from file: String?) throws -> RecoveryCode {
        try RecoveryCode(parsing: try readSecret(prompt: "Recovery code: ", file: file))
    }

    /// A secret from a file (first line, newline stripped) or a hidden prompt.
    static func readSecret(prompt: String, file: String?) throws -> String {
        if let file {
            let text = try String(contentsOfFile: file, encoding: .utf8)
            return String(text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
        }
        guard let typed = getpass(prompt) else { throw Error.noTerminal }
        return String(cString: typed)
    }

    static func emit(_ report: Report, json: Bool) throws -> Int32 {
        if json {
            print(String(decoding: try report.json(), as: UTF8.self))
        } else {
            print(report.text(), terminator: "")
        }
        return report.hasFailures ? 1 : 0
    }
}
