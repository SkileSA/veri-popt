import Foundation

/// Minimal argument handling: a subcommand, positionals, `--flag` and
/// `--option value`. Enough for this tool; no dependency.
struct Arguments {
    let command: String?
    private(set) var positionals: [String] = []
    private(set) var flags: Set<String> = []
    private(set) var options: [String: String] = [:]

    enum Error: Swift.Error, CustomStringConvertible {
        case missingValue(String)
        case unknown(String)
        var description: String {
            switch self {
            case .missingValue(let o): "option \(o) needs a value"
            case .unknown(let o): "unknown option \(o)"
            }
        }
    }

    init(_ argv: [String], flags known: Set<String>, options knownOptions: Set<String>) throws {
        var rest = argv.dropFirst()
        command = rest.first.flatMap { $0.hasPrefix("-") ? nil : $0 }
        if command != nil { rest = rest.dropFirst() }
        var iterator = rest.makeIterator()
        while let arg = iterator.next() {
            if arg.hasPrefix("--") {
                let name = String(arg.dropFirst(2))
                if known.contains(name) {
                    flags.insert(name)
                } else if knownOptions.contains(name) {
                    guard let value = iterator.next() else { throw Error.missingValue(arg) }
                    options[name] = value
                } else {
                    throw Error.unknown(arg)
                }
            } else {
                positionals.append(arg)
            }
        }
    }

    func flag(_ name: String) -> Bool { flags.contains(name) }
    func option(_ name: String) -> String? { options[name] }
}

/// Writes to stderr.
func warn(_ text: String) {
    FileHandle.standardError.write(Data((text + "\n").utf8))
}
