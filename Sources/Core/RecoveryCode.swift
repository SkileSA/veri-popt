import Foundation

/// The recovery code (SPEC § 3): sixteen Crockford base32 characters,
/// shown as four hyphenated groups of four.
///
/// The hyphens are part of the key material: the KDF input is the UTF-8
/// bytes of the 19-character formatted string. This type accepts any
/// reasonable input form (hyphens or not, spaces, lowercase, surrounding
/// whitespace) and always yields the canonical formatted string.
struct RecoveryCode: Equatable, Sendable {
    static let alphabet: Set<Character> = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    static let length = 16
    static let groupLength = 4

    /// Canonical form, `XXXX-XXXX-XXXX-XXXX`.
    let formatted: String

    /// What the recovery KEK is derived from: the formatted string's bytes.
    var keyMaterial: Data { Data(formatted.utf8) }

    enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case wrongLength(Int)
        case invalidCharacter(Character)

        var description: String {
            switch self {
            case .wrongLength(let n): "recovery code has \(n) characters, expected \(RecoveryCode.length)"
            case .invalidCharacter(let c): "recovery code contains \"\(c)\", which is not in the Crockford base32 alphabet"
            }
        }
    }

    /// Trims, uppercases, drops hyphens and spaces, checks the alphabet and
    /// the length, then re-joins as four groups of four.
    init(parsing input: String) throws {
        let cleaned = input
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .uppercased()
            .filter { $0 != "-" && $0 != " " }
        if let bad = cleaned.first(where: { !Self.alphabet.contains($0) }) {
            throw Error.invalidCharacter(bad)
        }
        guard cleaned.count == Self.length else { throw Error.wrongLength(cleaned.count) }
        let chars = Array(cleaned)
        formatted = stride(from: 0, to: Self.length, by: Self.groupLength)
            .map { String(chars[$0 ..< $0 + Self.groupLength]) }
            .joined(separator: "-")
    }
}
