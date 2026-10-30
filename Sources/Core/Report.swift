import Foundation

/// What every command produces: sections of lines and findings, rendered
/// as text or JSON. A run fails when any finding is `.fail`.
struct Report: Codable {
    enum Level: String, Codable, Comparable {
        case ok, note, warning, fail

        private var rank: Int {
            switch self { case .ok: 0; case .note: 1; case .warning: 2; case .fail: 3 }
        }

        static func < (a: Level, b: Level) -> Bool { a.rank < b.rank }

        var tag: String {
            switch self {
            case .ok: "ok  "
            case .note: "note"
            case .warning: "WARN"
            case .fail: "FAIL"
            }
        }
    }

    struct Finding: Codable {
        let level: Level
        let message: String
    }

    struct Section: Codable {
        let title: String
        var lines: [String] = []
        var findings: [Finding] = []

        mutating func line(_ text: String) { lines.append(text) }
        mutating func ok(_ text: String) { findings.append(Finding(level: .ok, message: text)) }
        mutating func note(_ text: String) { findings.append(Finding(level: .note, message: text)) }
        mutating func warning(_ text: String) { findings.append(Finding(level: .warning, message: text)) }
        mutating func fail(_ text: String) { findings.append(Finding(level: .fail, message: text)) }
    }

    let title: String
    var sections: [Section] = []

    init(title: String) { self.title = title }

    mutating func section(_ title: String, _ fill: (inout Section) throws -> Void) rethrows {
        var section = Section(title: title)
        try fill(&section)
        sections.append(section)
    }

    var findings: [Finding] { sections.flatMap(\.findings) }
    var worst: Level { findings.map(\.level).max() ?? .ok }
    var hasFailures: Bool { worst == .fail }

    // MARK: - Rendering

    func text() -> String {
        var out = "\(title)\n\(String(repeating: "=", count: title.count))\n"
        for section in sections {
            out += "\n\(section.title)\n\(String(repeating: "-", count: section.title.count))\n"
            for line in section.lines { out += "  \(line)\n" }
            for finding in section.findings { out += "  [\(finding.level.tag)] \(finding.message)\n" }
        }
        let counts = Dictionary(grouping: findings, by: \.level).mapValues(\.count)
        out += "\nResult: \(hasFailures ? "FAIL" : worst == .warning ? "PASS with warnings" : "PASS")"
        out += " (\(counts[.ok] ?? 0) ok, \(counts[.note] ?? 0) notes, \(counts[.warning] ?? 0) warnings, \(counts[.fail] ?? 0) failures)\n"
        return out
    }

    func json() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(Envelope(report: self))
    }

    private struct Envelope: Codable {
        let report: Report
        var result: String { report.hasFailures ? "fail" : "pass" }
        enum CodingKeys: String, CodingKey { case title, sections, result }
        func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(report.title, forKey: .title)
            try c.encode(report.sections, forKey: .sections)
            try c.encode(result, forKey: .result)
        }
        init(report: Report) { self.report = report }
        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            var report = Report(title: try c.decode(String.self, forKey: .title))
            report.sections = try c.decode([Section].self, forKey: .sections)
            self.report = report
        }
    }
}
