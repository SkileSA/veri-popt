import AppKit
import Foundation

/// `veri-popt find-db`
///
/// Finds the live database of a running Popt through the files the process
/// holds open (what `lsof` shows; any process of the same user may ask) and
/// reveals it in Finder. The CLI never reads the container itself, so no
/// Full Disk Access is involved: Finder is allowed in, and the user copies
/// the files from there.
enum FindDBCommand {
    static let bundleIdPrefix = "ch.skile.popt-it"

    static let usage = """
    usage: veri-popt find-db

      Launch Popt, then run this. It prints where the running app keeps its
      database and opens that folder in Finder with the file selected.
    """

    static func run(_ args: Arguments) -> Int32 {
        let apps = NSWorkspace.shared.runningApplications.filter {
            $0.bundleIdentifier?.hasPrefix(bundleIdPrefix) == true
        }
        guard !apps.isEmpty else {
            warn("find-db: Popt is not running. Launch it, then run this again; the path comes from the live process.")
            return 2
        }
        var found = 0
        for app in apps {
            let pid = app.processIdentifier
            let label = "\(app.localizedName ?? "Popt") (\(app.bundleIdentifier ?? "?"), pid \(pid))"
            let paths = openFiles(of: pid).filter { $0.hasSuffix("/" + Database.appFileName) }
            guard let dbPath = paths.first else {
                warn("find-db: \(label) has no database open yet; give it a moment after launch and retry.")
                continue
            }
            found += 1
            let folder = (dbPath as NSString).deletingLastPathComponent
            print("\(label) keeps its database at")
            print("  \(folder)/")
            print("    \(Database.appFileName)")
            print("    \(Database.appFileName)-wal")
            print("")
            reveal(dbPath)
        }
        guard found > 0 else { return 2 }
        print("""
        Revealed in Finder. To take a copy:
          1. Quit Popt, so the write-ahead log is at rest.
          2. In that Finder window select those two files (the -shm file is
             not needed), copy them (Cmd-C), then paste (Cmd-V) into a folder
             of yours.
          Do not drag them: on the same disk a drag MOVES the files out of the app.
          3. Save My Account ▸ Security ▸ Export Locked Keys into the same folder.
        Then: veri-popt inspect <your-folder>   and   veri-popt derive <your-folder>
        """)
        return 0
    }

    /// Paths the process has open, via lsof's machine-readable output.
    static func openFiles(of pid: pid_t) -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-p", String(pid), "-Fn"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return [] }
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        return output.split(separator: "\n").filter { $0.hasPrefix("n/") }.map { String($0.dropFirst()) }
    }

    static func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }
}
