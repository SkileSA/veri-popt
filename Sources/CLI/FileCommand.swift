import Foundation

/// `veri-popt file <folder> [--env production|staging] [--id BLOCK] [--limit N] [--out DIR] [--code-file F] [--json]`
enum FileCommand {
    static let usage = """
    usage: veri-popt file <folder> [--env production|staging] [--id BLOCK] [--limit N] [--out DIR] [--code-file <file>] [--json]

      Fetches attachment objects from the bucket exactly as the app does, a
      plain GET of the object key, and opens each under the file key carried
      in its row (SPEC § 7). The only command that uses the network.

      --env NAME        which bucket: production (default) or staging
      --id BLOCK        one attachment row only
      --limit N         how many rows to check (default 10; 0 for all)
      --out DIR         write the decrypted files there, <id>.<ext>
      --code-file FILE  read the recovery code from a file instead of prompting
      --json            machine-readable report
    """

    static func run(_ args: Arguments) -> Int32 {
        guard args.positionals.count == 1 else {
            warn(usage)
            return 2
        }
        do {
            let environment = try args.option("env").map { name -> BucketEnvironment in
                guard let env = BucketEnvironment(rawValue: name) else { throw OptionError.badEnvironment(name) }
                return env
            } ?? .production
            var options = FileReport.Options()
            options.id = args.option("id")
            if let limit = args.option("limit") {
                guard let n = Int(limit), n >= 0 else { throw OptionError.badLimit(limit) }
                options.limit = n
            }
            options.outDirectory = args.option("out")
            let session = try SessionLoader.open(args, requireDatabase: true)
            let report = try FileReport.run(session: session, fetcher: LiveObjectFetcher(environment: environment), environment: environment, options: options)
            return try SessionLoader.emit(report, json: args.flag("json"))
        } catch {
            warn("file: \(error)")
            return 2
        }
    }

    enum OptionError: Swift.Error, CustomStringConvertible {
        case badEnvironment(String), badLimit(String)
        var description: String {
            switch self {
            case .badEnvironment(let n): "unknown --env \(n); use production or staging"
            case .badLimit(let n): "--limit needs a whole number, got \(n)"
            }
        }
    }
}

/// HTTPS GETs against the bucket, synchronous for the CLI's sake.
struct LiveObjectFetcher: ObjectFetcher {
    let environment: BucketEnvironment

    func fetch(objectKey: String) throws -> Fetched {
        let url = environment.url(for: objectKey)
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Fetched, Swift.Error> = .failure(URLError(.unknown))
        URLSession.shared.dataTask(with: url) { data, response, error in
            defer { semaphore.signal() }
            if let error { result = .failure(error); return }
            guard let http = response as? HTTPURLResponse else { result = .failure(URLError(.badServerResponse)); return }
            result = .success((200 ..< 300).contains(http.statusCode) ? .bytes(data ?? Data()) : .status(http.statusCode))
        }.resume()
        semaphore.wait()
        return try result.get()
    }
}
