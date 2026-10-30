# veri-popt

A command-line tool for your Mac. It checks what [Popt](https://popt.com)
says about encryption, using your own data and your own recovery code.

Popt says your content is encrypted on your device before it goes
anywhere. The keys come from your recovery code and a record the server
cannot open. The server, the sync service and the file bucket only ever
hold ciphertext. This tool lets you see that for yourself. It
re-implements the published cryptography without any of the app's code,
then runs it against a copy of the app's database, the keys the app
exports, and the files the bucket serves.

## What it proves

For the account you give it:

- The published derivation reproduces the app's keys. The public keys it
  derives are the ones the server publishes.
- Every row of your content opens under the documented key. It decrypts
  to exactly what the app itself decrypted.
- Every audience key you hold unwraps through the documented path. Peer
  keys come from your pinned keys, never from what the server publishes.
  Audiences you own were minted by the documented rule.
- Files fetched from the bucket are ciphertext. They open under the key
  inside the owning row, to the file the row describes.
- A vault opens with its passphrase and nothing less. Every block in it
  opens under its own key. The main database keeps the inner layer sealed.
- Wrong inputs fail: a wrong code, a wrong passphrase, a wrong key, a
  changed byte.

With no secret at all, it also shows what a copy of the database reveals:
which columns leave the device in plaintext, that every stored payload is
an envelope, and that the app's plaintext mirror never syncs.

## What it does not prove

- Anything about the app's binaries or the running app. The tool checks
  the data the app produced, not the app's code.
- Anything about the server beyond what it stores for your account.
- The items listed as not covered in [docs/SPEC.md](docs/SPEC.md) § 10.
  Each will get a check, or a note on why it cannot, in a coming version.

## How it stays independent

- No code from the app. The crypto is written from
  [docs/SPEC.md](docs/SPEC.md) with Apple's CryptoKit, CommonCrypto for
  PBKDF2, and the system SQLite. No packages.
- No entitlements, no signing, no Full Disk Access. The tool never reads
  the app's folder. `find-db` asks the running app where its database
  is and shows it in Finder. You copy the files.
- Known-answer tests. The vectors in `Tests/Fixtures/vectors.json` were
  produced once by the app's own code. The spec records when and from
  which version.
- One network use. Only `file` goes online, and only to fetch objects
  from the bucket with plain GETs. Downloads are open by design. No
  token, no account call.

## Commands

Every command except `find-db` takes one folder. The folder holds:

- `powersync-popt-it.sqlite` and its `-wal` file, copied from where
  `find-db` points;
- `popt-locked-keys.json`, from My Account ▸ Security ▸ Export Locked
  Keys;
- `popt-vault.sqlite`, optional, copied while a vault is unlocked.

The recovery code is typed at a hidden prompt, or read from a file with
`--code-file`. It is never a command-line argument. Reports never print a
key unless you ask with `--reveal`. Every command has `--help` and
`--json`. The exit status is 1 when a check fails and 2 when the tool
could not run.

### find-db

Launch Popt, then run this. It prints where the running app keeps its
database and opens that folder in Finder. Copy the two files from there.

### inspect

No secret needed. It lists which columns of your content leave the
device in plaintext. It checks that every stored payload and every
wrapped key is an envelope. It checks the pending uploads the same way.
It shows your audiences and profiles. And it checks that the plaintext
mirror the app keeps for its own screens has no sync trigger.

### derive

Needs the locked keys and your recovery code. It walks the chain from
the code to every key and prints a fingerprint for each. It tries a
wrong code and shows that it fails. With the database in the folder, it
shows each key opening something the app wrote, or says plainly when
there was nothing to check it against. It also checks your key pins.

### keys

Needs all three files and your code. One section per audience: who owns
it, how many blocks it holds, which row you hold, how your key for it
was obtained, and whether an audience you own was minted by the rule.

### blocks

Needs all three files and your code. It opens every row of your content
under the documented key and compares it with the app's own decryption,
row by row. Rows the app has not mirrored yet are counted as pending.
Failures are listed and the run goes on.

### file

Needs all three files and your code. The only command that uses the
network. It fetches your attachments from the bucket as the app does,
with plain GETs, and opens each one under the key inside its row. It
checks the size, the declared type and the thumbnail. With `--out` it
writes the decrypted files so you can open your own photos. It checks
ten objects by default; `--limit 0` checks all.

### vault-list

Needs all three files and your code. It finds the vault config block at
its id derived from your Master DEK and lists every vault, hidden ones
included, with the id to use.

### vault

Needs a vault's passphrase as well. Pick a vault with `--vault <id>` or
`--name <name>`. It opens the vault's key with the passphrase, opens
every block in it under its own key, checks that parents stay inside the
vault, and checks that the main database keeps the inner layer sealed.
With `popt-vault.sqlite` in the folder, it compares with the app's own
decryption.

The walk-through is [docs/VERIFYING.md](docs/VERIFYING.md).

## Building

Xcode 27 or later on macOS 26.2 or later. Open `veri-popt.xcodeproj`
and build the `veri-popt` scheme, or:

```bash
xcodebuild -scheme veri-popt -destination 'platform=macOS' build
```

The binary lands in Xcode's build products folder. Copy it somewhere on
your `PATH` if you like. Run the tests with Product ▸ Test, or:

```bash
xcodebuild -scheme veri-popt -destination 'platform=macOS' test
```

The tests need no database, no network and no account. They run the
primitives against the vectors and the commands against a small database
built from them.

## Layout

- `docs/SPEC.md`: the cryptography as implemented. The tool is written
  from this text. It records where each fact comes from.
- `docs/VERIFYING.md`: how to run a verification, step by step.
- `Sources/Core`: the pure parts, compiled into the tool and the tests.
- `Sources/CLI`: the commands.
- `Tests`: the known-answer tests and the small database.

## License

MIT, see [LICENSE](LICENSE).
