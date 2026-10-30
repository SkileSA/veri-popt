# Verifying your own account

What you need: a Mac with Popt installed and signed in, Xcode, your
recovery code, and about ten minutes. Nothing here needs an admin
password or a privacy grant.

## 1. Build the tool

Open `veri-popt.xcodeproj`, build the `veri-popt` scheme, and note where
the binary is (Product ▸ Show Build Folder in Finder), or from a
Terminal in the repository:

```bash
xcodebuild -scheme veri-popt -destination 'platform=macOS' build
```

The commands below write `veri-popt` for the binary; use its full path or
put it on your `PATH`.

## 2. Find the database

Launch Popt, then:

```bash
veri-popt find-db
```

It prints the folder where the running app keeps its database and opens
that folder in Finder with the file selected. The tool itself never
reads that folder; Finder is allowed in, and you do the copying.

## 3. Copy the database

Quit Popt first, so its write-ahead log is at rest. In the Finder window,
select the two files

- `powersync-popt-it.sqlite`
- `powersync-popt-it.sqlite-wal`

copy them (Cmd-C) and paste them (Cmd-V) into a new folder of yours, say
`~/popt-check`. Do not drag them: on the same disk a drag moves the files
out of the app. The `-shm` file is not needed.

## 4. Export your locked keys

Launch Popt again. In My Account, under Security, tap Export Locked Keys
and save `popt-locked-keys.json` into the same folder. The file holds
the encrypted copy of your keys that the server already stores, and your
recovery code is the only thing that opens it. It never contains the
code.

Your folder now holds the three files every command takes.

## 5. Look without any secret

```bash
veri-popt inspect ~/popt-check
```

This reads the copy and reports what the server sees: the plaintext
columns, every payload and wrapped key checked for being ciphertext, the
upload queue, your audiences, and the fact that the app's plaintext
mirror has no sync trigger. Nothing here uses your code.

## 6. Derive your keys

```bash
veri-popt derive ~/popt-check
```

You are prompted for your recovery code, typed with echo off; any form
is fine, with or without hyphens, in any case. The report walks the
chain from the code to every key, showing fingerprints rather than keys,
then shows each key opening something the app wrote, or says plainly
when the database holds nothing to check it against. A deliberately
wrong code is tried too and must fail.

If you want to script this, put the code alone in a file and pass
`--code-file`; delete the file afterwards. Never put the code on the
command line.

## 7. Audiences and blocks

```bash
veri-popt keys ~/popt-check
veri-popt blocks ~/popt-check
```

`keys` goes through every share: how each audience key is obtained and
whether the ones you own were minted by the documented rule. `blocks`
opens every row of your content under the documented key and compares
it with the app's own decryption, row by row. On a copy taken after a
quiet moment, every row should match; rows the app had not mirrored yet
are reported as pending, not as failures.

## 8. Attachments

```bash
veri-popt file ~/popt-check --out ~/popt-check/decrypted
```

This is the one command that uses the network: it fetches your
attachment objects from the bucket exactly as the app does, by plain
GET, and opens each under the file key carried in its row. With `--out`
the decrypted files are written where you say, so you can open your own
photos and see them come back. The default checks ten objects; pass
`--limit 0` for all. If your account is on the staging environment, add
`--env staging`.

## 9. Vaults

```bash
veri-popt vault-list ~/popt-check
veri-popt vault ~/popt-check --vault <id>
```

`vault-list` needs only the recovery code: it finds the secret config
block at its id derived from your Master DEK and lists every vault,
hidden ones included, with the id to use. `vault` then asks for that
vault's passphrase and checks every block in it. Without `--vault` it
tries the one passphrase on every slot and says which it opened. To
compare the inner content with the app's own decryption, copy
`popt-vault.sqlite` from the databases folder into your folder while
that vault is unlocked in Popt; the file is wiped at lock.

## Reading a report

Each line is tagged:

- `ok`: the check passed.
- `note`: a fact worth knowing, not a problem (for example, a key with no
  example to check against in this database).
- `WARN`: something unexpected that is not a failed check.
- `FAIL`: a check failed. The run continues so you see everything.

The exit status is 0 on pass, 1 when any check failed, 2 when the tool
could not run at all (a missing file, a wrong code). `--json` gives the
same report as data.

## If something fails

A report contains no key and no code unless you asked for `--reveal`,
so it is safe to share. Open an issue on this repository with the
report, the version of Popt, and whether the copy was taken while Popt
was running. A failure is either a bug in this tool, a change in the app
the spec has not caught up with, or a real problem, and the spec's
provenance table says which version of the app it describes.

## Cleaning up

The folder holds a readable copy of your content: the database carries
the app's own decrypted mirror, and `--out` writes your files in the
clear. Delete the folder when you are done.
