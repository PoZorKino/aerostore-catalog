# Getting your app into aerostore

aerostore lists open source Windows apps. If your app is open source and has a
Windows build, you can add it. There are two ways in.

## 1. Pull request

1. Fork this repo.
2. Copy a file from `manifests/` that looks like your app (installer or
   portable) and save it as `manifests/<your.id>.json`. The id is
   `publisher.app` in lowercase, like `videolan.vlc`, and has to match the
   file name.
3. Fill it in. The full format is in `FORMAT.md`, and `schema.json` has the
   same rules for your editor.
4. Check it (needs Go 1.27+):

   ```
   cd tools
   go run ./cmd/validate ../manifests/your.id.json
   ```

   Add `-download` to also fetch your file and check the hash and size.
5. Open the PR. Updates work the same way: bump `version`, `url`, `sha256`
   and `size` in your existing file.

Leave the `.sig` files alone. After merge the maintainer signs the manifest,
and the app shows your app (or the update) once it's signed.

## 2. Web form or the app

Use "Submit your app" inside AeroStore. (A web form is coming once the server is
public.)
You can leave the hash empty. The server downloads your file, fills in the
sha256 and size, and a person reviews it. Approved apps get committed to this
repo, same as a PR.

## Things we check

- The license is OSI-approved or FSF-free, written as an SPDX id
  (`GPL-3.0-or-later`, `MIT`, `Apache-2.0`).
- `source` points at the public source code.
- `install.url` is a fixed link to that exact version, not a "latest"
  redirect. Every url is https.
- `install.sha256` matches the file. The app checks it before running anything.
- Installers: `silent_args` installs without questions. NSIS is `/S`, Inno
  Setup is `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, MSI is `/qb`.
  `detect` is the start of the `DisplayName` your installer writes under
  `Software\Microsoft\Windows\CurrentVersion\Uninstall`.
- Portable zips: `exe` is the path of the main exe inside the zip.
- The icon is square, PNG or ICO, 256px if you have it.

If something is unclear, open an issue and ask.
