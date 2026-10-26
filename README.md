# AeroStore catalog

The list of apps in AeroStore, an app store
for open source Windows software that looks like Windows 7.

Every app is one JSON file in `manifests/`, plus a `.sig` signature the maintainer adds after
review. AeroStore only shows signed entries and checks every download against its sha256.

Want your app in? See [CONTRIBUTING.md](CONTRIBUTING.md). The format is in [FORMAT.md](FORMAT.md).

`tools/` is a copy of the validator from the AeroStore server, so CI here can check PRs.
