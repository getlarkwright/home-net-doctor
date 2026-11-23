# Releasing

Publishing runs from GitHub Actions (`.github/workflows/publish.yml`): tests, then npm through
trusted publishing (no npm token stored anywhere), then the entry in the official MCP Registry.

## Each release

1. Bump `version` in `package.json`, in both places in `server.json`, and in the README install lines, then commit and push to `main`.
2. Wait for CI to pass on Linux, macOS and Windows.
3. Publish a GitHub release whose tag is `v` plus that version, for example `v0.1.1`. Prereleases are skipped.
4. Check it: `npm view home-net-doctor version`, then `npx -y home-net-doctor@<version> --version` from an
   empty folder, and the server's entry in the MCP Registry.

## First version and the one-time npm setup

npm adds a trusted publisher in the package's own settings, so the package has to exist first. Version 0.1.0
is therefore published by hand (`npm publish`, with the maintainer's passkey). The registry step can then
be run by publishing the GitHub release.

Then, on npmjs.com, open the package's **Settings → Trusted Publisher**, choose **GitHub Actions**, and enter:

| Field | Value |
| --- | --- |
| Organization or user | `getlarkwright` |
| Repository | `home-net-doctor` |
| Workflow filename | `publish.yml` |
| Environment | (leave empty) |

Allow direct `npm publish`. The fields are case-sensitive, and npm does not check them when you save;
a mistake shows up only as an `ENEEDAUTH` error at publish time. npm expires a new trusted publisher that
has not published within 2 days, so add it shortly before a release.

Once one release has gone out this way, set **Publishing access** to "Require two-factor authentication and
disallow tokens". Trusted publishing keeps working with that setting.
