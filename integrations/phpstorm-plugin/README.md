# phpwarden for PhpStorm

A PhpStorm plugin that runs the phpwarden CLI already installed on your machine and shows its
findings in the editor and in the Problems tool window. It does the same job as the VS Code
extension in `integrations/vscode`.

- **composer.lock**: when you open or save the file, the plugin runs `phpwarden deps composer.lock --json`
  and marks each vulnerable package on its `"name": "vendor/package"` line.
- **PHP files**: when you open or save a file, the plugin runs `phpwarden code <file> --format sarif` and
  marks each finding at the reported line.
- **Severity mapping**:

  | Finding | Shown as |
  |---|---|
  | Known exploited (CISA KEV) or EPSS ≥ 0.5 | Error, message prefixed `[EXPLOITED]` for KEV |
  | Dependency severity critical / high | Warning |
  | Dependency severity medium / low / unknown | Weak warning |
  | SARIF `error` / `warning` / `note` | Error / Warning / Weak warning |

- **Tooltip** (hover or quick documentation): CVE, title, severity/CVSS/EPSS, KEV and ransomware flags,
  every fixed version, and the `composer require vendor/pkg:^X.Y.Z` upgrade to the lowest fixed version above
  the installed one. For code findings it shows the rule's description and fix advice.
- **Quick fix** (Alt+Enter): *Copy upgrade command*.
- **Tools menu**: *phpwarden: Rescan Open Files* and *phpwarden: Feed Status*.
- **Settings | Tools | phpwarden**: CLI path (`phpwarden`, `vendor/bin/phpwarden`, or
  `python3 /path/to/phpwarden.pyz`), enable/disable the plugin, dependency scan, code scan and
  rescan on save, plus a minimum dependency severity. KEV and EPSS ≥ 0.5 findings are always shown.

The CLI is only run when the file on disk changes. While you have unsaved edits, the plugin keeps showing the
last results. The plugin makes no network calls and uploads nothing. The CLI's own feed updates are the same
as when you run it in a terminal.

Requirements: PhpStorm 2024.2 or newer (build 242+), and the phpwarden CLI (`pipx install phpwarden`).
`phpwarden code` needs CLI 2.2.0 or newer. With an older CLI the plugin switches PHP scans off and tells you once.

If you can't install a plugin, use the External Tool setup in `integrations/phpstorm/README.md` instead.

## Build

You need JDK 21, because 2024.2+ IDEs run on Java 21. The Gradle wrapper is included, and the first build
downloads Gradle 8.10.2 and PhpStorm 2024.2 (about 1 GB) from the official Gradle and JetBrains repositories.

```sh
cd integrations/phpstorm-plugin
./gradlew buildPlugin      # -> build/distributions/phpwarden-phpstorm-0.1.0.zip
./gradlew test             # parser tests against ../vscode/test-fixtures
./gradlew verifyPlugin     # JetBrains Plugin Verifier against the IDEs listed in build.gradle.kts
./gradlew runIde           # sandbox PhpStorm with the plugin loaded
```

## Install from disk

1. Run `./gradlew buildPlugin`.
2. In PhpStorm, open **Settings | Plugins**, click the gear icon, and choose **Install Plugin from Disk…**.
3. Pick `build/distributions/phpwarden-phpstorm-0.1.0.zip` and restart if PhpStorm asks you to.
4. Open **Settings | Tools | phpwarden** and set the CLI path if `phpwarden` isn't on the PATH PhpStorm sees.
   GUI-launched IDEs on macOS often don't get your shell PATH, so use an absolute path such as
   `/Users/you/.local/bin/phpwarden`.

## Publishing to JetBrains Marketplace

None of this has been set up yet. Here is what's needed and why:

1. **Plugin ID:** `io.phpwarden.ide`. Marketplace rejects new IDs containing "phpstorm", so this is the ID to
   upload with; it can't be changed after the first upload.
2. **A JetBrains Account**, signed in at plugins.jetbrains.com. All uploads belong to an account.
3. **A vendor/organization profile** named *phpwarden* (URL `https://phpwarden.io`, email
   `sales@phpwarden.io`). Marketplace shows this as the publisher, and it should match `<vendor>` in
   `plugin.xml`. Accept the Marketplace developer agreement while creating it.
4. **The first upload is done by hand** in the web UI (*Upload plugin*). Choose the license
   (Apache-2.0, link to the source repo) and a category. JetBrains then reviews the plugin manually, which
   takes a few business days. They check the name, the description, a working plugin and vendor details.
5. **A signing certificate chain and private key.** Marketplace signs plugins too, but you sign the zip
   with your own key so the IDE can check it came from you and wasn't changed. To create them:
   ```sh
   openssl genpkey -aes-256-cbc -algorithm RSA -out private_encrypted.pem -pkeyopt rsa_keygen_bits:4096
   openssl rsa -in private_encrypted.pem -out private.pem
   openssl req -key private.pem -new -x509 -days 3650 -out chain.crt
   ```
   Then provide them as environment variables, never committed: `CERTIFICATE_CHAIN` (the contents of
   chain.crt), `PRIVATE_KEY` (the contents of private.pem) and `PRIVATE_KEY_PASSWORD`, and run
   `./gradlew signPlugin`. Keep the key backed up. Later updates should be signed with the same key.
6. **A Marketplace permanent token** (from *My Tokens* in your JetBrains Account) in `PUBLISH_TOKEN`.
   After the first manual upload, `./gradlew publishPlugin` signs the zip and uploads new versions.
7. **Listing assets** (optional, but they help review): a 40×40 `META-INF/pluginIcon.svg` (plus an optional
   `pluginIcon_dark.svg`), screenshots, and change notes (`<change-notes>` or the `patchPluginXml` changeNotes).

## Status

- `./gradlew buildPlugin`: BUILD SUCCESSFUL (compiled against PhpStorm 2024.2, JDK 21).
- `./gradlew test`: 3/3 pass.
- `./gradlew verifyPlugin`: **Compatible** with PhpStorm 2025.2 (PS-252.23892.419). The verifier could not resolve the bundled PHP plugin
  in the 2024.2 download, so 2024.2 was compiled against but not verified.
- The plugin hasn't been tested by hand in a running IDE yet. Try it with `./gradlew runIde` on a project
  that has a composer.lock.
