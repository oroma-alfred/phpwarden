# phpwarden for VS Code

PHP vulnerabilities, ranked by real-world exploitation. This extension runs the open-source
[phpwarden](https://phpwarden.io) CLI on your machine and shows its findings in the Problems panel.

## What it does

- **composer.lock**: when you open or save `composer.lock` (and when the workspace opens), it runs
  `phpwarden deps composer.lock --json` and marks each vulnerable package on its `"name"` line.
  - **Error**: the CVE is on CISA's Known Exploited Vulnerabilities list (tagged `[EXPLOITED]`), or EPSS ≥ 0.5
  - **Warning**: critical / high severity
  - **Information**: everything else
- **Quick fix**: "Copy upgrade command" copies `composer require vendor/pkg:^<fixed>` to the clipboard,
  using the lowest fixed version above the one you have installed.
- **PHP code** (phpwarden ≥ 2.2): when you save a `.php` file it runs `phpwarden code <file> --format sarif`
  and shows the results. With an older CLI, the status bar says so and the rest keeps working.
- **Status bar**: `phpwarden: N exploited / M total`. Click it to open Problems.

## Install the extension

It is not on the Marketplace yet. Build the `.vsix` from this folder and install it:

```sh
cd integrations/vscode
npm install && npm run compile
npx @vscode/vsce package --no-dependencies
code --install-extension phpwarden-0.1.0.vsix
```

## Install the CLI first

```sh
pipx install phpwarden
```

You can also use the single-file build (https://phpwarden.io/phpwarden.pyz): set `phpwarden.path` to
`python3 /path/to/phpwarden.pyz`.

## Commands

- `phpwarden: Scan workspace`
- `phpwarden: Scan composer.lock`
- `phpwarden: Show feed status`

## Settings

| Setting | Default | |
|---|---|---|
| `phpwarden.path` | `phpwarden` | CLI command; may include arguments, e.g. `python3 phpwarden.pyz` |
| `phpwarden.runOnSave` | `true` | Scan on save |
| `phpwarden.codeScan` | `true` | Run `phpwarden code` on PHP files |
| `phpwarden.minSeverity` | `low` | `low` / `medium` / `high` / `critical`. Exploited findings always show |

## Privacy

Everything runs locally. The extension only starts the phpwarden CLI on your machine against your files.
It uploads no code, lockfiles or telemetry. The CLI checks against its bundled vulnerability feed.

## License

Apache-2.0
