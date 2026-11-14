# phpwarden in PhpStorm

There is no phpwarden plugin for PhpStorm or other JetBrains IDEs yet. Until
there is, you can run the CLI from inside the IDE as an External Tool. This
needs phpwarden installed first (`pipx install phpwarden`, or
`composer require --dev phpwarden/phpwarden` and use `vendor/bin/phpwarden`).
The `code` command is in phpwarden 2.2.0 and newer.

## Run it as an External Tool

**Settings → Tools → External Tools → +** and add one entry per command.

Scan your own code:

| Field | Value |
|---|---|
| Name | phpwarden code |
| Program | `phpwarden` |
| Arguments | `code $ProjectFileDir$` |
| Working directory | `$ProjectFileDir$` |

Scan the dependencies:

| Field | Value |
|---|---|
| Name | phpwarden deps |
| Program | `phpwarden` |
| Arguments | `deps $ProjectFileDir$/composer.lock` |
| Working directory | `$ProjectFileDir$` |

Run them from **Tools → External Tools**, or give them a shortcut under
**Settings → Keymap → External Tools**. The output opens in the Run tool
window. `code` findings are printed as `file:line:column` relative to the
project, so you can jump to them with **Navigate → File** (paste
`plain.php:13`).

To scan only the file you are editing, use `code $FilePath$` as the arguments.

## Run it when a file is saved

If the File Watchers plugin is enabled (**Settings → Tools → File Watchers**),
add a custom watcher for the PHP file type with program `phpwarden` and
arguments `code $FilePath$`. The watcher's console shows the findings after
each save. A whole-project scan is quick, but a per-file watcher keeps the
output short.

## What this does not give you

- No inline highlighting in the editor and no quick fixes. For that today, use
  the VS Code extension in [`../vscode`](../vscode).
- No results in the Problems tool window.

`phpwarden code --format sarif` and `phpwarden deps --format sarif` write
SARIF 2.1.0 files, which other tools can read; this guide does not depend on
that.

Everything runs on your machine. Nothing is uploaded.
