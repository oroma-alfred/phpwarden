import * as vscode from 'vscode';
import { execFile } from 'child_process';
import * as path from 'path';
import * as p from './parse';

let depsDiag: vscode.DiagnosticCollection;
let codeDiag: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;
let output: vscode.OutputChannel;
const upgrades = new Map<string, string>(); // key: uri#line -> command
const lockCounts = new Map<string, { exploited: number; total: number }>();
const timers = new Map<string, NodeJS.Timeout>();
let codeUnsupported = false;

function cfg() { return vscode.workspace.getConfiguration('phpwarden'); }

interface RunResult { stdout: string; stderr: string; code: number; notFound: boolean }

function run(args: string[], cwd?: string): Promise<RunResult> {
  const { cmd, args: pre } = p.splitCommand(cfg().get<string>('path', 'phpwarden'));
  return new Promise(resolve => {
    execFile(cmd, [...pre, ...args], { cwd, maxBuffer: 64 * 1024 * 1024, timeout: 300000 }, (err: any, stdout, stderr) => {
      const notFound = err && err.code === 'ENOENT';
      const code = err ? (typeof err.code === 'number' ? err.code : -1) : 0;
      resolve({ stdout: String(stdout), stderr: String(stderr), code, notFound: !!notFound });
    });
  });
}

let warnedMissing = false;
function cliMissing() {
  status.text = '$(warning) phpwarden: CLI not found';
  if (warnedMissing) return;
  warnedMissing = true;
  vscode.window.showWarningMessage('phpwarden CLI not found. Install it with `pipx install phpwarden`, or set `phpwarden.path`.');
}

const SEV: Record<p.Level, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error, warning: vscode.DiagnosticSeverity.Warning, info: vscode.DiagnosticSeverity.Information,
};

function toDiag(d: p.DiagData): vscode.Diagnostic {
  const diag = new vscode.Diagnostic(new vscode.Range(d.line, d.column, d.line, d.endColumn), d.message, SEV[d.level]);
  diag.source = 'phpwarden';
  if (d.code) diag.code = d.code;
  return diag;
}

function updateStatus() {
  let e = 0, t = 0;
  for (const c of lockCounts.values()) { e += c.exploited; t += c.total; }
  status.text = `${e ? '$(flame)' : '$(shield)'} phpwarden: ${e} exploited / ${t} total`;
  status.tooltip = 'phpwarden Composer findings in this workspace — click to open Problems';
  status.show();
}

async function scanLock(uri: vscode.Uri) {
  const res = await run(['deps', uri.fsPath, '--json'], path.dirname(uri.fsPath));
  if (res.notFound) return cliMissing();
  let doc: p.DepsDoc;
  try { doc = JSON.parse(res.stdout); } catch {
    output.appendLine(`deps failed for ${uri.fsPath} (exit ${res.code}): ${res.stderr}`);
    return;
  }
  const text = (await vscode.workspace.fs.readFile(uri)).toString();
  const data = p.depsToDiagnostics(doc, text, cfg().get<string>('minSeverity', 'low'));
  for (const k of [...upgrades.keys()]) if (k.startsWith(uri.toString() + '#')) upgrades.delete(k);
  for (const d of data) if (d.upgrade) upgrades.set(`${uri.toString()}#${d.line}#${d.code}`, d.upgrade);
  depsDiag.set(uri, data.map(toDiag));
  lockCounts.set(uri.toString(), p.countDeps(doc));
  updateStatus();
}

async function scanCode(target: vscode.Uri) {
  if (!cfg().get<boolean>('codeScan', true) || codeUnsupported) return;
  const folder = vscode.workspace.getWorkspaceFolder(target);
  const cwd = folder ? folder.uri.fsPath : path.dirname(target.fsPath);
  const res = await run(['code', target.fsPath, '--format', 'sarif'], cwd);
  if (res.notFound) return cliMissing();
  let sarif: any;
  try { sarif = JSON.parse(res.stdout); } catch {
    if (p.looksLikeMissingSubcommand(res.stderr)) {
      codeUnsupported = true;
      vscode.window.setStatusBarMessage('phpwarden code needs phpwarden ≥ 2.2', 10000);
    } else {
      output.appendLine(`code scan failed for ${target.fsPath} (exit ${res.code}): ${res.stderr}`);
    }
    return;
  }
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const d of p.sarifToDiagnostics(sarif)) {
    const u = d.file!.startsWith('file:') ? vscode.Uri.parse(d.file!) : vscode.Uri.file(path.resolve(cwd, decodeURIComponent(d.file!)));
    const k = u.toString();
    if (!byFile.has(k)) byFile.set(k, []);
    byFile.get(k)!.push(toDiag(d));
  }
  // A single-file scan with no results clears that file.
  if (!byFile.has(target.toString())) codeDiag.delete(target);
  for (const [k, diags] of byFile) codeDiag.set(vscode.Uri.parse(k), diags);
}

async function scanWorkspace() {
  const locks = await vscode.workspace.findFiles('**/composer.lock', '**/{vendor,node_modules}/**');
  await Promise.all(locks.map(scanLock));
  if (!locks.length) updateStatus();
  if (cfg().get<boolean>('codeScan', true)) {
    for (const f of vscode.workspace.workspaceFolders ?? []) await scanCode(f.uri);
  }
}

function debounce(key: string, fn: () => void, ms = 800) {
  clearTimeout(timers.get(key));
  timers.set(key, setTimeout(() => { timers.delete(key); fn(); }, ms));
}

const isLock = (d: vscode.TextDocument) => path.basename(d.uri.fsPath) === 'composer.lock' && d.uri.scheme === 'file';

class UpgradeActions implements vscode.CodeActionProvider {
  provideCodeActions(doc: vscode.TextDocument, _r: vscode.Range, ctx: vscode.CodeActionContext) {
    const acts: vscode.CodeAction[] = [];
    for (const d of ctx.diagnostics) {
      if (d.source !== 'phpwarden') continue;
      const cmd = upgrades.get(`${doc.uri.toString()}#${d.range.start.line}#${d.code}`);
      if (!cmd) continue;
      const a = new vscode.CodeAction(`Copy upgrade command: ${cmd}`, vscode.CodeActionKind.QuickFix);
      a.command = { command: 'phpwarden.copyUpgrade', title: 'Copy upgrade command', arguments: [cmd] };
      a.diagnostics = [d];
      acts.push(a);
    }
    return acts;
  }
}

export function activate(ctx: vscode.ExtensionContext) {
  depsDiag = vscode.languages.createDiagnosticCollection('phpwarden-deps');
  codeDiag = vscode.languages.createDiagnosticCollection('phpwarden-code');
  output = vscode.window.createOutputChannel('phpwarden');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'workbench.actions.view.problems';
  status.text = '$(shield) phpwarden';
  status.show();

  ctx.subscriptions.push(depsDiag, codeDiag, output, status,
    vscode.commands.registerCommand('phpwarden.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('phpwarden.scanLock', async () => {
      const ed = vscode.window.activeTextEditor;
      if (ed && isLock(ed.document)) return scanLock(ed.document.uri);
      const locks = await vscode.workspace.findFiles('**/composer.lock', '**/vendor/**');
      if (!locks.length) return vscode.window.showInformationMessage('phpwarden: no composer.lock in this workspace.');
      await Promise.all(locks.map(scanLock));
    }),
    vscode.commands.registerCommand('phpwarden.feedStatus', async () => {
      const res = await run(['feed', 'status', '--json']);
      if (res.notFound) return cliMissing();
      try {
        const s = JSON.parse(res.stdout);
        vscode.window.showInformationMessage(`phpwarden feed ${s.feed_version} (${s.channel}, ${s.source}): ` +
          `${s.total_advisories} advisories, ${s.composer_count} Composer.`);
      } catch { vscode.window.showErrorMessage(`phpwarden feed status failed: ${res.stderr || res.stdout}`); }
    }),
    vscode.commands.registerCommand('phpwarden.copyUpgrade', async (cmd: string) => {
      await vscode.env.clipboard.writeText(cmd);
      vscode.window.setStatusBarMessage(`Copied: ${cmd}`, 4000);
    }),
    vscode.languages.registerCodeActionsProvider({ pattern: '**/composer.lock' }, new UpgradeActions(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidOpenTextDocument(d => { if (isLock(d)) scanLock(d.uri); }),
    vscode.workspace.onDidSaveTextDocument(d => {
      if (!cfg().get<boolean>('runOnSave', true) || d.uri.scheme !== 'file') return;
      if (isLock(d)) scanLock(d.uri);
      else if (d.languageId === 'php' || d.uri.fsPath.endsWith('.php')) debounce(d.uri.toString(), () => scanCode(d.uri));
    }),
    vscode.workspace.onDidChangeConfiguration(e => { if (e.affectsConfiguration('phpwarden')) { codeUnsupported = false; scanWorkspace(); } }),
  );
  scanWorkspace();
}

export function deactivate() { for (const t of timers.values()) clearTimeout(t); }
