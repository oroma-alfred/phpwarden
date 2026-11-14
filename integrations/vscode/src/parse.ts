// Pure logic (no `vscode` import) so it can be unit-tested with plain node.

/** Mirrors one entry of `phpwarden deps <lock> --json` -> doc.vulnerable[] (src/phpwarden/cli.py _deps). */
export interface DepFinding {
  package: string;
  installed: string;
  cve: string;
  severity: string; // critical|high|medium|low|unknown
  cvss: number | null;
  known_exploited: boolean;
  ransomware: boolean;
  epss: number | null;
  epss_percentile: number | null;
  title: string;
  fixed: string[];
  reach: string;
}

export interface DepsDoc { lockfile: string; vulnerable: DepFinding[] }

export type Level = 'error' | 'warning' | 'info';

export interface DiagData {
  line: number;       // 0-based
  column: number;     // 0-based start
  endColumn: number;  // 0-based end
  level: Level;
  message: string;
  code?: string;
  file?: string;      // SARIF only: artifact uri
  pkg?: string;
  upgrade?: string;   // composer require command for quick fix
  exploited?: boolean;
}

const SEV_RANK: Record<string, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function isUrgent(f: DepFinding): boolean {
  return !!f.known_exploited || (f.epss !== null && f.epss !== undefined && f.epss >= 0.5);
}

export function depLevel(f: DepFinding): Level {
  if (isUrgent(f)) return 'error';
  const s = (f.severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'warning';
  return 'info';
}

/** True when the finding should be shown under the minSeverity setting. Urgent findings always show. */
export function passesMinSeverity(f: DepFinding, min: string): boolean {
  if (isUrgent(f)) return true;
  const m = SEV_RANK[(min || 'low').toLowerCase()] ?? 1;
  if (m <= 1) return true; // "low" shows everything, including unknown severity
  return (SEV_RANK[(f.severity || '').toLowerCase()] ?? 0) >= m;
}

function parts(v: string): number[] {
  return v.trim().replace(/^v/i, '').split(/[-+]/)[0].split('.').map(p => parseInt(p, 10) || 0);
}

export function compareVersions(a: string, b: string): number {
  const x = parts(a), y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** Lowest fixed version strictly greater than installed, or undefined. */
export function pickFixed(installed: string, fixed: string[]): string | undefined {
  const c = (fixed || []).filter(f => compareVersions(f, installed) > 0).sort(compareVersions);
  return c[0];
}

export function upgradeCommand(f: DepFinding): string | undefined {
  const v = pickFixed(f.installed, f.fixed);
  return v ? `composer require ${f.package}:^${v.replace(/^v/i, '')}` : undefined;
}

export function depMessage(f: DepFinding): string {
  const fixed = f.fixed && f.fixed.length ? f.fixed.join(', ') : 'no fix yet';
  let m = `${f.package} ${f.installed}: ${f.cve} ${f.title} — fixed in ${fixed}`;
  if (f.known_exploited) m = `[EXPLOITED] ${m}`;
  return m;
}

/** Find the `"name": "<pkg>"` line in composer.lock text. Returns 0-based line/cols or undefined. */
export function findPackageLine(lockText: string, pkg: string): { line: number; column: number; endColumn: number } | undefined {
  const lines = lockText.split(/\r?\n/);
  const needle = JSON.stringify(pkg).toLowerCase();
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].toLowerCase();
    const m = /"name"\s*:\s*/.exec(l);
    if (m && l.slice(m.index + m[0].length).startsWith(needle)) {
      const col = m.index + m[0].length;
      return { line: i, column: col, endColumn: col + needle.length };
    }
  }
  return undefined;
}

export function depsToDiagnostics(doc: DepsDoc, lockText: string, minSeverity = 'low'): DiagData[] {
  const out: DiagData[] = [];
  for (const f of doc.vulnerable || []) {
    if (!passesMinSeverity(f, minSeverity)) continue;
    const pos = findPackageLine(lockText, f.package) ?? { line: 0, column: 0, endColumn: 1 };
    out.push({ ...pos, level: depLevel(f), message: depMessage(f), code: f.cve, pkg: f.package,
      upgrade: upgradeCommand(f), exploited: !!f.known_exploited });
  }
  return out;
}

export function countDeps(doc: DepsDoc): { exploited: number; total: number } {
  const v = doc.vulnerable || [];
  return { exploited: v.filter(f => f.known_exploited).length, total: v.length };
}

/** SARIF 2.1.0 -> diagnostics data. Results without a location are skipped. */
export function sarifToDiagnostics(sarif: any): DiagData[] {
  const out: DiagData[] = [];
  const results = sarif?.runs?.[0]?.results;
  if (!Array.isArray(results)) return out;
  for (const r of results) {
    const pl = r?.locations?.[0]?.physicalLocation;
    const uri = pl?.artifactLocation?.uri;
    if (!uri) continue;
    const line = Math.max(0, (pl?.region?.startLine ?? 1) - 1);
    const column = Math.max(0, (pl?.region?.startColumn ?? 1) - 1);
    const endColumn = pl?.region?.endColumn ? Math.max(column + 1, pl.region.endColumn - 1) : column + 1;
    const level: Level = r.level === 'error' ? 'error' : r.level === 'note' || r.level === 'none' ? 'info' : 'warning';
    out.push({ file: uri, line, column, endColumn, level, code: r.ruleId, message: r?.message?.text ?? r.ruleId ?? 'phpwarden finding' });
  }
  return out;
}

/** Heuristic: did the CLI reject the `code` subcommand (older phpwarden)? */
export function looksLikeMissingSubcommand(stderr: string): boolean {
  return /invalid choice: 'code'|unrecognized arguments|argument cmd: invalid choice/i.test(stderr);
}

/** Split the `phpwarden.path` setting into executable + leading args (supports `python3 phpwarden.pyz`). */
export function splitCommand(path: string): { cmd: string; args: string[] } {
  const toks = (path || 'phpwarden').match(/"[^"]*"|'[^']*'|\S+/g) ?? ['phpwarden'];
  const clean = toks.map(t => t.replace(/^["']|["']$/g, ''));
  return { cmd: clean[0], args: clean.slice(1) };
}
