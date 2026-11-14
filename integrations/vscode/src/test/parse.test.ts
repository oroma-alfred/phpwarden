import { test } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as p from '../parse';

const fx = (n: string) => fs.readFileSync(path.join(__dirname, '..', '..', 'test-fixtures', n), 'utf8');
const deps: p.DepsDoc = JSON.parse(fx('deps.json'));
const lock = fx('composer.lock');

test('findPackageLine locates "name" lines', () => {
  assert.deepStrictEqual(p.findPackageLine(lock, 'guzzlehttp/guzzle')?.line, 3);
  assert.strictEqual(p.findPackageLine(lock, 'monolog/monolog')?.line, 13);
  assert.strictEqual(p.findPackageLine(lock, 'nope/nope'), undefined);
  assert.strictEqual(p.findPackageLine(lock, 'guzzlehttp/guz'), undefined);
});

test('severity levels', () => {
  const [g, s, m, l] = deps.vulnerable;
  assert.strictEqual(p.depLevel(g), 'warning');
  assert.strictEqual(p.depLevel(s), 'error');   // KEV
  assert.strictEqual(p.depLevel(m), 'error');   // EPSS >= 0.5
  assert.strictEqual(p.depLevel(l), 'info');
});

test('message format and EXPLOITED tag', () => {
  assert.strictEqual(p.depMessage(deps.vulnerable[0]),
    'guzzlehttp/guzzle 7.4.0: CVE-2022-29248 Cross-domain cookie leakage — fixed in 6.5.6, 7.4.3');
  assert.match(p.depMessage(deps.vulnerable[1]), /^\[EXPLOITED\] symfony\/http-kernel/);
});

test('upgrade command picks lowest fixed > installed', () => {
  assert.strictEqual(p.upgradeCommand(deps.vulnerable[0]), 'composer require guzzlehttp/guzzle:^7.4.3');
  assert.strictEqual(p.pickFixed('v5.4.1', ['6.2.6', '5.4.20']), '5.4.20');
  assert.strictEqual(p.upgradeCommand(deps.vulnerable[3]), undefined);
  assert.ok(p.compareVersions('1.10.0', '1.9.9') > 0);
});

test('depsToDiagnostics + minSeverity', () => {
  const all = p.depsToDiagnostics(deps, lock, 'low');
  assert.strictEqual(all.length, 4);
  assert.strictEqual(all[3].line, 0); // psr/log not in lock -> line 0 fallback
  const high = p.depsToDiagnostics(deps, lock, 'high');
  assert.deepStrictEqual(high.map(d => d.pkg), ['guzzlehttp/guzzle', 'symfony/http-kernel', 'monolog/monolog']);
  assert.deepStrictEqual(p.countDeps(deps), { exploited: 1, total: 4 });
});

test('sarifToDiagnostics', () => {
  const d = p.sarifToDiagnostics(JSON.parse(fx('code.sarif')));
  assert.strictEqual(d.length, 2);
  assert.deepStrictEqual([d[0].file, d[0].line, d[0].column, d[0].level, d[0].code], ['src/db.php', 11, 4, 'error', 'PHPW-SQLI']);
  assert.deepStrictEqual([d[1].line, d[1].column, d[1].level], [2, 0, 'info']);
  assert.deepStrictEqual(p.sarifToDiagnostics({}), []);
});

test('splitCommand and missing-subcommand detection', () => {
  assert.deepStrictEqual(p.splitCommand('python3 "/a b/phpwarden.pyz"'), { cmd: 'python3', args: ['/a b/phpwarden.pyz'] });
  assert.deepStrictEqual(p.splitCommand('phpwarden'), { cmd: 'phpwarden', args: [] });
  assert.ok(p.looksLikeMissingSubcommand("phpwarden: error: argument cmd: invalid choice: 'code' (choose from ...)"));
});
