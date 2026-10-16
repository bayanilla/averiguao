// Browser probe: hostile source data (RDAP names, InternetDB cpes/tags/vulns, run label, approval ref, inventory
// labels) must render as text. Fails if any injected script runs, any dialog opens, or the page tries to reach a
// host other than the local server.
// Run from the repo root: NODE_PATH=$(npm root -g) node tests/security/xss_probe.mjs
import { spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let failures = 0;
function check(condition, message) {
  if (condition) console.log(`ok   ${message}`);
  else { failures += 1; console.log(`FAIL ${message}`); }
}

function startServer() {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', ['-m', 'tests.security.serve_hostile'], { cwd: ROOT });
    let out = '';
    const timer = setTimeout(() => reject(new Error(`server did not start: ${out}`)), 30000);
    child.stdout.on('data', chunk => {
      out += chunk;
      const m = /READY (http:\/\/127\.0\.0\.1:\d+\/\?token=[\w-]+) ([0-9a-f]{32})/.exec(out);
      if (m) { clearTimeout(timer); resolve({ child, url: m[1], runId: m[2] }); }
    });
    child.stderr.on('data', chunk => { out += chunk; });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`server exited ${code}: ${out}`)); });
  });
}

const { child, url, runId } = await startServer();
const origin = new URL(url).origin;
const browser = await chromium.launch();
try {
  const context = await browser.newContext();
  const foreign = [];
  const dialogs = [];
  const errors = [];
  await context.route('**/*', route => {
    const u = route.request().url();
    if (!u.startsWith(origin) && !u.startsWith('data:') && !u.startsWith('blob:')) { foreign.push(u); return route.abort(); }
    return route.continue();
  });
  const page = await context.newPage();
  page.on('dialog', d => { dialogs.push(d.message()); d.dismiss(); });
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto(`${url}#run=${runId}`);
  await page.waitForFunction(() => document.querySelectorAll('#findings tr[data-finding]').length > 0, null, { timeout: 20000 });
  // Open the inventory entries and every finding drawer.
  await page.evaluate(() => { const d = document.querySelector('#inv-entries'); if (d) d.open = true; });
  const count = await page.locator('#findings .value-button').count();
  for (let i = 0; i < count; i += 1) {
    await page.locator('#findings .value-button').nth(i).click();
    await page.waitForSelector('#drawer .assertion', { timeout: 10000 });
    await page.keyboard.press('Escape');
  }
  await page.click('#tab-coverage').catch(() => {});
  await page.waitForTimeout(500);
  const pwned = await page.evaluate(() => window.__pwned);
  const bodyText = await page.evaluate(() => document.body.innerText);
  const injectedNodes = await page.evaluate(() => document.querySelectorAll('img[src="x"], img[onerror], script:not([src="/app.js"])').length);
  check(pwned === undefined, `no injected script executed (window.__pwned=${pwned})`);
  check(dialogs.length === 0, `no dialogs (${dialogs.join(' | ')})`);
  check(foreign.length === 0, `no request left the local origin (${foreign.join(', ')})`);
  check(injectedNodes === 0, `no injected element in the DOM (${injectedNodes})`);
  check(bodyText.includes('onerror='), 'hostile strings are shown as literal text');
  check(errors.length === 0, `no page errors (${errors.join(' | ')})`);
} finally {
  await browser.close();
  child.kill();
}
if (failures) { console.log(`${failures} failure(s)`); process.exit(1); }
console.log('xss probe passed');
