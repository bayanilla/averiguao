// End-to-end UI check against the demo world (no network).
// Run: NODE_PATH=$(npm root -g) node tests/e2e/test_ui.mjs
// Screenshots go to /tmp/claude-0/e2e/*.png.
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SHOTS = '/tmp/claude-0/e2e';
mkdirSync(SHOTS, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), 'averiguao-e2e-'));

let failures = 0;
function check(condition, message) {
  if (condition) console.log(`ok   ${message}`);
  else { failures += 1; console.log(`FAIL ${message}`); }
}

function startServer() {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', ['averiguao.py', '--demo', '--port', '0', '--data-dir', dataDir], { cwd: ROOT });
    let out = '';
    const timer = setTimeout(() => reject(new Error(`server did not start: ${out}`)), 15000);
    child.stdout.on('data', chunk => {
      out += chunk;
      const match = /http:\/\/127\.0\.0\.1:(\d+)\/\?token=[\w-]+/.exec(out);
      if (match) { clearTimeout(timer); resolve({ child, url: match[0] }); }
    });
    child.stderr.on('data', chunk => { out += chunk; });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`server exited ${code}: ${out}`)); });
  });
}

async function inViewport(page, selector) {
  await page.evaluate(() => Promise.all(document.getAnimations().map(a => a.finished)));
  return page.evaluate(sel => {
    const node = document.querySelector(sel);
    if (!node) return false;
    const r = node.getBoundingClientRect();
    return r.height > 0 && r.top >= 0 && r.top < window.innerHeight && r.left >= 0 && r.right <= window.innerWidth + 1;
  }, selector);
}

const { child, url } = await startServer();
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const problems = [];
  page.on('console', msg => { if (msg.type() === 'error') problems.push(msg.text()); });
  page.on('pageerror', err => problems.push(String(err)));

  await page.goto(url);
  await page.waitForSelector('#demo-banner:not(.hidden)');
  check(await page.isVisible('#demo-banner'), 'demo banner is visible');
  check((await page.textContent('#demo-banner')).includes('Demo data — synthetic world, no network'), 'demo banner text');
  check((await page.inputValue('#seeds')).includes('example.com'), 'form pre-filled with DEMO_CONFIG');
  await page.waitForSelector('#inv-summary .inv-label');
  check((await page.textContent('#inv-summary')).includes('3 entries'), 'demo inventory snapshot preloaded');

  await page.click('#preview');
  await page.waitForSelector('#preview-result .estimate');
  check(!(await page.isDisabled('#start')), 'start enabled after preview');
  await page.screenshot({ path: join(SHOTS, '01-preview.png'), fullPage: false });
  await page.click('#start');

  await page.waitForFunction(() => {
    const s = document.querySelector('#run-meta .status');
    return s && s.textContent === 'complete';
  }, null, { timeout: 60000 });
  check(true, 'run completed');
  await page.waitForFunction(() => document.querySelectorAll('#findings tr[data-finding]').length > 0);
  const allCount = Number((await page.textContent('[data-count="all"]')).replace(/\D/g, ''));
  check(allCount > 0, `findings counted (${allCount})`);
  check(await page.isVisible('#warnings .warning'), 'warning area shows source failures / scope notes');
  await page.screenshot({ path: join(SHOTS, '02-run-complete.png'), fullPage: true });

  await page.click('.chip[data-queue="new"]');
  const newCount = Number((await page.textContent('[data-count="new"]')).replace(/\D/g, ''));
  await page.waitForFunction(n => document.querySelectorAll('#findings tr[data-finding]').length === Math.min(n, 50), newCount);
  const queues = await page.$$eval('#findings .pill[class*="q-"]', nodes => nodes.map(n => n.textContent));
  check(queues.length === newCount && queues.every(q => q === 'New'), `New chip filters to ${newCount} New findings`);
  check((await page.getAttribute('.chip[data-queue="new"]', 'aria-pressed')) === 'true', 'New chip is pressed');

  const firstButton = page.locator('#findings .value-button').first();
  const value = await firstButton.textContent();
  await firstButton.click();
  await page.waitForFunction(v => document.querySelector('#drawer-title').textContent === v, value);
  await page.waitForSelector('#drawer .path .hop');
  check(await inViewport(page, '#drawer .path'), 'evidence path visible in the viewport');
  check(await inViewport(page, '#drawer'), 'drawer is beside the table, inside the viewport');
  check((await page.$$('#drawer .assertion')).length === 4, 'four assertions shown');
  check((await page.textContent('#drawer .path')).includes('example.com') || (await page.textContent('#drawer .path')).includes('198.51.100'), 'path starts from a seed');
  check(await page.evaluate(() => document.activeElement && document.activeElement.id === 'drawer-title'), 'focus moved into drawer');
  check(await inViewport(page, '#findings'), 'table still visible next to drawer');
  await page.screenshot({ path: join(SHOTS, '03-drawer.png'), fullPage: false });
  await page.keyboard.press('Escape');
  check(await page.isHidden('#drawer'), 'Escape closes drawer');
  check(await page.evaluate(() => document.activeElement && document.activeElement.classList.contains('value-button')), 'focus returned to the row');

  // Third-party finding with a CNAME and a coverage tab.
  await page.click('.chip[data-queue="third_party"]');
  await page.waitForFunction(() => [...document.querySelectorAll('#findings .pill[class*="q-"]')].every(n => n.textContent === 'Third-party'));
  await page.locator('#findings .value-button').first().click();
  await page.waitForSelector('#drawer .path .hop');
  await inViewport(page, '#drawer');
  await page.screenshot({ path: join(SHOTS, '04-drawer-third-party.png'), fullPage: false });
  await page.keyboard.press('Escape');
  await page.click('#tab-coverage');
  await page.waitForFunction(() => document.querySelectorAll('#coverage tr').length > 1);
  check(true, 'coverage tab lists prefix checks');
  await page.screenshot({ path: join(SHOTS, '05-coverage.png'), fullPage: false });

  const exportStatus = await page.evaluate(async () => {
    const href = document.querySelector('#export-md').getAttribute('href');
    const r = await fetch(href);
    return [r.status, r.headers.get('content-disposition')];
  });
  check(exportStatus[0] === 200 && /attachment/.test(exportStatus[1]), 'Markdown export downloads');

  // Narrow phone width.
  const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  const mobile = await phone.newPage();
  mobile.on('pageerror', err => problems.push(String(err)));
  await mobile.goto(url);
  await mobile.waitForFunction(() => document.querySelectorAll('#findings tr[data-finding]').length > 0);
  const overflow = await mobile.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(overflow <= 0, `no horizontal scroll at 390px (overflow ${overflow}px)`);
  await mobile.screenshot({ path: join(SHOTS, '06-mobile.png'), fullPage: true });
  await mobile.locator('#findings .value-button').first().click();
  await mobile.waitForSelector('#drawer .path .hop');
  check(await inViewport(mobile, '#drawer .path'), 'path visible in drawer at 390px');
  const drawerOverflow = await mobile.evaluate(() => document.querySelector('#drawer-body').scrollWidth - document.querySelector('#drawer-body').clientWidth);
  check(drawerOverflow <= 0, `drawer has no horizontal scroll at 390px (${drawerOverflow}px)`);
  await mobile.screenshot({ path: join(SHOTS, '07-mobile-drawer.png'), fullPage: false });

  // A light theme renders too.
  await page.selectOption('#theme', 'notebook');
  await page.click('.chip[data-queue=""]');
  await page.screenshot({ path: join(SHOTS, '08-notebook-theme.png'), fullPage: false });

  check(problems.length === 0, `no console errors or CSP violations${problems.length ? ': ' + problems.join(' | ') : ''}`);
} catch (error) {
  failures += 1;
  console.log(`FAIL ${error.stack || error}`);
} finally {
  await browser.close();
  child.kill('SIGINT');
  rmSync(dataDir, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : 'all e2e checks passed');
process.exit(failures ? 1 : 0);
