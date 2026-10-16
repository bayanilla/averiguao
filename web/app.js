'use strict';
/* Múcaro | Averiguao UI. All data is rendered with textContent; no HTML is built from strings. */

const $ = id => document.getElementById(id);
const PAGE = 50;
const POLL_MS = 2500;
const ACTIVE = new Set(['queued', 'running', 'pausing']);
const THEMES = new Set(['soc', 'nord', 'contrast', 'matrix', 'mucaro', 'notebook', 'amber']);
const LIMIT_FIELDS = ['max_depth', 'max_hostnames', 'max_addresses', 'max_queries', 'max_seconds', 'max_prefix_addresses'];
const QUEUE_LABEL = { known: 'Known', new: 'New', unexplained: 'Unexplained', third_party: 'Third-party' };
const ROLE_LABEL = { first_party: 'First party', third_party: 'Third party', unresolved: 'Unresolved' };
const DIM_LABEL = { ownership: 'Ownership', operational_control: 'Operational control', hosting: 'Hosting', service_association: 'Service association' };
const DIM_SHORT = { ownership: 'O', operational_control: 'C', hosting: 'H', service_association: 'S' };
const ASSESS_MARK = { supported: '+', contradicted: '−', unresolved: '?' };
const SOURCE_LABEL = { ct: 'Certificate Transparency', dns: 'DNS', rdap: 'RDAP', internetdb: 'InternetDB', scope: 'Approved scope' };
const PREDICATE_LABEL = {
  seed_is: 'approved seed',
  prefix_contains_ip: 'address inside the approved prefix, observed by InternetDB',
  certificate_mentions_hostname: 'named in a certificate logged for the domain',
  hostname_resolves_to_ip: 'resolves to (DNS)',
  ip_reports_hostname: 'InternetDB reports this hostname on the address'
};
const FLAG_HELP = {
  conflict: 'Sources disagree (for example, providers differ between addresses); both sides are kept.',
  inventory_match_indeterminate: 'Matches inventory only under a match rule that is switched off.',
  stale_evidence: 'Every observation expired before the run completed.',
  no_resolution: 'The hostname did not resolve to an address.',
  source_error: 'A source call about this asset failed; the picture may be incomplete.',
  potential_vulns: 'InternetDB lists potential vulnerabilities (not verified).',
  truncated_run: 'The run hit a limit; related assets may be missing.',
  empty_inventory: 'No inventory snapshot existed when the run completed.'
};

const state = {
  health: { demo: false },
  inventory: null,
  runs: [],
  runId: null,
  run: null,
  filters: { queue: '', type: '', flag: '', q: '', sort: 'rank' },
  offset: 0,
  total: 0,
  covOffset: 0,
  tab: 'findings',
  findingId: null,
  returnFocus: null,
  previewKey: null,
  pollTimer: null,
  findingsKey: null
};

/* ------------------------------------------------------------------ helpers */

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'text') node.textContent = String(value);
    else if (key === 'className') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function fill(target, ...nodes) { target.replaceChildren(...nodes.flat().filter(n => n !== null && n !== undefined && n !== false)); }

function number(value) { return new Intl.NumberFormat().format(value || 0); }

function when(iso) {
  if (!iso) return 'not reported';
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(iso);
  return match ? `${match[1]} ${match[2]} UTC` : String(iso);
}

async function request(path, options = {}) {
  const init = { method: options.method || 'GET', headers: {} };
  if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, init);
  let data = null;
  try { data = await response.json(); } catch (_) { data = null; }
  if (!response.ok) throw new Error((data && data.error) || `Request failed (${response.status})`);
  return data;
}

function setStatusText(target, text, kind = '') {
  target.replaceChildren(el('p', { className: kind ? `${kind}-text` : '', text }));
}

function runTitle(run) {
  if (!run) return 'Select a run';
  if (run.label) return run.label;
  const seeds = (run.config && run.config.seeds) || [];
  return seeds.length ? seeds.map(s => s.value).slice(0, 3).join(', ') + (seeds.length > 3 ? ` +${seeds.length - 3}` : '') : run.id.slice(0, 8);
}

function statusPill(status) { return el('span', { className: `status status-${status}`, text: status }); }

function queuePill(queue) { return el('span', { className: `pill q-${queue}`, text: QUEUE_LABEL[queue] || queue }); }

/* ------------------------------------------------------------------ theme */

function initTheme() {
  let saved = 'soc';
  try { saved = localStorage.getItem('averiguao-theme') || saved; } catch (_) { /* storage unavailable */ }
  if (!THEMES.has(saved)) saved = 'soc';
  document.documentElement.dataset.theme = saved;
  $('theme').value = saved;
  $('theme').addEventListener('change', event => {
    const theme = event.target.value;
    if (!THEMES.has(theme)) return;
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('averiguao-theme', theme); } catch (_) { /* theme still applies */ }
  });
}

/* ------------------------------------------------------------------ health and demo */

async function loadHealth() {
  try {
    state.health = await request('/api/health');
  } catch (_) { return; }
  if (!state.health.demo) return;
  $('demo-banner').classList.remove('hidden');
  const config = state.health.demo_config;
  if (config && !$('seeds').value) fillForm(config);
}

function fillForm(config) {
  $('seeds').value = Array.isArray(config.seeds) ? config.seeds.join('\n') : (config.seeds || '');
  $('approval-ref').value = config.approval_ref || '';
  $('org-names').value = Array.isArray(config.org_names) ? config.org_names.join(', ') : (config.org_names || '');
  $('run-label').value = config.label || '';
  for (const field of LIMIT_FIELDS) {
    if (config.limits && config.limits[field] !== undefined) $(`lim-${field}`).value = config.limits[field];
  }
  if (config.match_rules) {
    if ('prefix_containment' in config.match_rules) $('rule-prefix').checked = !!config.match_rules.prefix_containment;
    if ('domain_hierarchy' in config.match_rules) $('rule-domain').checked = !!config.match_rules.domain_hierarchy;
  }
}

/* ------------------------------------------------------------------ inventory */

async function loadInventory() {
  try {
    state.inventory = await request('/api/inventory');
  } catch (error) {
    setStatusText($('inv-summary'), error.message, 'error');
    return;
  }
  renderInventory();
}

function renderInventory() {
  const current = state.inventory && state.inventory.current;
  const target = $('inv-summary');
  if (!current) {
    target.replaceChildren(
      el('p', { className: 'warn-text', text: 'No inventory snapshot yet.' }),
      el('p', { className: 'subtle', text: 'Without one, nothing can be Known: every finding lands in New, Unexplained or Third-party.' }));
    $('inv-entries').classList.add('hidden');
    return;
  }
  const count = current.entries.length;
  const older = Math.max(0, (state.inventory.snapshots || []).length - 1);
  fill(target,
    el('p', {}, el('span', { className: 'inv-label', text: current.label || 'Unlabelled snapshot' })),
    el('p', { className: 'subtle', text: `${number(count)} ${count === 1 ? 'entry' : 'entries'} · as of ${when(current.as_of)}` }),
    el('p', { className: 'subtle mono', text: current.id }),
    older ? el('p', { className: 'subtle', text: `${older} earlier snapshot${older === 1 ? '' : 's'} kept.` }) : null);
  $('inv-entries').classList.remove('hidden');
  const body = $('inv-entries-body');
  body.replaceChildren();
  const shown = current.entries.slice(0, 500);
  for (const entry of shown) {
    body.append(el('tr', {}, el('td', { text: entry.kind === 'domain_tree' ? `*.${entry.value}` : entry.value }),
      el('td', { text: entry.kind }), el('td', { text: entry.label || '' })));
  }
  const note = $('inv-entries-note');
  note.textContent = count > shown.length ? `Showing the first ${shown.length} of ${number(count)} entries.` : '';
  note.classList.toggle('hidden', count <= shown.length);
}

async function saveInventory() {
  const status = $('inventory-state');
  const asOf = $('inventory-asof').value;
  try {
    const data = await request('/api/inventory', {
      method: 'POST',
      body: { csv: $('inventory-text').value, label: $('inventory-label').value, as_of: asOf ? `${asOf}T00:00:00+00:00` : null }
    });
    status.className = 'subtle';
    status.textContent = `Saved snapshot with ${number(data.entry_count)} entries. Reassess completed runs to use it.`;
    $('inventory-text').value = '';
    await loadInventory();
    if (state.run) renderRun();
  } catch (error) {
    status.className = 'subtle error-text';
    status.textContent = error.message;
  }
}

/* ------------------------------------------------------------------ new run form */

function formConfig() {
  const limits = {};
  for (const field of LIMIT_FIELDS) {
    const raw = $(`lim-${field}`).value.trim();
    if (raw !== '') limits[field] = Number(raw);
  }
  return {
    seeds: $('seeds').value,
    approval_ref: $('approval-ref').value.trim(),
    org_names: $('org-names').value,
    label: $('run-label').value.trim(),
    limits,
    match_rules: { prefix_containment: $('rule-prefix').checked, domain_hierarchy: $('rule-domain').checked }
  };
}

function formChanged() {
  if (state.previewKey !== JSON.stringify(formConfig())) {
    $('start').disabled = true;
  }
}

async function preview(event) {
  event.preventDefault();
  const target = $('preview-result');
  $('start').disabled = true;
  state.previewKey = null;
  const config = formConfig();
  $('approval-ref').setAttribute('aria-invalid', config.approval_ref ? 'false' : 'true');
  $('seeds').setAttribute('aria-invalid', config.seeds.trim() ? 'false' : 'true');
  if (!config.approval_ref) {
    setStatusText(target, 'An approval reference is required: name the ticket, letter or contract that authorizes this scope.', 'error');
    $('approval-ref').focus();
    return;
  }
  try {
    const data = await request('/api/preview', { method: 'POST', body: { config } });
    state.previewKey = JSON.stringify(config);
    $('start').disabled = false;
    const seeds = el('ul', {}, data.seeds.map(seed => el('li', {}, el('span', { className: 'mono', text: seed.value }), ` · ${seed.type}`)));
    const warnings = data.warnings.length
      ? el('ul', {}, data.warnings.map(text => el('li', { className: 'warn-text', text })))
      : null;
    fill(target,
      el('p', {}, `${data.seeds.length} seed${data.seeds.length === 1 ? '' : 's'} · about `,
        el('span', { className: 'estimate', text: number(data.estimated_queries) }), ' source queries'),
      seeds, warnings);
  } catch (error) {
    setStatusText(target, error.message, 'error');
  }
}

async function startRun() {
  if (!state.previewKey) return;
  $('start').disabled = true;
  try {
    const run = await request('/api/runs', { method: 'POST', body: { config: JSON.parse(state.previewKey) } });
    state.previewKey = null;
    setStatusText($('preview-result'), 'Run started.', '');
    await loadRuns();
    await selectRun(run.id, true);
  } catch (error) {
    setStatusText($('preview-result'), error.message, 'error');
    $('start').disabled = false;
  }
}

/* ------------------------------------------------------------------ runs list */

async function loadRuns() {
  const data = await request('/api/runs');
  state.runs = data.runs;
  renderRuns();
}

function renderRuns() {
  const target = $('runs');
  target.replaceChildren();
  if (!state.runs.length) { target.append(el('li', { className: 'muted', text: 'No runs yet.' })); return; }
  for (const run of state.runs) {
    const c = run.counts || {};
    const progress = ACTIVE.has(run.status) || run.status === 'paused'
      ? `tasks ${number(c.tasks_done)} done · ${number(c.tasks_pending)} pending`
      : `${number(c.findings)} findings · ${number(c.queue_new)} new · ${number(c.queue_unexplained)} unexplained`;
    const button = el('button', { type: 'button', className: 'run-item', 'aria-current': run.id === state.runId ? 'true' : 'false',
      onclick: () => selectRun(run.id, true) },
      el('strong', { text: runTitle(run) }),
      el('span', { className: 'run-row' }, statusPill(run.status), (run.truncated || []).length ? el('span', { className: 'flag flag-truncated_run', text: 'truncated' }) : null),
      el('small', { text: progress }),
      el('small', { text: `${when(run.created_at)} · ${run.id.slice(0, 8)}` }));
    target.append(el('li', {}, button));
  }
}

/* ------------------------------------------------------------------ selected run */

async function selectRun(id, focus = false) {
  closeDrawer(false);
  state.runId = id;
  state.offset = 0;
  state.covOffset = 0;
  state.findingsKey = null;
  state.filters = { queue: '', type: '', flag: '', q: '', sort: 'rank' };
  $('f-type').value = ''; $('f-flag').value = ''; $('f-q').value = ''; $('f-sort').value = 'rank';
  setTab('findings');
  try { history.replaceState(null, '', `#run=${id}`); } catch (_) { /* ignore */ }
  renderRuns();
  await refreshRun();
  await loadFindings();
  if (focus) $('run-card').focus();
  schedulePoll();
}

async function refreshRun() {
  if (!state.runId) return;
  try {
    state.run = await request(`/api/runs/${state.runId}`);
  } catch (error) {
    state.run = null;
    showActionMessage(error.message, true);
    return;
  }
  renderRun();
}

function showActionMessage(text, isError = false) {
  const target = $('action-message');
  target.textContent = text;
  target.className = `action-message${isError ? ' error-text' : ''}`;
  target.classList.toggle('hidden', !text);
}

function renderRun() {
  const run = state.run;
  if (!run) return;
  $('empty-state').classList.add('hidden');
  $('run-panel').classList.remove('hidden');
  $('run-actions').classList.remove('hidden');
  $('run-title').textContent = runTitle(run);
  const refs = [...new Set((run.config.seeds || []).map(s => s.approval_ref))];
  fill($('run-meta'), statusPill(run.status),
    el('span', { text: `Created ${when(run.created_at)}` }),
    el('span', { text: `${number(run.query_count)} queries` }),
    el('span', { text: `Approval: ${refs.join('; ')}` }),
    run.inventory_snapshot_id ? el('span', { className: 'mono', text: `Inventory ${run.inventory_snapshot_id}` }) : null);

  $('pause').classList.toggle('hidden', !['queued', 'running'].includes(run.status));
  $('resume').classList.toggle('hidden', !['paused', 'pausing'].includes(run.status));
  $('reassess').classList.toggle('hidden', run.status !== 'complete');
  for (const ext of ['json', 'csv', 'md']) {
    const link = $(`export-${ext}`);
    link.href = `/api/runs/${run.id}/export.${ext}`;
    link.classList.toggle('hidden', run.status !== 'complete');
  }

  renderWarnings(run);
  const c = run.counts || {};
  const done = c.tasks_done || 0;
  const pending = c.tasks_pending || 0;
  const fraction = run.status === 'complete' ? 1 : (done + pending ? done / (done + pending) : 0);
  $('progress').value = fraction;
  $('run-status-text').textContent = statusSentence(run);
  $('progress-text').textContent = `tasks ${number(done)} done · ${number(pending)} pending · ${number(c.assets)} assets`;

  const counts = { all: c.findings, new: c.queue_new, unexplained: c.queue_unexplained, third_party: c.queue_third_party, known: c.queue_known };
  for (const [key, value] of Object.entries(counts)) {
    document.querySelector(`[data-count="${key}"]`).textContent = number(value);
  }
  const hasPrefix = (run.config.seeds || []).some(seed => seed.type === 'prefix');
  $('tab-coverage').classList.toggle('hidden', !hasPrefix);
  if (!hasPrefix && state.tab === 'coverage') setTab('findings');
}

function statusSentence(run) {
  switch (run.status) {
    case 'queued': return 'Queued: waits for the active run to finish.';
    case 'running': return 'Running: discovery in progress.';
    case 'pausing': return 'Pausing after the current batch…';
    case 'paused': return 'Paused. Resume continues from the saved queue.';
    case 'complete': return `Complete ${when(run.finished_at)}.`;
    case 'failed': return 'Failed.';
    default: return run.status;
  }
}

function renderWarnings(run) {
  const items = [];
  const add = (title, text, kind = '') => items.push(el('p', { className: `warning ${kind}` }, el('strong', { text: title }), text));
  if (run.status === 'failed' || run.last_error) add(run.status === 'failed' ? 'Run failed.' : 'Note.', run.last_error || 'No detail recorded.', run.status === 'failed' ? 'danger' : 'info');
  for (const t of run.truncated || []) {
    add('Truncated.', `Limit ${t.limit} reached: ${number(t.omitted)} item(s) not recorded or not queried. ${t.detail || ''} Findings are usable but incomplete.`);
  }
  const failures = Object.entries(run.source_failures || {}).filter(([, n]) => n > 0);
  if (failures.length) {
    add('Source failures.', `${failures.map(([s, n]) => `${SOURCE_LABEL[s] || s}: ${number(n)}`).join(' · ')}. Affected findings carry the source_error flag.`);
  }
  const noInventory = !(state.inventory && state.inventory.current);
  if ((run.flags || []).includes('empty_inventory')) {
    add('Empty inventory.', 'No inventory snapshot existed when this run completed, so nothing is Known. Import one, then Reassess.');
  } else if (noInventory && run.status !== 'complete') {
    add('No inventory loaded.', 'Import a baseline before this run completes, or reassess afterwards; otherwise nothing can be Known.');
  }
  if (!(run.config.org_names || []).length) {
    add('No organization names.', 'IP ownership can never be supported in this run.', 'info');
  }
  const oos = Object.entries(run.out_of_scope || {});
  if (oos.length) {
    add('Scope boundary.', `Observed but not recorded (outside approved scope): ${oos.map(([r, n]) => `${r.replace(/_/g, ' ')} ${number(n)}`).join(' · ')}.`, 'info');
  }
  fill($('warnings'), items);
}

/* ------------------------------------------------------------------ findings table */

function findingsQuery() {
  const params = new URLSearchParams();
  const f = state.filters;
  if (f.queue) params.set('queue', f.queue);
  if (f.type) params.set('type', f.type);
  if (f.flag) params.set('flag', f.flag);
  if (f.q) params.set('q', f.q);
  params.set('sort', f.sort);
  params.set('offset', String(state.offset));
  params.set('limit', String(PAGE));
  return params.toString();
}

async function loadFindings() {
  if (!state.runId) return;
  const runId = state.runId;
  let data;
  try {
    data = await request(`/api/runs/${runId}/findings?${findingsQuery()}`);
  } catch (error) {
    $('findings').replaceChildren(el('tr', {}, el('td', { colspan: 7, className: 'error-text', text: error.message })));
    return;
  }
  if (runId !== state.runId) return;
  state.total = data.total;
  state.findingsKey = `${findingsQuery()}|${data.total}`;
  renderFindings(data.findings);
}

function assessBadges(finding, assessments) {
  const group = el('span', { className: 'assess-group' });
  for (const dim of Object.keys(DIM_SHORT)) {
    const a = assessments && assessments[dim];
    const value = a ? a.assessment : 'unresolved';
    const label = `${DIM_LABEL[dim]}: ${value}${a && a.value ? ` (${a.value})` : ''}`;
    group.append(el('span', { className: `assess ${value}`, title: label, 'aria-label': label },
      el('span', { className: 'dim', text: DIM_SHORT[dim], 'aria-hidden': 'true' }), el('span', { text: ASSESS_MARK[value], 'aria-hidden': 'true' })));
  }
  return group;
}

function renderFindings(findings) {
  const body = $('findings');
  body.replaceChildren();
  if (!findings.length) {
    const run = state.run;
    const message = run && ACTIVE.has(run.status)
      ? 'Findings are computed when discovery completes.'
      : (Object.values(state.filters).some(v => v && v !== 'rank') ? 'No findings match these filters.' : 'No findings for this run.');
    body.append(el('tr', {}, el('td', { colspan: 7, className: 'muted', text: message })));
  }
  for (const f of findings) {
    const assessments = f.assessments || null;
    const button = el('button', { type: 'button', className: 'value-button', text: f.value, 'aria-haspopup': 'dialog',
      onclick: event => openFinding(f.id, event.currentTarget) });
    const flags = el('td', { 'data-label': 'Flags' }, f.flags.length ? f.flags.map(flag => el('span', { className: `flag flag-${flag}`, text: flag.replace(/_/g, ' '), title: FLAG_HELP[flag] || flag })) : el('span', { className: 'muted', text: '—' }));
    const row = el('tr', { 'data-finding': f.id, 'aria-selected': f.id === state.findingId ? 'true' : 'false' },
      el('td', { 'data-label': 'Value' }, button),
      el('td', { 'data-label': 'Type', text: f.asset_type }),
      el('td', { 'data-label': 'Queue' }, queuePill(f.queue)),
      el('td', { 'data-label': 'Role', text: ROLE_LABEL[f.role] || f.role }),
      el('td', { 'data-label': 'O·C·H·S' }, assessBadges(f, assessments)),
      flags,
      el('td', { 'data-label': 'Rank', className: 'num', text: Number(f.rank).toFixed(2) }));
    body.append(row);
  }
  const page = Math.floor(state.offset / PAGE) + 1;
  const pages = Math.max(1, Math.ceil(state.total / PAGE));
  $('page-label').textContent = `Page ${page} of ${pages} · ${number(state.total)} finding${state.total === 1 ? '' : 's'}`;
  $('prev').disabled = state.offset === 0;
  $('next').disabled = state.offset + PAGE >= state.total;
}

/* ------------------------------------------------------------------ coverage */

async function loadCoverage() {
  if (!state.runId) return;
  const data = await request(`/api/runs/${state.runId}/coverage?offset=${state.covOffset}&limit=100`);
  const body = $('coverage');
  body.replaceChildren();
  if (!data.coverage.length) body.append(el('tr', {}, el('td', { colspan: 4, className: 'muted', text: 'No addresses checked yet.' })));
  for (const row of data.coverage) {
    body.append(el('tr', {}, el('td', { text: row.ip }), el('td', { text: SOURCE_LABEL[row.source] || row.source }),
      el('td', { className: row.status === 'error' ? 'error-text' : '', text: row.status.replace('_', ' ') }), el('td', { text: when(row.retrieved_at) })));
  }
  const page = Math.floor(state.covOffset / 100) + 1;
  $('cov-page-label').textContent = `Page ${page} of ${Math.max(1, Math.ceil(data.total / 100))} · ${number(data.total)} checks`;
  $('cov-prev').disabled = state.covOffset === 0;
  $('cov-next').disabled = state.covOffset + 100 >= data.total;
}

function setTab(tab) {
  state.tab = tab;
  for (const name of ['findings', 'coverage']) {
    const selected = name === tab;
    $(`tab-${name}`).setAttribute('aria-selected', selected ? 'true' : 'false');
    $(`tab-${name}`).tabIndex = selected ? 0 : -1;
    $(`panel-${name}`).classList.toggle('hidden', !selected);
  }
  if (tab === 'coverage') loadCoverage().catch(error => showActionMessage(error.message, true));
}

/* ------------------------------------------------------------------ finding drawer */

function kv(pairs) {
  const list = el('dl', { className: 'kv' });
  for (const [label, value] of pairs) {
    if (value === undefined) continue;
    list.append(el('dt', { text: label }), el('dd', {}, value instanceof Node ? value : String(value === null ? 'not reported' : value)));
  }
  return list;
}

function evidenceCard(ev) {
  const validity = ev.valid_from || ev.valid_to ? `${when(ev.valid_from)} → ${when(ev.valid_to)}` : 'not reported by the source';
  return el('div', { className: 'evidence' },
    el('div', { className: 'evidence-title', text: `${SOURCE_LABEL[ev.source] || ev.source} · ${ev.id}` }),
    kv([
      ['Observed', when(ev.observed_at)],
      ['Validity', validity],
      ['Query', el('code', { text: ev.query })],
      ['Record id', ev.source_record_id || 'none'],
      ['Source URL', el('code', { text: ev.source_url || 'none' })],
      ['SHA-256', el('code', { text: ev.raw_sha256 || 'not stored' })],
      ...evidenceData(ev)
    ]));
}

/* The few source fields an analyst needs to read a hop; the full record is in the JSON export. */
function evidenceData(ev) {
  const d = ev.data || {};
  const list = value => (Array.isArray(value) && value.length ? value.join(', ') : undefined);
  const rows = [];
  if (ev.source === 'dns') {
    if (list(d.cnames)) rows.push(['CNAME chain', list(d.cnames)]);
    if (list(d.addresses)) rows.push(['Addresses', list(d.addresses)]);
  } else if (ev.source === 'rdap') {
    if (list(d.org_names) || d.network_name) rows.push(['Registrant', list(d.org_names) || d.network_name]);
    if (list(d.cidrs)) rows.push(['Network', list(d.cidrs)]);
  } else if (ev.source === 'internetdb') {
    if (list(d.ports)) rows.push(['Ports', list(d.ports)]);
    if (list(d.hostnames)) rows.push(['Hostnames', list(d.hostnames)]);
    if (list(d.vulns)) rows.push(['Potential vulns', list(d.vulns)]);
  } else if (ev.source === 'ct') {
    if (d.issuer) rows.push(['Issuer', d.issuer]);
    if (list(d.names)) rows.push(['Names', list(d.names)]);
  }
  if (d.status && d.status !== 'ok') rows.push(['Status', d.error ? `${d.status}: ${d.error}` : d.status]);
  return rows;
}

function nodeLine(node) {
  const label = node.type === 'seed' ? `${node.id} (${node.seed_type})` : node.type;
  return el('div', { className: 'hop-node' }, el('span', { className: 'node-type', text: label }), node.value);
}

function renderPath(path, finding) {
  const list = el('ol', { className: 'path', 'aria-label': 'Evidence path from seed to asset' });
  if (!path.length) {
    list.append(el('li', { className: 'hop' }, el('div', { className: 'muted', text: 'No path recorded.' })));
    return list;
  }
  const first = path[0];
  const seedHop = first.relationship.predicate === 'seed_is';
  list.append(el('li', { className: 'hop' }, nodeLine(first.subject),
    el('div', { className: 'hop-predicate', text: `approved seed · ${finding.seed_id}` }),
    seedHop ? first.evidence.map(evidenceCard) : null));
  for (const hop of seedHop ? path.slice(1) : path) {
    list.append(el('li', { className: 'hop' },
      el('div', { className: 'hop-predicate', text: `↳ ${PREDICATE_LABEL[hop.relationship.predicate] || hop.relationship.predicate} · depth ${hop.relationship.depth}` }),
      nodeLine(hop.object),
      hop.evidence.length ? hop.evidence.map(evidenceCard) : el('p', { className: 'muted', text: 'No evidence stored for this hop.' })));
  }
  return list;
}

function inventoryEntryText(match) {
  if (!match.entry_id) return 'none';
  const current = state.inventory && state.inventory.current;
  if (current && current.id === match.snapshot_id) {
    const entry = current.entries.find(e => e.id === match.entry_id);
    if (entry) return `${entry.kind === 'domain_tree' ? '*.' : ''}${entry.value}${entry.label ? ` (${entry.label})` : ''} · ${entry.id}`;
  }
  return match.entry_id;
}

async function openFinding(id, trigger) {
  state.returnFocus = trigger || null;
  state.findingId = id;
  for (const row of document.querySelectorAll('#findings tr[data-finding]')) {
    row.setAttribute('aria-selected', row.dataset.finding === id ? 'true' : 'false');
  }
  const drawer = $('drawer');
  const body = $('drawer-body');
  $('drawer-title').textContent = 'Loading…';
  body.replaceChildren();
  drawer.classList.remove('hidden');
  document.body.classList.add('drawer-open');
  let data;
  try {
    data = await request(`/api/runs/${state.runId}/findings/${encodeURIComponent(id)}`);
  } catch (error) {
    $('drawer-title').textContent = 'Could not load finding';
    body.replaceChildren(el('p', { className: 'error-text', text: error.message }));
    $('drawer-title').focus();
    return;
  }
  if (state.findingId !== id) return;
  const f = data.finding;
  $('drawer-eyebrow').textContent = `${f.asset_type.toUpperCase()} · FINDING`;
  $('drawer-title').textContent = f.value;

  const parts = [];
  parts.push(el('div', { className: 'summary-line' }, queuePill(f.queue), el('span', { className: 'pill', text: ROLE_LABEL[f.role] || f.role }),
    el('span', { className: 'muted', text: `rank ${Number(f.rank).toFixed(2)}` }),
    f.flags.map(flag => el('span', { className: `flag flag-${flag}`, text: flag.replace(/_/g, ' ') }))));
  const m = f.inventory_match;
  parts.push(kv([
    ['Inventory', `${m.status} · rule ${m.rule}`],
    ['Entry', inventoryEntryText(m)],
    ['Observed', `${when(f.first_observed)} → ${when(f.last_observed)}`],
    ['Finding id', el('code', { text: f.id })]
  ]));
  const expected = state.health.demo && state.health.demo_expected && state.health.demo_expected[f.asset_id];
  if (expected) {
    parts.push(el('p', { className: 'warning info' }, el('strong', { text: 'Demo world expects:' }), `${QUEUE_LABEL[expected.queue] || expected.queue} — ${expected.why}`));
  }

  parts.push(el('h3', { id: 'path-heading', text: 'Evidence path' }));
  parts.push(renderPath(data.path, f));

  parts.push(el('h3', { text: 'Assessments' }));
  const assertions = el('div', { className: 'assertions' });
  for (const a of data.assertions) {
    assertions.append(el('section', { className: `assertion ${a.assessment}`, 'aria-label': DIM_LABEL[a.dimension] },
      el('div', { className: 'assertion-head' }, el('span', { className: 'dimension', text: DIM_LABEL[a.dimension] || a.dimension }),
        el('span', { className: `assess ${a.assessment}`, text: `${ASSESS_MARK[a.assessment]} ${a.assessment}` })),
      el('p', { className: 'assertion-value', text: a.value ? a.value : 'no value' }),
      el('p', { className: 'assertion-rationale', text: a.rationale }),
      a.supporting_evidence_ids.length ? el('p', { className: 'assertion-ev', text: `Supporting: ${a.supporting_evidence_ids.join(', ')}` }) : null,
      a.contradicting_evidence_ids.length ? el('p', { className: 'assertion-ev', text: `Contradicting: ${a.contradicting_evidence_ids.join(', ')}` }) : null));
  }
  parts.push(assertions);

  if (f.flags.length) {
    parts.push(el('h3', { text: 'Flags' }));
    parts.push(el('ul', { className: 'flag-list' }, f.flags.map(flag => el('li', {}, el('strong', { text: flag.replace(/_/g, ' ') }), ` — ${FLAG_HELP[flag] || ''}`))));
  }

  const onPath = new Set(data.path.flatMap(hop => hop.evidence.map(ev => ev.id)));
  const other = data.evidence.filter(ev => !onPath.has(ev.id));
  if (other.length) {
    parts.push(el('h3', { text: 'Enrichment and assessment evidence' }));
    for (const ev of other) parts.push(evidenceCard(ev));
  }
  fill(body, parts);
  body.scrollTop = 0;
  $('drawer-title').focus();
}

function closeDrawer(restoreFocus = true) {
  const drawer = $('drawer');
  if (drawer.classList.contains('hidden')) return;
  drawer.classList.add('hidden');
  document.body.classList.remove('drawer-open');
  const id = state.findingId;
  state.findingId = null;
  for (const row of document.querySelectorAll('#findings tr[aria-selected="true"]')) row.setAttribute('aria-selected', 'false');
  if (!restoreFocus) return;
  let target = state.returnFocus;
  if (!target || !document.contains(target)) {
    const row = id && document.querySelector(`#findings tr[data-finding="${CSS.escape(id)}"] button`);
    target = row || $('run-card');
  }
  target.focus();
}

/* ------------------------------------------------------------------ run actions */

async function runAction(name) {
  if (!state.runId) return;
  showActionMessage(name === 'reassess' ? 'Reassessing…' : '');
  try {
    const data = await request(`/api/runs/${state.runId}/${name}`, { method: 'POST', body: {} });
    showActionMessage(name === 'reassess' ? 'Reassessed against the current inventory snapshot.' : `Run is ${data.status}.`);
    await Promise.all([refreshRun(), loadRuns()]);
    await loadFindings();
  } catch (error) {
    showActionMessage(error.message, true);
  }
  schedulePoll();
}

/* ------------------------------------------------------------------ polling */

function needsPolling() {
  if (state.run && ACTIVE.has(state.run.status)) return true;
  return state.runs.some(run => ACTIVE.has(run.status));
}

function schedulePoll() {
  if (state.pollTimer) return;
  if (!needsPolling()) return;
  state.pollTimer = setTimeout(poll, POLL_MS);
}

async function poll() {
  state.pollTimer = null;
  try {
    await loadRuns();
    if (state.runId) {
      const before = state.run ? `${state.run.status}|${(state.run.counts || {}).findings}|${state.run.inventory_snapshot_id}` : '';
      await refreshRun();
      const after = state.run ? `${state.run.status}|${(state.run.counts || {}).findings}|${state.run.inventory_snapshot_id}` : '';
      if (before !== after) await loadFindings();
      if (state.tab === 'coverage') await loadCoverage();
    }
  } catch (_) { /* keep the last view during a transient local error */ }
  schedulePoll();
}

/* ------------------------------------------------------------------ wiring */

function setQueue(queue) {
  state.filters.queue = queue;
  state.offset = 0;
  for (const chip of document.querySelectorAll('.chip')) {
    chip.setAttribute('aria-pressed', chip.dataset.queue === queue ? 'true' : 'false');
  }
  setTab('findings');
  loadFindings();
}

function wire() {
  $('inventory-file').addEventListener('change', async event => {
    const file = event.target.files && event.target.files[0];
    if (file) {
      $('inventory-text').value = await file.text();
      if (!$('inventory-label').value) $('inventory-label').value = file.name.replace(/\.[^.]+$/, '');
    }
  });
  $('save-inventory').addEventListener('click', saveInventory);
  $('run-form').addEventListener('submit', preview);
  $('run-form').addEventListener('input', formChanged);
  $('run-form').addEventListener('change', formChanged);
  $('start').addEventListener('click', startRun);
  $('pause').addEventListener('click', () => runAction('pause'));
  $('resume').addEventListener('click', () => runAction('resume'));
  $('reassess').addEventListener('click', () => runAction('reassess'));
  for (const chip of document.querySelectorAll('.chip')) chip.addEventListener('click', () => setQueue(chip.dataset.queue));
  $('f-type').addEventListener('change', event => { state.filters.type = event.target.value; state.offset = 0; loadFindings(); });
  $('f-flag').addEventListener('change', event => { state.filters.flag = event.target.value; state.offset = 0; loadFindings(); });
  $('f-sort').addEventListener('change', event => { state.filters.sort = event.target.value; state.offset = 0; loadFindings(); });
  let searchTimer = null;
  $('f-q').addEventListener('input', event => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filters.q = event.target.value.trim(); state.offset = 0; loadFindings(); }, 300);
  });
  $('prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - PAGE); loadFindings(); });
  $('next').addEventListener('click', () => { state.offset += PAGE; loadFindings(); });
  $('cov-prev').addEventListener('click', () => { state.covOffset = Math.max(0, state.covOffset - 100); loadCoverage(); });
  $('cov-next').addEventListener('click', () => { state.covOffset += 100; loadCoverage(); });
  $('tab-findings').addEventListener('click', () => setTab('findings'));
  $('tab-coverage').addEventListener('click', () => setTab('coverage'));
  $('drawer-close').addEventListener('click', () => closeDrawer());
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !$('drawer').classList.contains('hidden')) {
      event.preventDefault();
      closeDrawer();
    }
  });
}

async function init() {
  initTheme();
  wire();
  await loadHealth();
  await loadInventory();
  try {
    await loadRuns();
  } catch (error) {
    $('runs').replaceChildren(el('li', { className: 'error-text', text: error.message }));
    return;
  }
  const fromHash = /^#run=([0-9a-f]{32})$/.exec(location.hash);
  const wanted = fromHash && state.runs.some(run => run.id === fromHash[1]) ? fromHash[1] : (state.runs[0] && state.runs[0].id);
  if (wanted) await selectRun(wanted);
  schedulePoll();
}

init();
