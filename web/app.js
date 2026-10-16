const $ = id => document.getElementById(id);
const themes = new Set(['soc', 'nord', 'contrast', 'matrix', 'mucaro', 'notebook', 'amber']);
let savedTheme = 'soc';
try { savedTheme = localStorage.getItem('averiguao-theme') || savedTheme; } catch (_) { /* Storage may be unavailable. */ }
if (!themes.has(savedTheme)) savedTheme = 'soc';
document.documentElement.dataset.theme = savedTheme;
$('theme').value = savedTheme;
$('theme').addEventListener('change', event => {
  const theme = event.target.value;
  if (!themes.has(theme)) return;
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('averiguao-theme', theme); } catch (_) { /* Theme still applies to this page. */ }
});
let selectedJob = null;
let currentOffset = 0;
let currentRows = [];
let previewCidr = null;

function number(value) { return new Intl.NumberFormat().format(value || 0); }
function node(tag, text, className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
}
async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function setMessage(id, value, isError = false) {
  const target = $(id);
  target.textContent = value;
  target.style.color = isError ? '#a13b3b' : '';
}
async function saveInventory() {
  try {
    const data = await request('/api/inventory', { method: 'POST', body: JSON.stringify({ csv: $('inventory-text').value }) });
    setMessage('inventory-state', `${number(data.count)} inventory entries saved.`);
    if (selectedJob) await showJob(selectedJob);
  } catch (error) { setMessage('inventory-state', error.message, true); }
}
async function previewSeed() {
  previewCidr = null;
  $('start').disabled = true;
  try {
    const data = await request('/api/preview', { method: 'POST', body: JSON.stringify({ seed: $('seed').value }) });
    previewCidr = data.cidr;
    $('start').disabled = false;
    $('preview-result').textContent = `${data.cidr} contains ${number(data.addresses)} IPv4 addresses. Each will receive one InternetDB lookup; large jobs may take a long time and can be paused or resumed.`;
    $('preview-result').classList.remove('muted');
  } catch (error) { setMessage('preview-result', error.message, true); }
}
async function startJob() {
  if (!previewCidr) return;
  $('start').disabled = true;
  try {
    const job = await request('/api/jobs', { method: 'POST', body: JSON.stringify({ seed: previewCidr }) });
    await loadJobs();
    await showJob(job.id);
  } catch (error) { setMessage('preview-result', error.message, true); }
  finally { $('start').disabled = false; }
}
async function loadJobs() {
  const data = await request('/api/jobs');
  const target = $('jobs');
  target.replaceChildren();
  if (!data.jobs.length) { target.append(node('p', 'No jobs yet.', 'muted')); return; }
  for (const job of data.jobs) {
    const button = node('button', undefined, `job-item${job.id === selectedJob ? ' selected' : ''}`);
    button.append(node('strong', job.seed_cidr), node('small', `${job.status} · ${number(job.next_offset)} / ${number(job.total)}`));
    button.addEventListener('click', () => showJob(job.id));
    target.append(button);
  }
}
async function showJob(id) {
  selectedJob = id;
  currentOffset = 0;
  await refreshJob();
  await loadResults();
  await loadJobs();
}
async function refreshJob() {
  if (!selectedJob) return;
  const job = await request(`/api/jobs/${selectedJob}`);
  $('empty-state').classList.add('hidden');
  $('job-panel').classList.remove('hidden');
  $('job-actions').classList.remove('hidden');
  $('job-title').textContent = job.seed_cidr;
  $('checked').textContent = `${number(job.next_offset)} / ${number(job.total)}`;
  $('found').textContent = number(job.found);
  $('no-record').textContent = number(job.empty);
  $('errors').textContent = number(job.errors);
  const percent = job.total ? Math.min(100, 100 * job.next_offset / job.total) : 0;
  $('progress-bar').style.width = `${percent}%`;
  $('progress-text').textContent = `${percent.toFixed(percent < 1 ? 2 : 1)}%`;
  $('job-status').textContent = job.status === 'running' ? 'Running · InternetDB observations are being collected' : job.status;
  $('pause').classList.toggle('hidden', job.status !== 'running');
  $('resume').classList.toggle('hidden', job.status !== 'paused');
  $('csv-link').href = `/api/jobs/${selectedJob}/export.csv`;
  $('json-link').href = `/api/jobs/${selectedJob}/export.json`;
  const warning = job.last_error || (job.status !== 'complete' ? 'This is a partial result. Unchecked addresses have unknown exposure.' : 'A missing InternetDB record does not prove an address has no exposed services.');
  $('job-warning').textContent = warning;
  $('job-warning').classList.remove('hidden');
}
async function loadResults() {
  if (!selectedJob) return;
  const data = await request(`/api/jobs/${selectedJob}/results?offset=${currentOffset}&limit=100`);
  currentRows = data.results;
  const target = $('results');
  target.replaceChildren();
  if (!currentRows.length) {
    const row = node('tr'); const cell = node('td', 'No stored records in this portion yet. InternetDB may have no record for checked addresses.', 'muted');
    cell.colSpan = 5; row.append(cell); target.append(row);
  }
  currentRows.forEach((result, index) => {
    const row = node('tr');
    const ports = result.payload?.ports || [];
    const inventory = node('span', result.inventory_status === 'known' ? 'Known' : 'Unaccounted', `pill ${result.inventory_status}`);
    const inventoryCell = node('td'); inventoryCell.append(inventory);
    const details = node('button', 'Inspect', 'details-button');
    details.addEventListener('click', () => showDetail(index));
    const detailCell = node('td'); detailCell.append(details);
    row.append(node('td', result.ip), node('td', result.status === 'error' ? 'Source error' : ports.length ? ports.join(', ') : 'Not reported'),
               inventoryCell, node('td', result.retrieved_at.replace('T', ' ').slice(0, 19) + ' UTC'), detailCell);
    target.append(row);
  });
  $('page-label').textContent = `Page ${Math.floor(currentOffset / 100) + 1}`;
  $('prev').disabled = currentOffset === 0;
  const storedCount = Number($('found').textContent.replaceAll(',', '')) + Number($('errors').textContent.replaceAll(',', ''));
  $('next').disabled = currentOffset + currentRows.length >= storedCount;
  $('detail').classList.add('hidden');
}
function showDetail(index) {
  const result = currentRows[index];
  const detail = $('detail');
  detail.replaceChildren();
  detail.append(node('h3', `${result.ip} · ${result.status === 'found' ? 'InternetDB record' : 'Source error'}`));
  const list = node('dl');
  const fields = [
    ['Seed path', `${$('job-title').textContent} → ${result.ip}`],
    ['Source', result.source],
    ['Source URL', result.source_url],
    ['Response SHA-256', result.payload?._response_sha256 || 'Not available'],
    ['Retrieved', result.retrieved_at],
    ['Source scan time', 'Not reported by InternetDB'],
    ['Inventory match', result.inventory_match ? `${result.inventory_match.cidr}${result.inventory_match.label ? ` · ${result.inventory_match.label}` : ''}` : 'None'],
    ['Ports', (result.payload?.ports || []).join(', ') || 'Not reported'],
    ['Hostnames', (result.payload?.hostnames || []).join(', ') || 'Not reported'],
    ['Software clues', (result.payload?.cpes || []).join(', ') || 'Not reported'],
    ['Tags', (result.payload?.tags || []).join(', ') || 'Not reported'],
    ['Potential CVEs', (result.payload?.vulns || []).join(', ') || 'Not reported']
  ];
  for (const [label, value] of fields) list.append(node('dt', label), node('dd', value));
  detail.append(list);
  detail.classList.remove('hidden');
}
async function action(name) {
  if (!selectedJob) return;
  try { await request(`/api/jobs/${selectedJob}/${name}`, { method: 'POST', body: '{}' }); await refreshJob(); await loadJobs(); }
  catch (error) { setMessage('job-warning', error.message, true); }
}
async function initialize() {
  $('inventory-file').addEventListener('change', async event => {
    const file = event.target.files?.[0]; if (file) $('inventory-text').value = await file.text();
  });
  $('save-inventory').addEventListener('click', saveInventory);
  $('preview').addEventListener('click', previewSeed);
  $('seed').addEventListener('input', () => { previewCidr = null; $('start').disabled = true; });
  $('start').addEventListener('click', startJob);
  $('pause').addEventListener('click', () => action('pause'));
  $('resume').addEventListener('click', () => action('resume'));
  $('prev').addEventListener('click', async () => { currentOffset = Math.max(0, currentOffset - 100); await loadResults(); });
  $('next').addEventListener('click', async () => { currentOffset += 100; await loadResults(); });
  try {
    const inventory = await request('/api/inventory');
    setMessage('inventory-state', `${number(inventory.entries.length)} inventory entries loaded.`);
    const jobs = await request('/api/jobs');
    if (jobs.jobs.length) { await showJob(jobs.jobs[0].id); } else { await loadJobs(); }
  } catch (error) { setMessage('inventory-state', error.message, true); }
  setInterval(async () => {
    try {
      await loadJobs();
      if (selectedJob) {
        const previousCount = Number($('found').textContent.replaceAll(',', '')) + Number($('errors').textContent.replaceAll(',', ''));
        await refreshJob();
        const latestCount = Number($('found').textContent.replaceAll(',', '')) + Number($('errors').textContent.replaceAll(',', ''));
        if (currentOffset === 0 && previousCount !== latestCount && $('detail').classList.contains('hidden')) await loadResults();
      }
    } catch (_) { /* Keep the last visible result during a transient local error. */ }
  }, 3000);
}
initialize();
