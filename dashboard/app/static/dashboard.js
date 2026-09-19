const state = { data: window.__INITIAL_DATA__ || {}, runId: null };

const $ = (id) => document.getElementById(id);
const number = (value, digits = 2) => value == null ? '—' : Number(value).toFixed(digits);
const ms = (value) => value == null ? '—' : `${number(value / 1000)} ms`;
const bytes = (value) => value == null ? '—' : `${Math.round(value).toLocaleString()} B`;

function metric(data, mode, name, stat = 'p50') {
  return data.summary?.modes?.[mode]?.metrics?.[name]?.[stat] ?? null;
}

function drawBars(targetId, rows, formatter) {
  const target = $(targetId);
  const values = rows.map((row) => row.value || 0);
  const max = Math.max(...values, 1);
  target.classList.remove('empty-chart');
  target.innerHTML = `<div class="chart-legend"><span><i class="legend-dot classical"></i>Classical</span><span><i class="legend-dot hybrid"></i>Hybrid</span><span><i class="legend-dot hybrid_p256"></i>Hybrid P256</span></div>` + rows.map((row) => `
    <div class="bar-row"><span>${row.label}</span><div class="bar-track"><div class="bar ${row.mode}" style="width:${Math.max(1, row.value / max * 100)}%"></div></div><b>${formatter(row.value)}</b></div>`).join('');
}

function render(data) {
  state.data = data;
  state.runId = data.selected_run;
  const select = $('run-select');
  select.innerHTML = data.runs.length ? data.runs.map((run) => `<option value="${run.id}" ${run.id === data.selected_run ? 'selected' : ''}>${run.id} · ${run.samples || 0} samples</option>`).join('') : '<option value="">No benchmark runs</option>';
  if (data.selected_run) select.value = data.selected_run;
  $('selected-run').textContent = data.selected_run || 'No data yet';
  $('csv-link').href = data.selected_run ? `/api/results.csv?run_id=${encodeURIComponent(data.selected_run)}` : '/api/results.csv';

  for (const mode of ['classical', 'hybrid', 'hybrid_p256']) {
    $(`${mode}-p50`).textContent = ms(metric(data, mode, 'client_handshake_us'));
    $(`${mode}-p95`).textContent = ms(metric(data, mode, 'client_handshake_us', 'p95'));
    $(`${mode}-server`).textContent = ms(metric(data, mode, 'server_handshake_us'));
    $(`${mode}-samples`).textContent = data.summary?.modes?.[mode]?.successes ?? 0;
  }
  const delta = data.summary?.comparison?.client_handshake_us;
  $('delta-value').textContent = delta?.delta == null ? '—' : `${delta.delta >= 0 ? '+' : ''}${ms(delta.delta)}`;
  $('delta-percent').textContent = delta?.percent == null ? 'Waiting for both modes' : `${delta.percent >= 0 ? '+' : ''}${number(delta.percent, 1)}% versus X25519 median`;

  if (data.recent.length) {
    drawBars('latency-chart', [
      { label: 'p50 C', mode: 'classical', value: metric(data, 'classical', 'client_handshake_us') },
      { label: 'p50 H', mode: 'hybrid', value: metric(data, 'hybrid', 'client_handshake_us') },
      { label: 'p50 P', mode: 'hybrid_p256', value: metric(data, 'hybrid_p256', 'client_handshake_us') },
      { label: 'p95 C', mode: 'classical', value: metric(data, 'classical', 'client_handshake_us', 'p95') },
      { label: 'p95 H', mode: 'hybrid', value: metric(data, 'hybrid', 'client_handshake_us', 'p95') },
      { label: 'p95 P', mode: 'hybrid_p256', value: metric(data, 'hybrid_p256', 'client_handshake_us', 'p95') },
      { label: 'p99 C', mode: 'classical', value: metric(data, 'classical', 'client_handshake_us', 'p99') },
      { label: 'p99 H', mode: 'hybrid', value: metric(data, 'hybrid', 'client_handshake_us', 'p99') },
      { label: 'p99 P', mode: 'hybrid_p256', value: metric(data, 'hybrid_p256', 'client_handshake_us', 'p99') },
    ], ms);
    drawBars('bytes-chart', [
      { label: 'Sent C', mode: 'classical', value: metric(data, 'classical', 'bytes_sent') },
      { label: 'Sent H', mode: 'hybrid', value: metric(data, 'hybrid', 'bytes_sent') },
      { label: 'Sent P', mode: 'hybrid_p256', value: metric(data, 'hybrid_p256', 'bytes_sent') },
      { label: 'Recv C', mode: 'classical', value: metric(data, 'classical', 'bytes_received') },
      { label: 'Recv H', mode: 'hybrid', value: metric(data, 'hybrid', 'bytes_received') },
      { label: 'Recv P', mode: 'hybrid_p256', value: metric(data, 'hybrid_p256', 'bytes_received') },
    ], bytes);
  }

  $('sample-count').textContent = `${data.recent.length} recent · ${(data.summary?.modes?.classical?.samples || 0) + (data.summary?.modes?.hybrid?.samples || 0) + (data.summary?.modes?.hybrid_p256?.samples || 0)} total`;
  $('results-body').innerHTML = data.recent.length ? data.recent.map((row) => `<tr>
    <td><code>${row.sample_id}</code></td><td><span class="badge ${row.mode}">${row.mode}</span> ${row.negotiated_group || '—'}</td>
    <td>${ms(row.client_tcp_us)}</td><td>${ms(row.client_handshake_us)}</td><td>${ms(row.server_handshake_us)}</td>
    <td>${ms(row.client_ttfb_us)}</td><td>${ms(row.client_total_us)}</td><td>${bytes((row.bytes_sent || 0) + (row.bytes_received || 0))}</td>
    <td class="${row.success ? 'ok' : 'failed'}">${row.success ? 'OK' : (row.error || 'Failed')}</td></tr>`).join('') : '<tr><td colspan="9" class="empty-cell">No measurements recorded.</td></tr>';
}

async function refresh() {
  const runId = state.runId;
  const query = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  try {
    const response = await fetch(`/api/dashboard${query}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
    $('refresh-status').textContent = 'on';
  } catch (error) {
    $('refresh-status').textContent = 'error';
  }
}

$('run-select').addEventListener('change', () => {
  state.runId = $('run-select').value || null;
  const nextUrl = state.runId ? `/?run_id=${encodeURIComponent(state.runId)}` : '/';
  history.replaceState({}, '', nextUrl);
  refresh();
});
render(state.data);
setInterval(refresh, 2000);
