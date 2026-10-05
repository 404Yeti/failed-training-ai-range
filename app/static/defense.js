(() => {
  const challengeId = document.body.dataset.challengeId;
  const character = document.body.dataset.character;
  let sessionId = null;
  let busy = false;
  let applied = [];
  const controls = document.getElementById('controls');
  const status = document.getElementById('configuration-status');
  const report = document.getElementById('report');
  const chat = document.getElementById('chat');
  const message = document.getElementById('message');
  const selected = () => [...controls.querySelectorAll('input:checked')].map(input => input.value);
  const dirty = () => JSON.stringify(selected()) !== JSON.stringify(applied);
  function buttons() {
    document.querySelectorAll('button, input, textarea').forEach(node => { node.disabled = busy || !sessionId; });
    document.getElementById('retest').disabled = busy || !sessionId || dirty();
    document.querySelector('#chat-form button').disabled = busy || !sessionId || dirty();
  }
  async function post(path, body = {}) {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...body, ...(sessionId ? {session_id: sessionId} : {})})});
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Request rejected. Check your input.');
    return data;
  }
  function appendMessage(who, text, blocked = false) {
    const item = document.createElement('div'); item.className = `message ${who === 'YOU' ? 'user' : 'assistant'}${blocked ? ' blocked' : ''}`;
    const label = document.createElement('b'); label.textContent = who;
    const content = document.createElement('p'); content.textContent = text;
    item.append(label, content); chat.append(item); chat.scrollTop = chat.scrollHeight;
  }
  function renderReport(data) {
    report.replaceChildren();
    if (!data) { report.textContent = 'No defense test run yet.'; return; }
    const heading = document.createElement('h2'); heading.textContent = data.validated ? 'DEFENSE VALIDATED' : data.errors ? 'DEFENSE TEST — ERROR' : 'DEFENSE NEEDS WORK'; report.append(heading);
    const table = document.createElement('div'); table.className = 'report-table';
    data.results.forEach(result => {
      const row = document.createElement('article');
      const name = document.createElement('b'); name.textContent = result.name;
      const outcome = document.createElement('strong'); outcome.textContent = result.result;
      const explanation = document.createElement('small'); explanation.textContent = result.explanation;
      row.append(name, outcome, explanation);
      if (result.result !== 'PASS') { const hint = document.createElement('small'); hint.textContent = `CONSIDER: ${result.hint}`; row.append(hint); }
      table.append(row);
    }); report.append(table);
    const score = document.createElement('p'); score.textContent = `Security checks passed: ${data.passed} / ${data.total}`;
    const takeaway = document.createElement('p'); takeaway.textContent = data.takeaway; report.append(score, takeaway);
  }
  function renderState(data) {
    applied = data.configuration.enabled;
    document.querySelectorAll('#defense-pipeline li').forEach(stage => {
      const ids = stage.dataset.controlIds.split(',').filter(Boolean);
      const active = ids.length === 0 || ids.some(id => applied.includes(id));
      stage.classList.toggle('active', active);
      stage.querySelector('small').textContent = ids.length === 0 ? 'ALWAYS' : active ? 'ON' : 'OFF';
    });
    controls.replaceChildren();
    data.controls.forEach(control => {
      const label = document.createElement('label'); label.className = 'defense-control';
      const input = document.createElement('input'); input.type = 'checkbox'; input.value = control.id; input.checked = applied.includes(control.id);
      const text = document.createElement('span');
      const name = document.createElement('strong'); name.textContent = control.name;
      const layer = document.createElement('b'); layer.textContent = control.layer;
      const explanation = document.createElement('small'); explanation.textContent = control.explanation;
      text.append(name, layer, explanation); label.append(input, text); controls.append(label);
      input.addEventListener('change', () => { status.textContent = dirty() ? 'UNAPPLIED CHANGES — apply before retesting.' : 'APPLIED CONFIGURATION'; buttons(); });
    });
    status.textContent = data.validated ? 'DEFENSE VALIDATED' : applied.length ? 'DEFENSE APPLIED — READY TO RETEST' : 'BASELINE CONFIGURATION — NO CONTROLS ENABLED';
    renderReport(data.report);
  }
  async function action(work) {
    if (busy) return;
    busy = true; buttons();
    try { await work(); } catch (error) { status.textContent = error.message; }
    finally { busy = false; buttons(); }
  }
  async function start() {
    sessionId = null;
    const data = await post(`/api/challenge/${challengeId}/start`); sessionId = data.session_id; renderState(data.defense);
    chat.replaceChildren(); appendMessage(character, 'Observe the baseline, configure controls, apply, then retest. Ordinary questions remain available.');
  }
  document.getElementById('apply').addEventListener('click', () => action(async () => { renderState(await post('/api/defense/apply', {enabled: selected()})); chat.replaceChildren(); appendMessage(character, 'Configuration applied. Conversation cleared.'); }));
  document.getElementById('retest').addEventListener('click', () => action(async () => { status.textContent = 'RUNNING BOUNDED REGRESSION — please wait.'; renderState(await post('/api/defense/retest')); }));
  document.getElementById('reset').addEventListener('click', () => action(async () => { const data = await post(`/api/challenge/${challengeId}/reset`); sessionId = data.session_id; renderState(data.defense); chat.replaceChildren(); appendMessage(character, 'New baseline session ready.'); }));
  document.getElementById('chat-form').addEventListener('submit', event => {
    event.preventDefault(); if (busy || dirty() || !message.value.trim()) return;
    const text = message.value;
    action(async () => { appendMessage('YOU', text); message.value = ''; const data = await post('/api/defense/chat', {message: text}); appendMessage(character, data.response, Boolean(data.blocked)); if (data.disclosed) { status.textContent = 'PROTECTED INFORMATION DELIVERED — analyze, improve and retest.'; renderReport(null); } });
  });
  action(start);
})();
