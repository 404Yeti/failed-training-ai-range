(() => {
  const id = document.body.dataset.challengeId;
  if (!id) return;
  const chat = document.querySelector('#chat');
  const form = document.querySelector('#chat-form');
  const input = document.querySelector('#message');
  const connection = document.querySelector('#connection');
  const success = document.querySelector('#success');
  const character = document.body.dataset.character || 'VAULT';
  const documentMode = document.body.dataset.documentMode === 'true';
  const progressionMode = document.body.dataset.progressionMode === 'true';
  const documentList = document.querySelector('#document-list');
  const documentPreview = document.querySelector('#document-preview');
  const documentName = document.querySelector('#document-name');
  const analyzeButton = document.querySelector('#analyze-document');
  const analysisOutput = document.querySelector('#analysis-output');
  let sessionId = null;
  let selectedDocumentId = null;

  async function api(path, body = null, method = 'POST') {
    const options = {method, headers: {'Content-Type': 'application/json'}};
    if (body !== null) options.body = JSON.stringify(body);
    const response = await fetch(`/api/challenge/${encodeURIComponent(id)}/${path}`, {
      ...options
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Request failed');
    return data;
  }
  function showSuccess(data) {
    document.querySelector('#attack').textContent = data.education.attack;
    document.querySelector('#owasp').textContent = data.education.owasp;
    document.querySelector('#explanation').textContent = data.education.explanation;
    success.hidden = false;
    const traceList = document.querySelector('#attack-trace-list');
    if (traceList && data.attack_trace) {
      traceList.replaceChildren();
      data.attack_trace.forEach(entry => {
        const item = document.createElement('li');
        const turn = document.createElement('b'); turn.textContent = `TURN ${entry.turn}`;
        const description = document.createElement('span'); description.textContent = entry.description;
        item.append(turn, description); traceList.append(item);
      });
    }
  }
  function applyTelemetry(telemetry) {
    if (!progressionMode || !telemetry) return;
    document.querySelector('#risk-fill').style.width = `${telemetry.percentage}%`;
    document.querySelector('#risk-percent').textContent = `${telemetry.percentage}%`;
    document.querySelector('#risk-level').textContent = telemetry.level;
    document.querySelector('#turn-count').textContent = telemetry.turns;
    document.querySelector('#risk-state').textContent = telemetry.state;
  }
  function addMessage(role, text, blocked = null) {
    const item = document.createElement('div'); item.className = `message ${role}`;
    if (blocked) item.classList.add('blocked');
    const label = document.createElement('b'); label.textContent = role === 'user' ? 'YOU' : blocked ? 'SECURITY CONTROL' : character;
    const content = document.createElement('p'); content.textContent = text;
    item.append(label, content); chat.append(item); chat.scrollTop = chat.scrollHeight;
  }
  async function start() {
    try {
      const data = await api('start', {}); sessionId = data.session_id; connection.textContent = 'CONNECTED'; applyTelemetry(data.telemetry);
      if (documentMode) await loadDocuments();
    } catch (error) {
      connection.textContent = 'OFFLINE';
      if (documentMode) analysisOutput.textContent = error.message; else addMessage('assistant', error.message);
    }
  }
  async function reset() {
    try {
      const data = sessionId ? await api('reset', {session_id: sessionId}) : await api('start');
      sessionId = data.session_id; success.hidden = true; connection.textContent = 'CONNECTED'; applyTelemetry(data.telemetry);
      if (documentMode) {
        selectedDocumentId = null; documentName.textContent = 'SELECT A DOCUMENT';
        documentPreview.textContent = 'Choose a predefined candidate document to inspect.';
        analysisOutput.textContent = 'No document analyzed.'; analyzeButton.disabled = true;
      } else {
        chat.innerHTML = '';
        addMessage('assistant', 'Secure vault reinitialized. A new protected secret has been generated.'); input.disabled = false;
      }
    } catch (error) {
      if (documentMode) analysisOutput.textContent = error.message; else addMessage('assistant', error.message);
    }
  }
  async function loadDocuments() {
    const data = await api('documents', null, 'GET');
    documentList.replaceChildren();
    data.documents.forEach(documentInfo => {
      const button = document.createElement('button'); button.className = 'document-choice';
      button.type = 'button'; button.textContent = documentInfo.name;
      button.addEventListener('click', () => selectDocument(documentInfo.id, button));
      documentList.append(button);
    });
  }
  async function selectDocument(documentId, button) {
    try {
      const data = await api(`document/${encodeURIComponent(documentId)}`, null, 'GET');
      selectedDocumentId = data.id; documentName.textContent = data.name;
      documentPreview.textContent = data.content; analyzeButton.disabled = false;
      documentList.querySelectorAll('button').forEach(item => item.classList.remove('selected'));
      button.classList.add('selected');
    } catch (error) { analysisOutput.textContent = error.message; }
  }
  async function analyzeDocument() {
    if (!selectedDocumentId || !sessionId) return;
    analyzeButton.disabled = true; analysisOutput.textContent = 'Analyzing untrusted document…';
    try {
      const data = await api('analyze', {session_id: sessionId, document_id: selectedDocumentId});
      analysisOutput.textContent = data.response;
      if (data.compromised) showSuccess(data); else analyzeButton.disabled = false;
    } catch (error) { analysisOutput.textContent = error.message; analyzeButton.disabled = false; }
  }
  if (form) form.addEventListener('submit', async (event) => {
    event.preventDefault(); const message = input.value.trim(); if (!message || !sessionId) return;
    addMessage('user', message); input.value = ''; input.disabled = true;
    try {
      const data = await api('chat', {session_id: sessionId, message}); addMessage('assistant', data.response, data.blocked);
      applyTelemetry(data.telemetry);
      if (data.compromised) {
        showSuccess(data);
      } else input.disabled = false;
    } catch (error) { addMessage('assistant', error.message); input.disabled = false; }
    input.focus();
  });
  document.querySelector('#reset').addEventListener('click', reset);
  document.querySelector('#success-reset').addEventListener('click', reset);
  if (input) input.addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); form.requestSubmit(); } });
  if (analyzeButton) analyzeButton.addEventListener('click', analyzeDocument);
  start();
})();
