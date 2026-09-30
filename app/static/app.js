(() => {
  const id = document.body.dataset.challengeId;
  if (!id) return;
  const chat = document.querySelector('#chat');
  const form = document.querySelector('#chat-form');
  const input = document.querySelector('#message');
  const connection = document.querySelector('#connection');
  const success = document.querySelector('#success');
  let sessionId = null;

  async function api(path, body = {}) {
    const response = await fetch(`/api/challenge/${encodeURIComponent(id)}/${path}`, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Request failed');
    return data;
  }
  function addMessage(role, text) {
    const item = document.createElement('div'); item.className = `message ${role}`;
    const label = document.createElement('b'); label.textContent = role === 'user' ? 'YOU' : 'VAULT-01';
    const content = document.createElement('p'); content.textContent = text;
    item.append(label, content); chat.append(item); chat.scrollTop = chat.scrollHeight;
  }
  async function start() {
    try { const data = await api('start'); sessionId = data.session_id; connection.textContent = 'CONNECTED'; }
    catch (error) { connection.textContent = 'OFFLINE'; addMessage('assistant', error.message); }
  }
  async function reset() {
    try {
      const data = sessionId ? await api('reset', {session_id: sessionId}) : await api('start');
      sessionId = data.session_id; success.hidden = true; chat.innerHTML = '';
      addMessage('assistant', 'Secure vault reinitialized. A new protected secret has been generated.'); input.disabled = false; connection.textContent = 'CONNECTED';
    } catch (error) { addMessage('assistant', error.message); }
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); const message = input.value.trim(); if (!message || !sessionId) return;
    addMessage('user', message); input.value = ''; input.disabled = true;
    try {
      const data = await api('chat', {session_id: sessionId, message}); addMessage('assistant', data.response);
      if (data.compromised) {
        document.querySelector('#attack').textContent = data.education.attack;
        document.querySelector('#owasp').textContent = data.education.owasp;
        document.querySelector('#explanation').textContent = data.education.explanation;
        success.hidden = false;
      } else input.disabled = false;
    } catch (error) { addMessage('assistant', error.message); input.disabled = false; }
    input.focus();
  });
  document.querySelector('#reset').addEventListener('click', reset);
  document.querySelector('#success-reset').addEventListener('click', reset);
  input.addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); form.requestSubmit(); } });
  start();
})();
