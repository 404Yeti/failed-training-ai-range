# Failed Training — AI Range

A small browser-based educational cyber range for learning why AI applications fail under adversarial input. v0.1 includes **Lab 01 — The Secret**, an intentionally vulnerable direct prompt-injection challenge with a randomized per-session flag.

## Architecture

- FastAPI serves Jinja pages and JSON endpoints.
- YAML files define challenge content; routes contain no challenge-specific configuration.
- An in-memory, replaceable session store holds flags, history, and compromise state server-side.
- A provider interface supports deterministic mock play and OpenAI-compatible chat APIs.
- Server-side scoring detects the exact session flag in model output.
- Vanilla HTML, CSS, and JavaScript provide the range UI.

No flag, system prompt, or API key is sent to the browser before compromise.

## Run locally

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # optional
uvicorn app.main:app --reload
```

Open <http://localhost:8000>. Mock mode is the default and needs no API key. In the lab, direct requests to reveal or show the secret make the predictable mock model disclose it so the full learning flow can be tested.

Run tests with:

```bash
pytest
```

## Run with Docker

```bash
docker compose up --build
```

Then open <http://localhost:8000>.

## LLM configuration

Copy `.env.example` to `.env`, then select one provider:

```dotenv
LLM_PROVIDER=mock
```

Or configure a server implementing the standard chat completions endpoint:

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=your-server-side-key
LLM_MODEL=gpt-4o-mini
```

The key stays in the backend process. `LLM_BASE_URL` should end before `/chat/completions`.

### Use Ollama on the Windows host

Start Ollama on Windows (launch the Ollama application, or run this in PowerShell):

```powershell
ollama serve
```

In another PowerShell window, list installed models and pull the development model if needed:

```powershell
ollama list
ollama pull qwen2:7b
```

Create a local `.env` beside `docker-compose.yml` (it is gitignored):

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=qwen2:7b
```

Ollama accepts the placeholder API key but does not require a real credential. Docker Compose maps `host.docker.internal` to the host, and the provider sends standard requests to `/v1/chat/completions`.

Rebuild and restart AI Range:

```bash
docker compose up --build -d --force-recreate
docker compose logs -f airange
```

To switch back to offline mock mode, set `LLM_PROVIDER=mock` in `.env` (the other variables may remain), then recreate the container:

```bash
docker compose up -d --force-recreate
```

If Ollama is not reachable, verify its OpenAI-compatible endpoint from WSL:

```bash
curl http://localhost:11434/v1/models
```

Then verify the same route from the running AI Range container:

```bash
docker compose exec airange python -c "import urllib.request; print(urllib.request.urlopen('http://host.docker.internal:11434/v1/models', timeout=5).read().decode())"
```

If WSL works but the container does not, ensure Ollama is allowed through Windows Firewall and is listening on an address accessible outside localhost. For local development, set `OLLAMA_HOST=0.0.0.0:11434` in the Windows environment, restart Ollama, and retry. Only expose Ollama on trusted networks.

## YAML challenges

Definitions in `challenges/` supply metadata, objective, system prompt, success strategy, and educational copy. The runtime replaces `{SESSION_FLAG}` in the system prompt with a cryptographically random value; never put real flags in YAML.

To add a lab, copy `challenges/01_the_secret.yaml`, give it a unique `id`, fill every schema field, and add an appropriate success strategy/provider behavior. The registry discovers YAML automatically. UI support for additional playable labs is intentionally deferred beyond v0.1.

## Security warning

The lab's AI behavior is deliberately vulnerable and is for education in an isolated environment. The surrounding platform still validates IDs and input length, escapes rendered chat content, holds secrets server-side, and executes no user commands or external tools. Do not place real secrets in challenge prompts. Rate limiting and production-grade persistence are TODOs before any public deployment.

## Roadmap

- v0.1 — Direct Prompt Injection
- v0.2 — Guardrail Bypass
- v0.3 — Indirect Prompt Injection
- v0.4 — Multi-turn/Crescendo
- v0.5 — PyRIT integration
- v0.6 — Agent/tool abuse
- v0.7 — MCP security
- v1.0 — rooms, scoring, instructor dashboard
