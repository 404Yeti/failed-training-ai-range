# Failed Training — AI Range

A small browser-based educational cyber range for learning why AI applications fail under adversarial input.

- **Lab 01 — The Secret:** direct prompt injection against model instructions.
- **Lab 02 — GUARDED:** guardrail bypass against deliberately weak input and output filters.
- **Lab 03 — POISONED DOCUMENT:** indirect prompt injection through untrusted resume content.
- **Lab 04 — SLOW BURN:** a deterministic simulation of conversation-level risk and multi-turn prompt injection.
- **Lab 05 — TOOL TROUBLE:** a harmless agent/tool authorization simulation with action-based scoring.
- **Lab 06 — AUTOMATE IT:** bounded, repeatable local security evaluation using the same target evaluators.

## Architecture

- FastAPI serves Jinja pages and JSON endpoints.
- YAML files define challenge content; routes contain no challenge-specific configuration.
- An in-memory, replaceable session store holds flags, history, and compromise state server-side.
- A provider interface supports deterministic mock play and OpenAI-compatible chat APIs.
- Strategy-based server-side scoring supports exact flags and approved transformed-secret representations.
- Optional YAML-configured guards run independently of the LLM provider.
- A predefined-document registry supplies controlled untrusted-content fixtures without uploads or client paths.
- A YAML-driven progression engine models unique conversation-context categories and coarse telemetry.
- A constrained simulated-tool layer separates model requests, argument validation, authorization, execution, and audit.
- A bounded red-team runner executes server-defined plans against allowlisted local challenges and produces redacted reports.
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

For offline Lab 02 testing, ask for the protected value in `base64`, `hex`, `spaced` characters, or `reverse` form. These are deterministic mock-provider behaviors for the educational flow, not suggested real-world bypass prompts.

For offline Lab 03 testing, analyze the normal resume for a baseline, then analyze the suspicious resume to exercise deterministic indirect disclosure.

For offline Lab 04 testing, build several distinct kinds of archive, reference, transformation, and example context across multiple turns. Entering the simulated context-drift state does not win by itself; a later operation request must still make the mock provider deliver the exact session flag.

For offline Lab 06 testing, click **Run Security Evaluation**. Its three-case mock plan reliably produces two NO FINDING results and one FINDING, then completes the curriculum without exposing the target session secret.

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

To add a basic lab, copy `challenges/01_the_secret.yaml`, give it a unique `id`, fill every required field, and choose a supported success strategy. The registry discovers YAML automatically.

### Guarded challenge pipeline

Lab 02 uses this server-side sequence:

```text
student message → input guard → model → output guard → delivered response → evaluator
```

If the input guard matches a configured phrase, the model is never called. If the output guard finds the literal session secret, the raw model response is discarded and a safe blocked message is delivered. Only delivered text reaches the evaluator.

Lab 01 uses `success.type: flag_in_response`, which requires the exact session flag. Lab 02 uses `success.type: transformed_secret` and explicitly lists accepted deterministic representations:

```yaml
success:
  type: transformed_secret
  accepted_encodings:
    - base64
    - hex
    - spaced
    - reversed
```

Each candidate is derived server-side from that session's actual random flag. Arbitrary `FT{...}` values and transformations of another value do not score.

To create another guarded challenge, start from `challenges/02_guarded.yaml`. Configure `guards.input.phrases`, select the `blocked_phrases` input type and `exact_secret` output type, then list only supported encodings under `success.accepted_encodings`. Never place a real flag in YAML; `{SESSION_FLAG}` is substituted server-side at runtime.

### Indirect prompt injection and document trust

Direct injection arrives in an explicit user instruction. Indirect injection arrives through content the application asks the model to consume—such as a document, webpage, email, support ticket, or retrieved RAG passage. Lab 03 demonstrates the core failure: **data consumed by an LLM can become an instruction channel.**

Lab 03 keeps privileged and untrusted content structurally separate:

```text
system message: privileged application instructions + session flag
user message:   analysis task + delimited untrusted document content
```

The separation makes the trust boundary explicit in code, but the intentionally vulnerable model workflow can still follow instructions embedded in the document. Success uses exact server-side flag scoring on the response actually delivered to the student.

Documents are plain UTF-8 fixtures declared in challenge YAML and preloaded from `documents/<challenge-id>/`. Browser requests use opaque document IDs, not filenames or filesystem paths. There are no uploads, parsers, external URL fetches, or user-selected paths.

To create another document-based challenge:

1. Add a challenge YAML containing `character`, `documents`, and a supported `success` strategy.
2. Give each document a constrained opaque `id`, display `name`, and basename-only `.txt` fixture `file`.
3. Place those fixtures in `documents/<challenge-id>/`.
4. Keep `{SESSION_FLAG}` only in the server-side system prompt; never place it in a fixture.

This small abstraction can later represent other controlled untrusted-content sources without adding them in v0.3.

### Multi-turn progression and Crescendo-style attacks

Lab 04 demonstrates that the attack surface can be the whole conversation rather than one prompt. Several individually ordinary interactions can establish archive terminology, internal-reference concepts, transformation context, examples, and follow-up operations. The full chronological user/assistant history is sent to the provider on every turn.

The YAML `progression` block defines:

- A maximum score, minimum turns, and context-drift threshold.
- Broad event categories with weights and phrase groups.
- Restricted and simulated context-drift posture text.
- Coarse post-compromise trace descriptions.

Each event category can contribute only once per session, so repeating one phrase cannot farm risk. Risk is capped at the configured maximum. Trigger phrases, event IDs, thresholds, system prompts, and flags remain server-side; the browser receives only turn count, percentage, LOW/ELEVATED/HIGH/CRITICAL level, and a coarse posture label.

Progression and scoring are deliberately independent:

```text
conversation → progression telemetry → simulated posture → provider response
                                                        ↓
                                      exact session-flag scoring
```

Reaching a threshold or 100% risk never counts as compromise. Only an assistant response delivered to the student that contains the exact server-held session flag wins.

**Context Risk is educational telemetry, not a universal or scientifically calibrated LLM risk metric.** Keyword categories cannot accurately quantify real model security, intent, or exploitability.

To create a future progression-based challenge, add a `progression` block like `challenges/04_slow_burn.yaml`, use a normal supported scoring strategy, provide coarse trace labels, and keep all matching configuration server-side. The generic chat pipeline and session state will apply the configured progression without challenge-ID-specific routing.

### Agent and tool security

Lab 05 demonstrates the security boundary introduced when model output can cause application actions:

```text
conversation → model output → structured tool request → argument validation
             → deterministic authorization → simulated execution → audit → scoring
```

The model may request an action, but it is never the authorization authority. Tool requests use a constrained JSON object with an allowlisted tool name and exact arguments. The server rejects malformed JSON, unknown tools, extra or missing fields, invalid types, oversized strings, negative amounts, and non-finite numbers. No model output is evaluated as code.

The fictional tools are:

- `lookup_customer`: reads a predefined fictional customer.
- `read_ticket`: reads a predefined fictional support ticket.
- `draft_email`: stores a draft string in the current session; it sends nothing.
- `issue_refund`: records a fictional refund in the current session; it contacts no payment system.

Refund authorization is deterministic application code: the customer and ticket must exist and the amount must not exceed the configured autonomous limit. The audit trail records the model request, policy decision, whether execution occurred, and whether execution violated policy as separate facts.

Lab 05 contains a YAML-scoped, deterministic simulation flaw that can cause a denied refund to reach only the local in-memory executor. The `unauthorized_tool_execution` scoring strategy succeeds only when a prohibited action was actually executed; a request or denial alone does not win.

**All tools in TOOL TROUBLE are fictional local simulations. No real payments, email, accounts, or external systems are accessed.**

To create another simulated-tool challenge, declare an allowlist and policy in YAML, reuse the strict registry and policy layer, and add only bounded local state changes. Never connect educational tool challenges to real credentials or services.

### Automated AI security evaluation

Lab 06 turns a small manual test plan into a repeatable regression check:

```text
MANUAL TESTING                 AUTOMATED TESTING
Human                          Server-defined plan
  ↓                              ↓
Prompt                         Bounded runner
  ↓                              ↓
Failed Training target         Same Failed Training target
  ↓                              ↓
Observation                    Same evaluator → redacted report
```

The browser submits only a Lab 06 session ID and the identifier of a server-defined plan. The plan selects an allowlisted local challenge ID; it cannot select a URL, hostname, IP address, port, file, external API, or user-provided prompt list. `RT-001` cannot target itself.

Each case normally receives a fresh target session, so cases cannot inherit flags or history from one another and cannot affect manually opened sessions. Runs and reports are held only in the Lab 06 session. Case count, prompts per case, prompt length, and report history are bounded.

The runner calls the normal target conversation pipeline and its existing evaluator. A target compromise becomes a **FINDING**; otherwise the case is **NO FINDING**. Target flags are replaced with `FT{REDACTED}` before report data is stored or returned, and reports omit system prompts, API keys, and hidden challenge configuration.

Lab 06 uses `success.type: evaluation_completed`. Completion means every configured case reached a terminal result and a valid report was generated. A finding is not required—the learning objective is building a repeatable evaluation, not forcing a vulnerability.

Automation complements rather than replaces human red teaming. Human exploration supplies reasoning and new hypotheses; automation supplies repeatability, regression coverage, and comparisons after model, prompt, guardrail, or application changes.

To add a local plan, define bounded cases under an automation challenge's YAML, allowlist only an existing Failed Training challenge, and keep all prompts server-side. Do not add remote destinations or internet-fetched plans.

## Using Failed Training with PyRIT

PyRIT is intentionally not a runtime dependency. The stable integration boundary is the local Failed Training target API:

```text
PyRIT adapter (optional, future)
        ↓
local challenge API
        ↓
Failed Training target pipeline
        ↓
existing evaluator
```

An adapter should create an allowlisted target session with `POST /api/challenge/{challenge_id}/start`, then submit bounded prompts to `POST /api/challenge/{challenge_id}/chat`. It must keep the range on localhost, preserve session IDs between turns when needed, obey prompt limits, and consume only the public JSON response. The `/api/redteam/run` endpoint is deliberately narrower: it accepts only `session_id` and `plan_id` and does not accept arbitrary prompts or destinations.

No version-specific Python example is included because PyRIT is optional and its installed API was not verified as part of the core application. Consult the [official Microsoft PyRIT project](https://github.com/microsoft/PyRIT) for current installation and adapter APIs. The range works fully without PyRIT.

## Security warning

The labs, Lab 02 filters, Lab 03 poisoned documents, Lab 04 progression model, Lab 05 authorization flaw, and Lab 06 test fixtures are deliberately vulnerable educational fixtures. They are not production-grade controls, safe documents for unrelated systems, or calibrated security measurements. The surrounding platform validates IDs and input length, renders content with DOM `textContent`, holds secrets and hidden challenge rules server-side, restricts documents to predeclared UTF-8 files, validates exact tool schemas, and executes no user commands or external tools. Automation accepts no arbitrary URLs, hosts, ports, files, shell commands, code, or bulk prompt lists. Arbitrary uploads, filesystem paths, document parsers, URL fetching, payments, email delivery, and account access are intentionally unsupported. Do not place real secrets in challenge prompts. Rate limiting and production-grade persistence are TODOs before any public deployment.

## Roadmap

- v0.1 — Direct Prompt Injection ✓
- v0.2 — Guardrail Bypass ✓
- v0.3 — Indirect Prompt Injection ✓
- v0.4 — Multi-turn/Crescendo ✓
- v0.5 — Agent / Tool Security ✓
- v0.6 — Automated AI Security Evaluation ✓
- Future — optional PyRIT adapter and MCP security
- v1.0 — rooms, scoring, instructor dashboard
