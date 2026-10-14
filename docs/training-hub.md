# Training Hub implementation review

The catalog uses the existing FastAPI, Jinja2 and vanilla CSS stack. No new JavaScript, assets, dependencies, storage or infrastructure were added.

## Files changed

- `app/training.py`: immutable Track records and a validated TrainingCatalog.
- `app/main.py`: initialize the catalog and render hub/track routes.
- `app/templates/training_base.html`: shared catalog shell, branding and skip link.
- `app/templates/training.html`: four-track hub.
- `app/templates/index.html`: Foundations modules and honest planned-track pages.
- `app/templates/challenge.html`, `app/templates/defense.html`: hub branding, Foundations exit links and breadcrumbs.
- `app/static/style.css`: responsive catalog layout, red/blue accents and focus styles.
- `tests/test_training.py`: associations, validation, rendered links, legacy routes/API start contracts and template/CSS checks.
- `docs/training-hub.md`: this review and deployment checklist.

## Route map and compatibility

| Route | Result |
| --- | --- |
| `/training` | Training Hub |
| `/training/llm` | LLM & Agent Security Foundations |
| `/training/ml` | Machine Learning Security, coming soon |
| `/training/voice` | Voice & Multimodal Security, coming soon |
| `/training/agents` | Advanced Agent Security, coming soon |
| `/training/{unknown}` | Safe 404 |
| `/` | Foundations catalog, HTTP 200, preserving the existing entry point |
| `/challenge/{challenge_id}` | Existing playable lab, unchanged route |
| `/api/*`, `/health`, `/static/*` | Existing routes and contracts |

Home bookmarks continue to reach the catalog without a redirect. Brand links lead to the hub; Exit Lab leads to Foundations. Challenge page changes are navigation only. Challenge loading, evaluators, scoring, sessions, provider configuration and security middleware are unchanged.

## Catalog structure

`Track` contains stable `id`, `title`, `description`, `order`, `availability` and ordered `modules` (tuples of challenge IDs). Track content is server-owned. Names, descriptions, difficulty and defense flags resolve from the existing YAML-backed ChallengeRegistry. Links use named FastAPI routes and resolved challenge IDs.

Foundations associations:

| Module | Attack | Defense |
| --- | --- | --- |
| 01 | PI-001 | BT-001 |
| 02 | PI-002 | BT-002 |
| 03 | II-001 | BT-003 |
| 04 | MT-001 | BT-004 |
| 05 | AG-001 | BT-005 |
| 06 | RT-001 (06A capstone) | None |

Startup rejects duplicate track IDs, unsafe IDs, invalid availability, unknown/repeated challenge associations and invalid module sizes. Planned tracks cannot declare playable modules. Rendered-link tests follow every catalog link and confirm all eleven lab pages and start endpoints work. There is no 06B or completion persistence.

## Validation

Final full suite: **632 passed** in 110.42 seconds using `.venv/bin/python -m pytest -q`. This includes the three new Training Hub tests. Template/CSS checks and `git diff --check` pass. The changed-file credential-pattern scan found **0 matches across 10 files**. The suite emits existing dependency deprecation warnings.

The sandbox run stalled in the existing proxy/static-file tests; the approved run outside the sandbox passed the full suite. Initial implementation validation did not include browser automation. Final browser QA below uses an existing local Playwright/Chromium installation without adding project dependencies.

Training tests cover all five training pages, home compatibility, unknown tracks, exact module and challenge link order, 06A/no 06B, planned pages without launch links, all eleven existing lab routes/start responses, template compilation, CSS brace balance and responsive/focus selectors. Existing suites cover challenge behavior and API contracts.

A credential-pattern scan checks changed/new files without printing secret values. It covers private-key headers, AWS access keys, GitHub/OpenAI token patterns and quoted credential assignments. This is a scoped pattern scan, not a guarantee that every possible secret format is detectable.

## Deployment smoke checklist

- [ ] Confirm `/health` returns the existing healthy response.
- [ ] Open `/training`, `/training/llm`, `/training/ml`, `/training/voice`, `/training/agents` and `/`; verify titles, availability and navigation.
- [ ] Confirm an unknown training ID returns 404.
- [ ] Follow all eleven Foundations launch links; verify 01A/01B through 05A/05B and 06A only.
- [ ] Start an attack lab, submit a message, reset; exercise a defense configuration/retest and the capstone evaluation using the deployment's configured provider.
- [ ] Confirm planned pages have no lab launch links.
- [ ] Check narrow/mobile and desktop layouts, keyboard focus, skip link and breadcrumbs.
- [ ] Verify security/cache headers remain present and no external asset requests occur.

No deployment, commit or push is part of this change.


## Final visual and navigation QA

Checked in headless Chromium using an existing local Playwright installation. No application UX/navigation defects were confirmed, so no templates, CSS, routes or API code were changed during this QA pass. Only this report was updated.

- Inspected full-page screenshots for `/training` and `/training/llm` at 1440px desktop and 320px mobile, plus viewport screenshots. Measured both pages at 1440, 768, 390 and 320px: no horizontal overflow or clipped headings, buttons or breadcrumbs.
- Hub displays all four track cards. Foundations is available; ML, Voice & Multimodal and Advanced Agents clearly show coming soon. All four card links reach the correct page, and all three planned pages have zero lab launch links.
- Foundations shows eleven launch links in the existing order, with paired 01A/01B through 05A/05B and the lone 06A capstone. All eleven lab pages returned HTTP 200.
- Tabbed through every hub link (6) and Foundations link (15) at 1440, 390 and 320px. Each displayed the visible 3px focus outline. Activated the skip link with Enter and confirmed the main-content destination.
- Clicked the visible Back to Training link on `/` at desktop and mobile sizes; it reaches `/training`.
- From every lab, clicked the Training breadcrumb back to the hub and Exit Lab back to Foundations at desktop and mobile sizes. Brand links also point to the hub. Breadcrumbs identify the current track/lab.
- Screenshots and browser measurements are in `/tmp/training-*.png` and `/tmp/training-visual-qa.json`; the browser QA script is `/tmp/training-visual-qa.cjs`.

Browser and local server execution required the approved outside-sandbox environment. No dependencies or infrastructure were added. Production provider exercises remain deployment smoke checks.

Final QA regression rerun: **632 passed** in 111.98 seconds with `.venv/bin/python -m pytest -q`; existing dependency deprecation warnings only. `git diff --check` passed. No commit or push was made.
