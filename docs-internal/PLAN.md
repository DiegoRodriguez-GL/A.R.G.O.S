# ARGOS — Plan Modular de Desarrollo

**Agent Risk Governance and Operational Security**
Framework de Auditoría de Seguridad para Agentes de IA

---

## 0. Contexto y Principios Rectores

### 0.1. Fuente de verdad
Este plan operacionaliza la `Propuesta_TFM_ARGOS.pdf` (v1.0, 22-03-2026). Cualquier
desviación respecto a la propuesta queda marcada explícitamente como `[EXTENSIÓN]`
y requiere aprobación del director antes de ejecutarse.

### 0.2. Principios arquitectónicos (no negociables)
1. **CLI-first**. La interfaz primaria es terminal. Todo lo demás es opcional.
2. **Local-only**. Ejecución 100% en la máquina del auditor. Cero cloud, cero SaaS.
3. **Zero-trust de LLM**. El modelo es un usuario potencialmente hostil.
4. **Verificabilidad**. Cada prompt → respuesta → herramienta queda logged.
5. **Simplicidad**. Menos complejidad agentica = menos superficie de ataque.
6. **Extensibilidad por plugins**. El core no sabe de reglas concretas.
7. **Estándares abiertos**. OpenTelemetry, JSON-RPC 2.0, YAML, Pydantic.

### 0.3. Estética visual (aplica a toda superficie UI)
Referencia: **greenlock.tech** — minimalismo técnico, verde/blanco, tipografía sans.
- Verde primario: `#059669` (emerald-600)
- Verde acento: `#22c55e` (green-500)
- Oscuros: `#111827`, `#1f2937`
- Tipografía: Inter (sistema), 400/500/600/700
- Padding generoso, sin decoración gratuita, cero emojis en UI.

---

## 1. Decisiones Asumidas (corregir si procede)

| # | Decisión | Justificación | Reversibilidad |
|---|----------|---------------|----------------|
| D1 | "Frontend" = **informes HTML (RF-12) + landing/docs del proyecto + identidad visual**. NO dashboard interactivo. | Propuesta §7 excluye dashboard. Landing + docs son estándar open-source, no invaden TFM. | Alta — añadir dashboard después es [EXTENSIÓN] |
| D2 | **Primer módulo = Módulo 0 (Foundation)**: scaffolding de repo + sistema de diseño + README. | Hoy es 15-abr-2026, estamos en T1.3/T1.4 del cronograma. Sin foundation, los módulos siguientes no compilan. | Media |
| D3 | **Stack visual**: Jinja2 + CSS plano (sin framework JS) para informes. **Astro** para landing/docs (separate static site). | Jinja2 es Python-nativo (sin build). Astro da MDX para docs sin invadir el core Python. | Baja — migrar después duele |
| D4 | **Licencia dual**: AGPL-3.0 (Community) desde día 1. Comercial se añade cuando exista algo que vender. | Evita legal overhead inicial. | Alta |
| D5 | **Python 3.11+**, `pyproject.toml` con `hatchling`, `uv` como gestor recomendado. | 3.11 por asyncio maduro y typing. `uv` 10-100× más rápido que pip. | Media |
| D6 | **Monorepo** con estructura `packages/`: `argos-core`, `argos-cli`, `argos-scanner`, `argos-redteam`, `argos-proxy`, `argos-reporter` + `apps/landing` + `apps/docs`. | Favorece evolución modular y publicación selectiva. | Baja — romper monorepo después es doloroso |
| D7 | **Nombre de paquete PyPI**: `argos-ai-audit` (disponible, busqueda pendiente de verificación). | Colisión potencial con otros "argos". `ai-audit` desambigua. | Media |
| D8 | **Calidad desde día 1**: ruff, mypy strict, pytest, pre-commit, GitHub Actions CI. Cobertura ≥70% (RNF-07). | Después es tarde. | Alta |

> Si quieres cambiar cualquiera de D1–D8, dímelo ahora y actualizo antes de ejecutar.

---

## 2. Qué SÍ hacemos vs Qué NO hacemos

### 2.1. SÍ (confirmado en propuesta)
- ✅ Escáner estático de configuraciones MCP (15+ reglas)
- ✅ Red teaming con 20+ probes mapeados a OWASP ASI01-ASI10
- ✅ Proxy MCP transparente con trazas OpenTelemetry
- ✅ Informes HTML interactivos + JSONL
- ✅ Motor de reglas YAML tipo Nuclei
- ✅ Sistema de plugins descubrible por `importlib`
- ✅ CLI con Typer (`argos scan`, `argos redteam`, `argos proxy`, `argos report`)
- ✅ Mapeo compliance multi-framework (OWASP ASI, EU AI Act Anexo IV, NIST AI RMF, ISO 42001, CSA AICM)
- ✅ Validación empírica en 3 escenarios (single ReAct, multi-agente supervisor, agente con memoria)
- ✅ Documentación (README, API docs MkDocs, CONTRIBUTING)
- ✅ Publicación en PyPI

### 2.2. NO (excluido explícitamente en §7 de la propuesta)
- ❌ **Bloqueo en runtime** — ARGOS detecta y reporta, no bloquea en <10 ms
- ❌ **Frameworks fuera de LangChain/LangGraph + MCP** — CrewAI/AutoGen vía plugins futuros
- ❌ **Testing de modelos fundacionales** — lo cubren Garak/Promptfoo
- ❌ **Certificación formal** — sólo metodología, no programa certificador
- ❌ **Dashboard web interactivo** — CLI-first, informes HTML estáticos
- ❌ **Soporte multi-idioma** — solo inglés en herramienta y docs
- ❌ **Despliegue cloud/SaaS** — ejecución 100% local

### 2.3. Zona gris (a confirmar antes de tocar)
- ⚠️ **Landing site** (`argos.dev` o similar) — no está en propuesta pero tampoco prohibido. Asumo SÍ como marketing/docs.
- ⚠️ **Identidad visual (logo)** — no mencionada. Asumo SÍ como parte del README y landing.
- ⚠️ **Plugin store / marketplace** — [EXTENSIÓN] fuera de TFM.
- ⚠️ **Integración LLM judge con API comercial** — RF-06 menciona LLM-as-judge. OK siempre que sea opcional y local-fallback.

---

## 3. Arquitectura del Monorepo

```
argos/
├── README.md                      # Presentación (estilo greenlock)
├── LICENSE                        # AGPL-3.0
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md                    # Política de disclosure (nosotros somos una tool de security)
├── pyproject.toml                 # Workspace root
├── uv.lock
├── .python-version                # 3.11
├── .pre-commit-config.yaml
├── .editorconfig
├── .gitignore
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                 # ruff + mypy + pytest en matriz 3.11/3.12
│   │   ├── release.yml            # publish a PyPI en tags
│   │   └── docs.yml               # deploy MkDocs/Astro a GitHub Pages
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
│
├── packages/
│   ├── argos-core/                # Modelos Pydantic, interfaces ABC, tipos compartidos
│   │   ├── src/argos_core/
│   │   │   ├── __init__.py
│   │   │   ├── models/            # Finding, Severity, ScanResult, Probe, etc.
│   │   │   ├── interfaces/        # ABC: IPlugin, IScanner, IProbe, IDetector, IReporter
│   │   │   ├── autonomy.py        # Taxonomía CSA Levels 0-5
│   │   │   ├── compliance/        # Mappings OWASP ASI ↔ AICM ↔ NIST ↔ EU AI Act ↔ ISO
│   │   │   └── telemetry.py       # OpenTelemetry setup
│   │   ├── tests/
│   │   └── pyproject.toml
│   │
│   ├── argos-cli/                 # Typer app, comandos, configuración
│   │   ├── src/argos_cli/
│   │   │   ├── __main__.py
│   │   │   ├── app.py             # typer.Typer()
│   │   │   ├── commands/          # scan.py, redteam.py, proxy.py, report.py
│   │   │   ├── config.py          # Load YAML/JSON config
│   │   │   └── plugins.py         # importlib discovery
│   │   └── pyproject.toml
│   │
│   ├── argos-scanner/             # Escaneo estático MCP (OE2)
│   │   ├── src/argos_scanner/
│   │   │   ├── parser.py          # MCP config parser
│   │   │   ├── rules/             # 15+ reglas built-in
│   │   │   │   ├── tool_poisoning.py
│   │   │   │   ├── command_injection.py
│   │   │   │   ├── excessive_permissions.py
│   │   │   │   ├── hardcoded_secrets.py
│   │   │   │   ├── missing_tls.py
│   │   │   │   └── ...
│   │   │   └── engine.py
│   │   └── pyproject.toml
│   │
│   ├── argos-redteam/             # Red teaming (OE3)
│   │   ├── src/argos_redteam/
│   │   │   ├── probes/            # 20+ probes mapeados a ASI01-ASI10
│   │   │   │   ├── asi01_goal_hijack/
│   │   │   │   ├── asi02_tool_misuse/
│   │   │   │   ├── ... (uno por categoría)
│   │   │   ├── detectors/         # StringMatch, Regex, LLMJudge, BehaviorDetector
│   │   │   ├── strategies/        # Cómo entregar los probes (single-turn, multi-turn)
│   │   │   └── runner.py
│   │   └── pyproject.toml
│   │
│   ├── argos-proxy/               # Proxy MCP de auditoría (OE4)
│   │   ├── src/argos_proxy/
│   │   │   ├── server.py          # asyncio JSON-RPC 2.0 transparent proxy
│   │   │   ├── interceptor.py
│   │   │   ├── detectors/         # Mutación de tool defs, PII, invocaciones fuera de scope
│   │   │   └── otel.py            # Trazas OpenTelemetry
│   │   └── pyproject.toml
│   │
│   ├── argos-reporter/            # Informes (OE5)
│   │   ├── src/argos_reporter/
│   │   │   ├── html/
│   │   │   │   ├── templates/     # Jinja2 con tokens del design system
│   │   │   │   │   ├── base.html.j2
│   │   │   │   │   ├── report.html.j2
│   │   │   │   │   ├── finding.html.j2
│   │   │   │   │   └── compliance_matrix.html.j2
│   │   │   │   └── static/
│   │   │   │       ├── argos.css  # Compilado desde design-system
│   │   │   │       └── argos.js   # Solo interactividad mínima (filtros)
│   │   │   ├── jsonl.py           # Exportador JSONL
│   │   │   └── compliance.py      # Mapeador multi-framework
│   │   └── pyproject.toml
│   │
│   └── argos-rules/               # Motor de reglas YAML (tipo Nuclei)
│       ├── src/argos_rules/
│       │   ├── parser.py
│       │   ├── matchers.py
│       │   ├── extractors.py
│       │   └── schema.py          # JSON Schema de la DSL
│       ├── schema/                # Esquema publicable
│       └── pyproject.toml
│
├── apps/
│   ├── landing/                   # Astro static site (estilo greenlock)
│   │   ├── src/
│   │   │   ├── pages/
│   │   │   ├── components/
│   │   │   ├── layouts/
│   │   │   └── styles/
│   │   ├── public/
│   │   └── astro.config.mjs
│   │
│   └── docs/                      # MkDocs Material con theme override
│       ├── mkdocs.yml
│       └── docs/
│           ├── index.md
│           ├── getting-started/
│           ├── methodology/       # ARGOS metodología OE1
│           ├── modules/
│           └── compliance/
│
├── examples/                      # Ejemplos ejecutables para docs y validación
│   ├── single-react-agent/
│   ├── supervisor-worker/
│   └── persistent-memory/
│
├── design-system/                 # Tokens + guía visual (FUENTE DE VERDAD)
│   ├── tokens.json                # Design tokens (colores, tipografía, espaciado)
│   ├── tokens.css                 # Generado: --argos-green-primary, etc.
│   ├── DESIGN_SYSTEM.md           # Guía: cuándo usar qué
│   └── screenshots/               # Mockups de informes y landing
│
├── benchmarks/                    # Métricas reproducibles (OE6)
│   └── scenarios/
│
└── docs-internal/
    ├── PLAN.md                    # Este fichero
    ├── ARCHITECTURE.md            # Diagramas C4
    ├── THREAT_MODEL.md            # ARGOS es una tool de security → threat model propio
    └── RFCs/                      # Decisiones arquitectónicas (formato RFC)
        └── 0001-monorepo-layout.md
```

---

## 4. Desglose Modular

### MÓDULO 0 — Foundation *(empezamos aquí)*

**Objetivo**: dejar el proyecto escaneable, buildeable, testeable y visualmente identificable antes de escribir lógica de negocio.

**Entregables**:
- M0.1. Inicialización de repo Git + licencia AGPL-3.0 + README v0 con estilo greenlock
- M0.2. `pyproject.toml` workspace + estructura de carpetas del §3
- M0.3. Configuración de herramientas de calidad: ruff, mypy strict, pytest, pre-commit
- M0.4. GitHub Actions CI (lint + type-check + test en matriz 3.11/3.12)
- M0.5. **Design system v0**: `design-system/tokens.json` + `tokens.css` + `DESIGN_SYSTEM.md`
- M0.6. Plantilla Jinja2 base (`base.html.j2`) que usa los tokens — sin contenido real todavía
- M0.7. `argos-core` esqueleto: modelos Pydantic mínimos (`Finding`, `Severity`, `ScanResult`) + interfaces ABC vacías
- M0.8. `argos-cli` esqueleto: `argos --help`, `argos --version` funcionales. Nada más.
- M0.9. Issue templates, PR template, CODE_OF_CONDUCT, SECURITY.md
- M0.10. Documento `THREAT_MODEL.md` inicial (¿cómo atacas ARGOS?)

**Criterios de aceptación**:
- `uv sync && uv run argos --help` imprime ayuda con estilo (colores verdes en terminal via rich)
- `uv run pytest` pasa con 0 tests reales pero infra lista
- `uv run ruff check && uv run mypy packages/` pasa limpio
- CI en verde en un PR dummy
- Abrir `design-system/DESIGN_SYSTEM.md` basta para entender la paleta sin leer código
- README se ve presentable en GitHub (badges, hero, quickstart)

**Tiempo estimado**: 15–20 h (3–4 sesiones). Encaja en T1.4 + solapa con T1.3 del cronograma.

**Cómo lo sabemos terminado**: podemos hacer `git tag v0.0.1` y publicar a TestPyPI sin vergüenza.

---

### MÓDULO 1 — Metodología y Mapeo de Compliance (OE1)

**Objetivo**: materializar la matriz de mapeo cross-framework como dato estructurado, no como PDF.

**Entregables**:
- M1.1. `argos_core/compliance/owasp_asi.yaml` — 10 categorías ASI01-ASI10 con controles
- M1.2. `argos_core/compliance/csa_aicm.yaml` — 243 controles con metadatos
- M1.3. `argos_core/compliance/eu_ai_act.yaml` — Anexo III + IV mapeado a controles
- M1.4. `argos_core/compliance/nist_ai_rmf.yaml` — GOVERN/MAP/MEASURE/MANAGE
- M1.5. `argos_core/compliance/iso_42001.yaml` — 38 controles
- M1.6. `argos_core/compliance/mapping.yaml` — mapeo N:M entre todos los anteriores
- M1.7. `argos_core/autonomy.py` — enum CSA Levels 0-5 + fórmula CBRA
- M1.8. Tests de integridad: cada amenaza ASI tiene ≥3 controles auditables (OE1)
- M1.9. Docs: `docs/methodology/index.md` con diagramas Mermaid

**Tiempo estimado**: 25 h. Corresponde a T1.1 + T1.2 del cronograma.

---

### MÓDULO 2 — Escáner de Configuración MCP (OE2)

**Objetivo**: `argos scan config.json` detecta 15+ patrones de riesgo.

**Entregables**:
- M2.1. Parser MCP (JSON → modelo Pydantic `MCPConfig`)
- M2.2. Registry de reglas (patrón visitor sobre el AST de MCPConfig)
- M2.3. 15+ reglas built-in:
  - Tool poisoning (descripciones con instrucciones ocultas)
  - Command injection patterns
  - Permisos excesivos
  - Secretos hardcoded (entropy check + patterns comunes)
  - Ausencia de TLS
  - Rug pull detection (hash de tool definitions)
  - URL fetch sin allowlist
  - File access fuera de directorio
  - ... (lista completa en RFC-002)
- M2.4. Output: `Finding` con severidad Crítica/Alta/Media/Baja
- M2.5. CLI: `argos scan <path> [--rules <glob>] [--severity <min>]`
- M2.6. 20+ tests con fixtures MCP reales

**Tiempo estimado**: 25 h. Corresponde a T2.2.

---

### MÓDULO 3 — Motor de Reglas YAML (tipo Nuclei)

**Objetivo**: permitir reglas custom sin escribir Python (RU-05).

**Entregables**:
- M3.1. DSL YAML con matchers (regex, word, json-path) y extractors
- M3.2. Parser + validador (JSON Schema publicado)
- M3.3. Runtime que ejecuta reglas YAML contra MCPConfig y contra respuestas de agente
- M3.4. Biblioteca inicial de 10 reglas YAML como ejemplo
- M3.5. Docs: `docs/rules/writing-your-first-rule.md`

**Tiempo estimado**: 15 h. Corresponde a T2.4.

---

### MÓDULO 4 — Red Teaming Agéntico (OE3)

**Objetivo**: `argos redteam --target <agent-endpoint>` ejecuta 20+ probes.

**Entregables**:
- M4.1. Framework de probes (ABC `IProbe`) con metadatos ASI
- M4.2. 20+ probes, mínimo 2 por categoría ASI01-ASI10:
  - ASI01: goal hijack via tool output, via RAG document, via email
  - ASI02: tool chaining abuse, parameter manipulation
  - ASI03: privilege escalation, credential replay
  - ASI04: supply chain (malicious tool definition)
  - ASI05: code execution injection
  - ASI06: memory poisoning (single-shot + progressive)
  - ASI07: inter-agent spoofing
  - ASI08: cascade failure trigger
  - ASI09: human trust exploitation (convincing false justifications)
  - ASI10: reward hacking scenarios
- M4.3. Detectores: `StringMatch`, `Regex`, `LLMJudge` (opcional con API key), `BehaviorDetector`
- M4.4. Soporte multi-turno (RF-07)
- M4.5. Integración LangGraph callback (T3.3)
- M4.6. Métricas TP/FP/FN por probe

**Tiempo estimado**: 50 h. Corresponde a T3.1 + T3.2 + T3.3.

---

### MÓDULO 5 — Proxy MCP de Auditoría (OE4)

**Objetivo**: `argos proxy --listen 0.0.0.0:8765 --upstream <mcp-server>` intercepta 100% del tráfico.

**Entregables**:
- M5.1. Servidor asyncio JSON-RPC 2.0 transparente
- M5.2. Interceptor de `tools/list`, `tools/call`, resources/prompts
- M5.3. Detectores en runtime: mutación de tool definitions, PII, invocaciones fuera de scope
- M5.4. Instrumentación OpenTelemetry (spans por request/response)
- M5.5. Persistencia local SQLite para forensics
- M5.6. Benchmark de latencia < 50 ms (RNF-02)

**Tiempo estimado**: 30 h. Corresponde a T2.3.

---

### MÓDULO 6 — Informes HTML + Compliance (OE5)

**Objetivo**: `argos report --input results.jsonl --output report.html` produce informe bonito y mapeado.

**Entregables**:
- M6.1. Plantillas Jinja2 con design system embebido
  - Hero con resumen ejecutivo
  - Tabla de findings con filtros client-side (vanilla JS)
  - Matriz de compliance (OWASP ASI × EU AI Act × NIST)
  - Evidencia por finding (request/response capturados)
  - Recomendaciones mapeadas a mitigaciones OWASP
- M6.2. Exportador JSONL (streaming-friendly)
- M6.3. Mapeador compliance automático
- M6.4. Modo "print-friendly" (CSS `@media print`) para auditorías formales

**Tiempo estimado**: 20 h. Corresponde a T4.1.

---

### MÓDULO 7 — Validación Empírica (OE6)

**Objetivo**: 3 escenarios reales ejecutados, documentados con TP/FP/FN.

**Entregables**:
- M7.1. Escenario 1: agente ReAct + herramientas MCP (ejemplo: file manager + email)
- M7.2. Escenario 2: supervisor-worker LangGraph (ejemplo: research agent)
- M7.3. Escenario 3: agente con memoria persistente (LangMem o vector store)
- M7.4. Métricas: cobertura por categoría ASI, precision, recall, tiempo de ejecución
- M7.5. Informe de validación (Markdown + HTML) incluido en memoria TFM

**Tiempo estimado**: 25 h. Corresponde a T4.2.

---

### MÓDULO 8 — Landing + Docs + Release

**Objetivo**: el mundo puede encontrar, entender e instalar ARGOS.

**Entregables**:
- M8.1. Astro landing en `apps/landing` con estilo greenlock
  - Hero: qué es ARGOS + 1 CTA "Get Started"
  - Features: 4 módulos (Scanner, Red Team, Proxy, Reports) con iconos
  - Methodology: link a docs
  - Compliance matrix (visual)
  - Footer con enlaces legales
- M8.2. MkDocs Material (`apps/docs`) con theme override a paleta ARGOS
  - Getting Started (install + first scan en <5 min)
  - Methodology (OE1 completo)
  - Modules (uno por capa)
  - Compliance reference
  - API docs (auto-generado con mkdocstrings)
  - Contributing
- M8.3. Publicación PyPI (`pip install argos-ai-audit`)
- M8.4. Publicación Docker image (opcional, para reproducibilidad)
- M8.5. GitHub release v1.0.0 con changelog

**Tiempo estimado**: 25 h. Corresponde a T4.3.

---

### MÓDULO 9 — Memoria TFM + Defensa

**Objetivo**: entrega académica.

**Entregables**:
- M9.1. Memoria (Introducción, Estado del Arte, Metodología, Arquitectura, Validación, Conclusiones)
- M9.2. Presentación 15-20 slides + demo en vivo
- M9.3. Ensayo de defensa

**Tiempo estimado**: 50 h. Corresponde a T5.

---

## 5. Dependencias entre módulos

```
M0 ─┬─> M1 ─┬─> M2 ─┬─> M3 ─┬─> M4 ─┬─> M5 ─┬─> M6 ─> M7 ─> M8 ─> M9
    │       │       │       │       │       │
    │       └───────┴───────┼───────┴───────┤  (M1 alimenta a todos
    │                       │               │   los módulos con
    └───────────────────────┴───────────────┘   mappings de compliance)
```

- M0 bloquea TODO.
- M1 es input semántico para M2, M4, M5, M6 (todos necesitan los mapeos).
- M3 es independiente de M2 pero se beneficia de existir antes de M4.
- M6 depende de que haya datos reales (M2, M4, M5 producen findings).
- M7 ejercita M2+M4+M5+M6 end-to-end.
- M8 y M9 pueden correr en paralelo a M4-M7 desde semana 10.

---

## 6. Alineación con el Cronograma TFM

| Semana | Fechas | Módulo principal | Hito propuesta |
|--------|--------|------------------|----------------|
| 1-2 | 7-20 abr | M1 (metodología) — *ya en curso* | H1: Metodología + Diseño |
| 3 | 21-27 abr | **M0 (foundation)** + cierre M1 | H2: MVP funcional (prep) |
| 4-5 | 28 abr-11 may | M2 (scanner) + M3 (rules) | — |
| 6-7 | 12-25 may | M5 (proxy) + cierre M2/M3 | H3: Red Teaming completo (prep) |
| 8-9 | 26 may-8 jun | M4 (red team) | — |
| 10 | 9-15 jun | M4 cierre + M7 (validación) | H3 real |
| 11-12 | 16-29 jun | M6 (reports) + M8 (landing/docs) + M9 | H4: Validación + Informes |
| 13 | 30 jun-6 jul | M9 defensa | H5: Entrega final |

**Nota crítica**: hoy (15-abr-2026) estamos en la semana 2. M0 debería estar terminado la semana 3 para no comprometer el resto del cronograma.

---

## 7. Riesgos y Mitigaciones

| # | Riesgo | Probabilidad | Impacto | Mitigación |
|---|--------|--------------|---------|------------|
| R1 | MCP spec cambia antes de junio | Media | Alto | Pinnar versión `2025-11-25` en docs; abstraer en `argos-core` |
| R2 | 20+ probes ASI no alcanzan calidad de paper | Alta | Medio | Empezar por 2 probes ejemplares por categoría, iterar |
| R3 | LLM judge requiere API comercial | Media | Bajo | Fallback a detector heurístico; judge opcional |
| R4 | Latencia proxy > 50 ms | Baja | Alto | Benchmark desde día 1 en M5, asyncio puro, sin dependencias pesadas |
| R5 | Design system se fragmenta entre reports y landing | Alta | Medio | Fuente única `design-system/tokens.json`, generar CSS para ambos |
| R6 | Nombre `argos` colisiona en PyPI | Media | Medio | `argos-ai-audit` ya elegido; verificar antes de M0.1 |
| R7 | Alcance creep (dashboard, multi-idioma) | Alta | Alto | Este documento. `[EXTENSIÓN]` explícito + revisión con director |
| R8 | ARGOS mismo es atacable (prompt injection en descripciones que parsea) | Media | Alto | `THREAT_MODEL.md` desde M0; sandbox los parsers |

---

## 8. Siguiente Acción Concreta

Si apruebas este plan (total o parcialmente), el siguiente paso operativo es ejecutar
**Módulo 0 — Foundation**, empezando por:

1. Inicializar Git + crear estructura de carpetas del §3
2. Escribir `design-system/tokens.json` y `DESIGN_SYSTEM.md` (foundation visual)
3. Escribir `pyproject.toml` raíz + skeletons de cada package
4. Configurar ruff/mypy/pytest/pre-commit
5. Primer commit + push a GitHub con CI verde

Todo lo anterior antes de escribir una sola línea de lógica de escaneo, probes o proxy.

---

*Documento vivo. Actualizar con cada decisión arquitectónica en `docs-internal/RFCs/`.*
