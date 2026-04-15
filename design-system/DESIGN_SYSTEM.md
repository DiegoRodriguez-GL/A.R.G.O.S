# ARGOS — Design System v0

**Fuente de verdad visual para toda superficie UI del proyecto.**

Referencia estética: `greenlock.tech` — minimalismo técnico, paleta verde/blanca,
tipografía sans, whitespace generoso, cero decoración gratuita.

Este documento es vinculante para:
- Informes HTML (Jinja2 templates)
- Landing site (Astro)
- Docs (MkDocs Material theme override)
- README del proyecto
- CLI (colores de terminal via `rich`)
- Cualquier diagrama o mockup

---

## 1. Filosofía

1. **Confianza por sobriedad**. ARGOS audita. Un informe ARGOS debe transmitir
   rigor técnico, no espectáculo. Si dudamos entre "más" o "menos", elegimos menos.
2. **Legibilidad antes que estética**. Jerarquía tipográfica clara, contraste AA
   mínimo (preferible AAA), sin texto claro sobre fondos claros.
3. **Verde = identidad, no alerta**. El verde es marca, no señal de "todo OK".
   Para severidad usamos una escala aparte (ver §4).
4. **Cero emojis en UI**. Iconos SVG consistentes (Phosphor o Lucide).
5. **Cero animaciones gratuitas**. Solo transiciones funcionales (≤200ms, ease-out).
6. **Monospace para datos técnicos**. Hashes, paths, CVEs, código: siempre mono.

---

## 2. Tokens de Color

### 2.1. Verdes (marca)

| Token | Hex | Uso |
|-------|-----|-----|
| `--argos-green-900` | `#064e3b` | Headings en modo light sobre blanco |
| `--argos-green-700` | `#047857` | Text emphasis, links activos |
| `--argos-green-600` | `#059669` | **Primario de marca** (logo, CTAs) |
| `--argos-green-500` | `#10b981` | Hover de CTAs, acentos |
| `--argos-green-400` | `#34d399` | Decorativo, highlights sutiles |
| `--argos-green-100` | `#d1fae5` | Fondos de éxito/activación sutil |
| `--argos-green-50`  | `#ecfdf5` | Fondos muy sutiles (code blocks activos) |

### 2.2. Neutrales (estructura)

| Token | Hex | Uso |
|-------|-----|-----|
| `--argos-ink-950` | `#030712` | Texto máximo contraste, modo light sobre blanco |
| `--argos-ink-900` | `#111827` | **Fondo primario en modo dark** (footer, hero oscuro) |
| `--argos-ink-800` | `#1f2937` | Fondo secundario dark, bordes fuertes |
| `--argos-ink-700` | `#374151` | Texto secundario dark |
| `--argos-ink-500` | `#6b7280` | Texto terciario, placeholders |
| `--argos-ink-400` | `#9ca3af` | Texto deshabilitado, footers light |
| `--argos-ink-300` | `#d1d5db` | Bordes sutiles |
| `--argos-ink-200` | `#e5e7eb` | Divisores |
| `--argos-ink-100` | `#f3f4f6` | Fondos de zona (cards, tables) |
| `--argos-ink-50`  | `#f9fafb` | Fondo alternativo de página |
| `--argos-paper`   | `#ffffff` | **Fondo primario en modo light** |

### 2.3. Severidad (escala propia, NO mezclar con marca)

| Token | Hex | Equivalente semántico | Uso |
|-------|-----|----------------------|-----|
| `--argos-sev-critical` | `#991b1b` | red-800 | Crítica — CVSS ≥ 9.0 |
| `--argos-sev-high`     | `#c2410c` | orange-700 | Alta — CVSS 7.0–8.9 |
| `--argos-sev-medium`   | `#a16207` | yellow-700 | Media — CVSS 4.0–6.9 |
| `--argos-sev-low`      | `#365314` | lime-900 | Baja — CVSS < 4.0 |
| `--argos-sev-info`     | `#1e40af` | blue-800 | Informativo |

> **Regla**: los colores de severidad se usan SOLO en chips/badges, bordes laterales
> de `Finding` cards, e iconografía de filas de tabla. Nunca como background de
> página o botones primarios.

### 2.4. Accesibilidad
- Contraste mínimo: **WCAG AA** (4.5:1 texto normal, 3:1 texto grande).
- Testeo obligatorio de pares verificados (ya calculados):
  - `green-600` sobre `paper` → 4.56:1 ✅
  - `ink-700` sobre `paper` → 10.3:1 ✅
  - `green-400` sobre `ink-900` → 8.9:1 ✅
- Cualquier token nuevo pasa por `npm run check:contrast` (o test python equivalente).

---

## 3. Tipografía

### 3.1. Familias

| Rol | Familia | Fallback |
|-----|---------|----------|
| Sans (UI, body) | **Inter** | `ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` |
| Mono (código, hashes) | **JetBrains Mono** | `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace` |

Sin fuentes display. Sin serifs. No cargamos fuentes si el sistema ya las tiene.

### 3.2. Escala tipográfica

Escala modular ratio 1.25 (Major Third), base 16px.

| Token | Tamaño | Line-height | Uso |
|-------|--------|-------------|-----|
| `--fs-xs` | `0.75rem` (12px) | 1.5 | Footnotes, metadatos |
| `--fs-sm` | `0.875rem` (14px) | 1.5 | **Body en reports densos**, labels |
| `--fs-base` | `1rem` (16px) | 1.6 | Body general |
| `--fs-lg` | `1.125rem` (18px) | 1.5 | Lead paragraphs |
| `--fs-xl` | `1.25rem` (20px) | 1.4 | Subheadings, logo |
| `--fs-2xl` | `1.5rem` (24px) | 1.3 | H3 |
| `--fs-3xl` | `1.875rem` (30px) | 1.25 | H2 |
| `--fs-4xl` | `2.25rem` (36px) | 1.2 | H1 |
| `--fs-5xl` | `3rem` (48px) | 1.1 | Hero landing |

### 3.3. Pesos
- `400` regular — body
- `500` medium — UI labels, tabla headers
- `600` semibold — subheadings, buttons
- `700` bold — H1-H2, emphasis fuerte
- Italic: solo para citas y términos foráneos. Nunca para emphasis (usar peso).

---

## 4. Espaciado

Sistema basado en múltiplos de 4px (0.25rem).

| Token | Valor | Uso típico |
|-------|-------|------------|
| `--sp-0` | 0 | Reset |
| `--sp-1` | 0.25rem (4px) | Gap mínimo entre ícono y texto |
| `--sp-2` | 0.5rem (8px) | Gap dentro de botones |
| `--sp-3` | 0.75rem (12px) | Padding interno de chips |
| `--sp-4` | 1rem (16px) | **Gap estándar** entre elementos |
| `--sp-6` | 1.5rem (24px) | Padding interno de cards |
| `--sp-8` | 2rem (32px) | Gap entre bloques de contenido |
| `--sp-12` | 3rem (48px) | Gap entre secciones en landing |
| `--sp-16` | 4rem (64px) | **Padding vertical de secciones** hero/landing |
| `--sp-24` | 6rem (96px) | Separación entre secciones mayores |

### 4.1. Layout containers
- `max-width` contenido principal: `72rem` (1152px)
- `max-width` texto largo (prose): `40rem` (640px) para legibilidad óptima
- Padding lateral mínimo en mobile: `--sp-6`

---

## 5. Bordes y Radios

| Token | Valor | Uso |
|-------|-------|-----|
| `--radius-sm` | 4px | Chips, badges |
| `--radius-md` | 6px | **Botones, inputs** |
| `--radius-lg` | 8px | Cards |
| `--radius-xl` | 12px | Hero containers, modals |
| `--radius-full` | 9999px | Pills, avatars |

Bordes:
- Default: `1px solid var(--argos-ink-200)`
- Focus: `2px solid var(--argos-green-600)` con `outline-offset: 2px`
- Hover sutil en cards: `var(--argos-ink-300)`

---

## 6. Sombras

Mínimas. Sobriedad antes que profundidad.

| Token | Valor |
|-------|-------|
| `--shadow-xs` | `0 1px 2px rgba(0,0,0,0.04)` |
| `--shadow-sm` | `0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)` |
| `--shadow-md` | `0 4px 6px rgba(0,0,0,0.05), 0 2px 4px rgba(0,0,0,0.04)` |

No usar shadows grandes. No usar shadows coloreadas. No glassmorphism.

---

## 7. Componentes Base (especificación)

### 7.1. Botón

**Primario**:
- Background: `--argos-green-600`
- Texto: `--argos-paper`
- Padding: `--sp-2` `--sp-4` (pequeño), `--sp-3` `--sp-6` (normal)
- Border-radius: `--radius-md`
- Font-weight: 600
- Hover: background → `--argos-green-700`, transition 150ms
- Focus: outline verde 2px + offset 2px
- Disabled: opacity 0.5, cursor not-allowed

**Secundario**:
- Background: transparente
- Border: `1px solid --argos-ink-300`
- Texto: `--argos-ink-900`
- Hover: background → `--argos-ink-100`

**Ghost**:
- Sin background ni border
- Hover: background `--argos-ink-100`
- Uso: toolbars, navegación secundaria

### 7.2. Chip / Badge

- Padding: `--sp-1` `--sp-2`
- Font: `--fs-xs`, weight 500
- Border-radius: `--radius-sm`
- Variantes por severidad: fondo a 10% opacity + texto full color + borde 1px a 30%

Ejemplo Critical:
```
background: rgba(153, 27, 27, 0.1);
color: #991b1b;
border: 1px solid rgba(153, 27, 27, 0.3);
```

### 7.3. Card

- Background: `--argos-paper`
- Border: `1px solid --argos-ink-200`
- Border-radius: `--radius-lg`
- Padding: `--sp-6`
- Hover opcional: border → `--argos-ink-300`, shadow → `--shadow-sm`

### 7.4. Tabla de Findings

- Header: fondo `--argos-ink-50`, texto `--argos-ink-700`, uppercase `--fs-xs` weight 600
- Filas: border-bottom `--argos-ink-200`
- Hover fila: background `--argos-ink-50`
- Columna severidad: chip (§7.2)
- Columna path/CVE: font-family mono, `--fs-sm`

### 7.5. Code block

- Background: `--argos-ink-50` (light) / `--argos-ink-900` (dark)
- Padding: `--sp-4`
- Border-radius: `--radius-md`
- Font: JetBrains Mono, `--fs-sm`, line-height 1.6
- Barra superior opcional con lenguaje + copy button

---

## 8. Iconografía

- **Librería**: Phosphor Icons (regular weight por defecto).
- **Tamaños estándar**: 16px (inline), 20px (buttons), 24px (section headers), 32px (features cards).
- **Color**: heredado (`currentColor`) para permitir tinting por contexto.
- **Stroke-width consistente**: 1.5 en todos los íconos custom.

Cero emojis. Cero íconos de marcas de terceros sin permiso.

---

## 9. Layout de Informe HTML (referencia visual)

```
┌─────────────────────────────────────────────────────────────┐
│  [ARGOS logo]                          Generated 2026-05-01 │ ← header dark (ink-900)
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ARGOS Security Audit Report                               │ ← hero, paper bg
│   Target: customer-support-agent-v2.yaml                    │
│   Methodology: ARGOS v1.0  ·  OWASP ASI  ·  EU AI Act       │
│                                                             │
│   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐              │
│   │   3    │ │   7    │ │  12    │ │   2    │              │ ← summary cards
│   │Critical│ │ High   │ │ Medium │ │  Low   │              │
│   └────────┘ └────────┘ └────────┘ └────────┘              │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Findings (24)                     [Filter ▾] [Export JSON] │ ← section
│                                                             │
│  ▌ ASI01-01  Goal hijack via tool output   [CRITICAL]       │ ← finding row
│    path: tools/web_search.description                       │   con borde verde
│    Evidence: "Forget previous..." → full dump...           │   izquierdo (severity)
│                                                             │
│  ▌ ASI02-03  Tool chaining abuse            [HIGH]          │
│  ...                                                        │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Compliance Matrix                                          │ ← heatmap-lite
│                                                             │
│  [tabla OWASP ASI × EU AI Act × NIST con celdas de color]   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  ARGOS v1.0.0 · open source · AGPL-3.0                      │ ← footer dark
└─────────────────────────────────────────────────────────────┘
```

---

## 10. Dark mode

- **Obligatorio** para landing y docs (toggle en nav).
- **Opcional** para informes HTML (respeta `prefers-color-scheme`).
- Inversión no automática: cada token tiene pareja dark explícita.
- Verde primario en dark: `--argos-green-400` (mejor contraste sobre fondos oscuros).

---

## 11. Export de tokens

Los tokens viven en `design-system/tokens.json` y se generan a:
- `design-system/tokens.css` — variables CSS para HTML
- `design-system/tokens.py` — constantes Python para `rich` (colores CLI)
- `design-system/tokens.ts` — para Astro (si decidimos usar Tailwind)

Pipeline:
```bash
uv run python scripts/build-tokens.py
```

---

## 12. Qué NO pertenece al design system

- Iconografía de logos de terceros (cada vendor tiene sus guidelines)
- Colores de gráficos matplotlib/plotly (usan sus propias paletas categoricales)
- Estilo de la terminal del usuario (solo ofrecemos colores via `rich`, respetamos `NO_COLOR`)

---

*Este documento evoluciona con el proyecto. Cada cambio visual aprobado se
documenta en `docs-internal/RFCs/` y actualiza este fichero.*
