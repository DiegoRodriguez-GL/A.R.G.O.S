# apps/landing

Static landing page for <https://diegorodriguez-gl.github.io/A.R.G.O.S>.

`public/index.html` is a single self-contained page (inline CSS built from
`design-system/tokens.json`, strict Content-Security-Policy, no scripts, no
external assets). The `docs.yml` workflow copies `public/` to the root of
the Pages site and places the MkDocs build under `docs/`.

An Astro rewrite was considered and not pursued:
one page with no build step is easier to audit, ships the same content and
keeps the deployment reproducible.
