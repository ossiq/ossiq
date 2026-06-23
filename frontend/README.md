# ossiq-frontend

Vue 3 + Vite single-file SPA that renders the OSS IQ scan report. Compiled into a single
`dist/index.html` and embedded by the Python HTML renderer
(`src/ossiq/ui/html_templates/spa_app.html`).

## Visual system

Each dependency carries a `constraint_type` from the backend (export schema v1.2+), encoded with
both color and a border/stroke pattern for colorblind-friendly display. Full details — colors,
stroke patterns, focus mode, filters, edge coloring, interactions — are in [EXPLORER.md](./EXPLORER.md).

## Recommended IDE setup

[VS Code](https://code.visualstudio.com/) + [Volar](https://marketplace.visualstudio.com/items?itemName=Vue.volar) (disable Vetur if installed).

## Project setup

```sh
npm install
```

### Dev server

```sh
npm run dev
```

### Build for production

```sh
npm run build
```

Runs type-check and Vite build in parallel; output is a single `dist/index.html`.

### Type-check only

```sh
npm run type-check
```

### Lint

```sh
npm run lint
```

### Unit tests

```sh
npm run test:unit
```

### Regenerate TypeScript types from export schema

```sh
npm run generate:types
```

Reads `../src/ossiq/ui/renderers/export/schemas/export_schema_v1.4.json` and writes
`src/types/report.ts`.

---

## Dev dataset injection

The SPA reads scan data from an embedded `<script type="json/oss-iq-report">` tag in
`index.html`. The `inject` script replaces that payload so the dev server has real data to render.

**Interactive picker** — lists all files in `frontend/datasets/` and prompts for a selection:

```sh
npm run inject
```

**Reset to empty** — injects `{}` so the SPA starts with no data:

```sh
npm run inject --default
```

After injecting, start the dev server as usual:

```sh
npm run dev
```

### Dataset format

Datasets are OSS IQ export JSON files (plain `.json` or gzip-compressed `.json.gz`).
The inject script decompresses `.gz` files transparently.

### Adding a new dataset

1. Export from the CLI:
   ```sh
   ossiq-cli export --output export.json /path/to/project
   ```
2. Move it into `frontend/datasets/`:
   ```sh
   mv export.json frontend/datasets/my_project.json
   ```
3. Compress to keep the directory tidy (optional but preferred):
   ```sh
   gzip frontend/datasets/my_project.json
   # produces frontend/datasets/my_project.json.gz
   ```
4. Run `npm run inject` and select the new file.

See the main [README](../README.md) for full CLI reference including `--cutoff-date`,
`--cooldown-period`, and other options that affect export output.
