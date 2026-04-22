# ossiq-frontend

Vue 3 + Vite single-file SPA that renders the OSS-IQ scan report. It is compiled into a single
`dist/index.html` and embedded in the Python HTML renderer
(`src/ossiq/ui/html_templates/spa_app.html`).

## Visual system

Each dependency carries a `constraint_type` from the backend (export schema v1.2), encoded
with both color and a border/stroke pattern so the distinction is colorblind-friendly.
Full details — colors, stroke patterns, focus mode, filters, edge coloring, interactions — are
in [EXPLORER.md](./EXPLORER.md).

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Vue (Official)](https://marketplace.visualstudio.com/items?itemName=Vue.volar) (and disable Vetur).

## Recommended Browser Setup

- Chromium-based browsers (Chrome, Edge, Brave, etc.):
  - [Vue.js devtools](https://chromewebstore.google.com/detail/vuejs-devtools/nhdogjmejiglipccpnnnanhbledajbpd)
  - [Turn on Custom Object Formatter in Chrome DevTools](http://bit.ly/object-formatters)
- Firefox:
  - [Vue.js devtools](https://addons.mozilla.org/en-US/firefox/addon/vue-js-devtools/)
  - [Turn on Custom Object Formatter in Firefox DevTools](https://fxdx.dev/firefox-devtools-custom-object-formatters/)

## Type Support for `.vue` Imports in TS

TypeScript cannot handle type information for `.vue` imports by default, so we replace the `tsc` CLI with `vue-tsc` for type checking. In editors, we need [Volar](https://marketplace.visualstudio.com/items?itemName=Vue.volar) to make the TypeScript language service aware of `.vue` types.

## Customize configuration

See [Vite Configuration Reference](https://vite.dev/config/).

## Project Setup

```sh
npm install
```

### Compile and Hot-Reload for Development

```sh
npm run dev
```

### Type-Check, Compile and Minify for Production

```sh
npm run build
```

### Inject a sample dataset for development

The SPA reads scan data from an embedded `<script type="json/oss-iq-report">` tag in
`index.html`. Use the `inject` script to replace that payload before running `npm run dev`.

**Interactive picker** — lists all files in `frontend/datasets/` and prompts for a selection:

```sh
npm run inject
```

**Reset to empty** — injects `{}` so the SPA starts with no data (useful for a clean dev session):

```sh
npm run inject --default
```

After injecting, start the dev server as usual:

```sh
npm run dev
```

### Adding a new sample dataset

1. Generate an export from the CLI and write it to a JSON file:
   ```sh
   ossiq scan ... --export export.json
   ```
2. Move the file into `frontend/datasets/`:
   ```sh
   mv export.json frontend/datasets/my_project.json
   ```
3. Compress it (keeps the directory tidy; the inject script handles `.json.gz` transparently):
   ```sh
   gzip frontend/datasets/my_project.json
   # produces frontend/datasets/my_project.json.gz
   ```
4. Run `npm run inject` and select the new file.

### Run Unit Tests with [Vitest](https://vitest.dev/)

```sh
npm run test:unit
```

### Lint with [ESLint](https://eslint.org/)

```sh
npm run lint
```
