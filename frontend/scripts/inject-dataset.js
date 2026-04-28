import { readdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { createInterface } from 'readline';
import { fileURLToPath } from 'url';
import { gunzipSync } from 'zlib';

const __dirname = dirname(fileURLToPath(import.meta.url));

const datasetsDir = join(__dirname, '..', 'datasets');
const indexHtml = join(__dirname, '..', 'index.html');

// Mirrors the regex used in hatch_build.py, with s-equivalent [\s\S] for multiline content
const SCRIPT_TAG_RE = /(<script\s+type="json\/oss-iq-report">)([\s\S]*?)(<\/script>)/;

function inject(json) {
  const html = readFileSync(indexHtml, 'utf8');
  if (!SCRIPT_TAG_RE.test(html)) {
    console.error('Could not find <script type="json/oss-iq-report"> tag in index.html');
    process.exit(1);
  }
  writeFileSync(indexHtml, html.replace(SCRIPT_TAG_RE, `$1${json}$3`), 'utf8');
}

// npm exposes --flag args as npm_config_<flag>=true
if (process.env.npm_config_default || process.argv.includes('--default')) {
  inject('{}');
  console.log('Injected empty dataset {}.');
  process.exit(0);
}

const files = readdirSync(datasetsDir).filter(f => f.endsWith('.json') || f.endsWith('.json.gz')).sort();

if (files.length === 0) {
  console.error('No .json files found in frontend/datasets/');
  process.exit(1);
}

console.log('\nAvailable datasets:');
files.forEach((f, i) => console.log(`  ${i + 1}. ${f}`));

const rl = createInterface({ input: process.stdin, output: process.stdout });

rl.question('\nSelect dataset number: ', (answer) => {
  rl.close();
  const idx = parseInt(answer, 10) - 1;
  if (isNaN(idx) || idx < 0 || idx >= files.length) {
    console.error('Invalid selection.');
    process.exit(1);
  }

  const chosen = files[idx];
  console.log(`Injecting ${chosen}...`);

  const raw = readFileSync(join(datasetsDir, chosen));
  const text = chosen.endsWith('.gz') ? gunzipSync(raw).toString('utf8') : raw.toString('utf8');
  inject(JSON.stringify(JSON.parse(text)));
  console.log(`Done. Run \`npm run dev\` to see changes.`);
});
