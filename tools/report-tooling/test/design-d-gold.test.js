'use strict';
/* T-0500.1.7.4 b3 (decision 3): gold means sponsorship and nothing else. Every rule of the site stylesheet that uses a gold token or a gold literal
   must belong to a sponsor surface (a selector naming a sponsor, the sponsor tier cards, the token definitions), and no page, include or layout outside
   the sponsor page, the sponsor includes and the sponsorship links may carry one. The report stylesheet (hl-report-tabs.css) is T-0500.1.7.3's and is
   checked only for its own featured-sponsor rules in featured-sponsor.test.js; this test does not read it. A non-sponsor use makes the test fail; the
   control below feeds it a rule that must fail. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

const GOLD = /--hl-accent-gold(?:-light)?\b|--hl-gold-bright|--hl-gold-glow|#b8902f|#d4a73a|#f4e9c8|#f59e0b|184,\s*144,\s*47|245,\s*158,\s*11|212,\s*167,\s*58/i;
// a selector is a sponsor surface when it names a sponsor, the sponsorship tier cards, the featured card, or defines the token on :root
const SPONSOR_SELECTOR = /sponsor|hl-tier-card|hl-rv-feat|^:root$/i;

// rule scanner: for each declaration line that matches GOLD, the selector that owns it (text before the nearest preceding "{" that is not a media query)
function goldRules(css) {
  const out = [];
  const lines = css.split('\n');
  let off = 0;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const m = GOLD.exec(ln);
    if (m && !/^\s*(\/\*|\*)/.test(ln) && !/^\s*[A-Za-z].*\*\/\s*$/.test(ln)) {
      // walk back to the opening brace of the block holding this line
      let k = off + ln.indexOf(m[0]);
      let depth = 0, j = k;
      for (; j >= 0; j--) { const c = css[j]; if (c === '}') depth++; else if (c === '{') { if (depth === 0) break; depth--; } }
      let selStart = j - 1; while (selStart >= 0 && css[selStart] !== '}' && css[selStart] !== '{' && css[selStart] !== ';') selStart--;
      let sel = css.slice(selStart + 1, j).replace(/\/\*[\s\S]*?\*\//g, '').trim();
      out.push({ line: i + 1, sel, text: ln.trim() });
    }
    off += ln.length + 1;
  }
  return out;
}

test('every gold rule of the site stylesheet is a sponsor surface', () => {
  const css = (process.env.HL_GOLD_CSS ? fs.readFileSync(process.env.HL_GOLD_CSS, 'utf8') : read('assets/css/custom.scss')).replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));   // comments blanked, line numbers kept
  const bad = goldRules(css).filter((r) => !SPONSOR_SELECTOR.test(r.sel));
  assert.deepEqual(bad.map((r) => `${r.line}: ${r.sel} { ${r.text} }`), [], 'non-sponsor rules use a gold token or literal');
});

test('control: the scanner flags a non-sponsor gold rule and passes a sponsor one', () => {
  const css = '.hl-chip { color: #b8902f; }\n.hl-sponsor-rail__cta { color: #d4a73a; }\n:root {\n  --hl-accent-gold: #b8902f;\n}\n';
  const bad = goldRules(css).filter((r) => !SPONSOR_SELECTOR.test(r.sel));
  assert.equal(goldRules(css).length, 3);
  assert.deepEqual(bad.map((r) => r.sel), ['.hl-chip']);
});

test('no page, include or layout outside the sponsor surfaces carries a gold literal', () => {
  const allowed = /^(sponsor\.md|support\.md|_layouts\/page\.html|_includes\/default\/navbar\.liquid|_includes\/(sidebar-sponsors|site-sponsors|sponsor-banner|sponsor-independence|report-featured-sponsor|report-sponsor-bar)\.html)$/;
  const scan = (dir, exts) => {
    const hits = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) {
        const rel = d ? `${d}/${e.name}` : e.name;
        if (e.isDirectory()) { if (!/^(node_modules|_site|\.git|docs|tools|reports|report-templates|assets|repos|\.jekyll-cache)$/.test(e.name)) walk(rel); continue; }
        if (!exts.test(e.name) || allowed.test(rel)) continue;
        const s = read(rel);
        if (GOLD.test(s)) hits.push(rel);
      }
    };
    walk(dir);
    return hits;
  };
  assert.deepEqual(scan('', /\.(md|html|liquid)$/), [], 'gold literal outside the sponsor surfaces');
});
