# Site Brand & Polish Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is a static Jekyll site — there is no unit-test suite, so "verify" steps are build/visual/grep checks instead of test runs.

**Goal:** Replace the raster banner logo with a self-hosted editorial wordmark in the nav, lead the home page with a value-prop hero, refresh the favicon + social image, and remove ~4.5 MB of raster bloat.

**Architecture:** Brand-and-polish layer over the existing `hl-*` dark design system. Wordmark is live HTML text styled with a self-hosted display font (Space Grotesk). Favicon + OG image are generated with Pillow (drawn directly — no SVG rasterizer available). No structural/layout/report-content changes.

**Tech Stack:** Jekyll (remote theme Type-on-Strap), hand-written CSS (`assets/css/custom.css`), Liquid includes, Python + Pillow for image generation.

**Spec:** `docs/superpowers/specs/2026-06-01-site-brand-refresh-design.md`

**Constraints:** Windows + Git Bash. Use `python` (not `python3`). No local Jekyll build — verify via the visual companion + code review. Work stays on `feature/brand-refresh`; **do not push to `main`** (live deploy) without owner approval.

---

## File Structure

| File | Responsibility |
|---|---|
| `assets/fonts/space-grotesk-500.woff2`, `-700.woff2`, `OFL.txt` | Self-hosted display font (new) |
| `assets/css/custom.css` | `@font-face`, nav height, wordmark lockup, home hero, remove `.hl-masthead`/`.hl-hero`, display font on headings |
| `_includes/default/navbar.liquid` | Wordmark lockup markup |
| `_includes/default/head.liquid` | Font preloads, favicon link set |
| `index.md` | Remove masthead img; value-prop hero |
| `assets/images/favicon.svg`, `favicon-32.png`, `apple-touch-icon.png` | New favicon set (HL monogram tile) |
| `assets/images/header.png` | Regenerated OG card (same filename) |
| `_config.yml` | Favicon reference |
| `assets/images/logo.png`, old `favicon.ico` | Deleted |

---

## Task 1: Self-host Space Grotesk

**Files:** Create `assets/fonts/space-grotesk-500.woff2`, `assets/fonts/space-grotesk-700.woff2`, `assets/fonts/OFL.txt`. Download variable TTF to a temp path (not committed) for later Pillow use.

- [ ] **Step 1: Create the fonts dir and download woff2 (latin subset) + license + TTF**

Run:
```bash
cd /c/Users/josep/Documents/GitHub/Threat-Intel-Reports
mkdir -p assets/fonts
python - <<'PY'
import re, urllib.request
UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36'}
def get(url, headers=UA):
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers)).read()
css = get("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&display=swap").decode()
# css2 returns one @font-face per (weight, subset), each preceded by a "/* subset */" comment.
blocks = re.split(r'/\*\s*([\w-]+)\s*\*/', css)  # [pre, subset, block, subset, block, ...]
saved = {}
for i in range(1, len(blocks)-1, 2):
    subset, block = blocks[i], blocks[i+1]
    if subset != 'latin':
        continue
    w = re.search(r'font-weight:\s*(\d+)', block).group(1)
    url = re.search(r'url\((https://fonts\.gstatic\.com/[^)]+\.woff2)\)', block).group(1)
    out = f"assets/fonts/space-grotesk-{w}.woff2"
    open(out, 'wb').write(get(url))
    saved[w] = out
print("woff2 saved:", saved)
# OFL license
open("assets/fonts/OFL.txt", "wb").write(get("https://github.com/google/fonts/raw/main/ofl/spacegrotesk/OFL.txt"))
# Variable TTF for Pillow (temp, not committed)
open("/tmp/SpaceGrotesk-var.ttf", "wb").write(get("https://github.com/google/fonts/raw/main/ofl/spacegrotesk/SpaceGrotesk%5Bwght%5D.ttf"))
print("TTF -> /tmp/SpaceGrotesk-var.ttf")
PY
```
Expected: prints `woff2 saved: {'500': ..., '700': ...}` and the TTF path.

- [ ] **Step 2: Verify the woff2 files are real fonts (magic bytes `wOF2`) and reasonably small**

Run:
```bash
ls -la assets/fonts/
python -c "import sys; [print(f, open('assets/fonts/'+f,'rb').read(4)) for f in ['space-grotesk-500.woff2','space-grotesk-700.woff2']]"
```
Expected: each file 12–40 KB; first 4 bytes `b'wOF2'`. If not `wOF2`, the latin-subset parse failed — inspect `/tmp/sg.css` and adjust.

- [ ] **Step 3: Commit**

```bash
git add assets/fonts/
git commit -m "Self-host Space Grotesk (woff2 500/700) for brand display type"
```

---

## Task 2: @font-face + preload

**Files:** Modify `assets/css/custom.css` (`:root` token block near line 28, then append `@font-face`), `_includes/default/head.liquid` (after the custom.css link, line ~97).

- [ ] **Step 1: Add the display-font token to `:root`**

In `assets/css/custom.css`, inside the existing `:root { ... }` (ends around line 29), add before the closing brace:
```css
  --hl-font-display: 'Space Grotesk', 'Segoe UI', system-ui, -apple-system, Arial, sans-serif;
```

- [ ] **Step 2: Append `@font-face` rules**

Add immediately after the `:root` block in `custom.css`:
```css
/* --- Brand display font: Space Grotesk (self-hosted, SIL OFL 1.1) --- */
@font-face {
  font-family: 'Space Grotesk';
  font-style: normal; font-weight: 500; font-display: swap;
  src: url('/assets/fonts/space-grotesk-500.woff2') format('woff2');
}
@font-face {
  font-family: 'Space Grotesk';
  font-style: normal; font-weight: 700; font-display: swap;
  src: url('/assets/fonts/space-grotesk-700.woff2') format('woff2');
}
```

- [ ] **Step 3: Preload both weights in `head.liquid`**

In `_includes/default/head.liquid`, immediately before `</head>` (after the custom.css `<link>` on line 97), add:
```html
    <link rel="preload" href="{{ '/assets/fonts/space-grotesk-700.woff2' | relative_url }}" as="font" type="font/woff2" crossorigin>
    <link rel="preload" href="{{ '/assets/fonts/space-grotesk-500.woff2' | relative_url }}" as="font" type="font/woff2" crossorigin>
```

- [ ] **Step 4: Verify & commit**

Run: `grep -n "hl-font-display\|@font-face\|preload.*space-grotesk" assets/css/custom.css _includes/default/head.liquid`
Expected: token, two `@font-face`, two preload links present.
```bash
git add assets/css/custom.css _includes/default/head.liquid
git commit -m "Load self-hosted Space Grotesk display font"
```

---

## Task 3: Nav wordmark lockup

**Files:** Modify `_includes/default/navbar.liquid` (brand line), `assets/css/custom.css` (`.hl-nav` height line ~129; `.hl-nav__brand` rules lines ~138–153; mobile rules ~184–186).

- [ ] **Step 1: Replace the brand markup in `navbar.liquid`**

Replace line 2 (`<a class="hl-nav__brand" ...>{{ site.title }}</a>`) with:
```liquid
  <a class="hl-nav__brand" href="{{ '/' | relative_url }}">
    <span class="hl-brand__rule" aria-hidden="true"></span>
    <span class="hl-brand__stack">
      <span class="hl-brand__top">THE HUNTER&#8217;S</span>
      <span class="hl-brand__main">LEDGER<span class="hl-brand__dot" aria-hidden="true"></span></span>
    </span>
  </a>
```
(The visible text "THE HUNTER'S LEDGER" remains screen-reader accessible; rule + dot are decorative.)

- [ ] **Step 2: Reduce nav height**

In `.hl-nav` (line ~129), change `height: 96px;` → `height: 70px;`.

- [ ] **Step 3: Replace `.hl-nav__brand` block**

Replace the existing `.hl-nav__brand, .hl-nav__brand:visited { ... }` and `.hl-nav__brand:hover { ... }` rules (lines ~138–153) with:
```css
.hl-nav__brand,
.hl-nav__brand:visited {
  display: flex;
  align-items: center;
  gap: 11px;
  text-decoration: none !important;
  flex-shrink: 0;
}
.hl-nav__brand:hover { text-decoration: none !important; }
.hl-brand__rule {
  width: 3px; height: 32px; border-radius: 2px;
  background: linear-gradient(180deg, #58a6ff, #1f6feb);
  flex-shrink: 0;
}
.hl-brand__stack { display: flex; flex-direction: column; gap: 3px; }
.hl-brand__top {
  font-family: var(--hl-font-display);
  font-weight: 500; font-size: 11px; line-height: 1;
  letter-spacing: 0.22em; color: #f0f6fc;
}
.hl-brand__main {
  font-family: var(--hl-font-display);
  font-weight: 700; font-size: 17px; line-height: 1;
  letter-spacing: 0.12em; color: #ffffff;
  display: flex; align-items: baseline;
}
.hl-brand__dot {
  width: 6px; height: 6px; border-radius: 2px;
  background: var(--hl-accent-blue); margin-left: 7px; display: inline-block;
}
```

- [ ] **Step 4: Fix the mobile brand rule**

In the `@media (max-width: 700px)` block, replace `.hl-nav__brand { font-size: 1.1rem; }` (lines ~184–186) with:
```css
  .hl-brand__top { font-size: 9px; letter-spacing: 0.2em; }
  .hl-brand__main { font-size: 15px; }
  .hl-brand__rule { height: 27px; }
```
And in that block's `.hl-nav { height: auto; padding: 14px 20px; ... }` leave height auto (already present).

- [ ] **Step 5: Verify in visual companion, then commit**

Render the nav with final CSS (see Task 8 preview harness). Confirm: wordmark left, both lines white, "THE HUNTER'S" bright, dot present, 70px bar.
```bash
git add _includes/default/navbar.liquid assets/css/custom.css
git commit -m "Replace nav text brand with editorial wordmark lockup; tighten nav to 70px"
```

---

## Task 4: Home value-prop hero (Option X)

**Files:** Modify `index.md` (lines 8–15), `assets/css/custom.css` (remove `.hl-masthead` ~196–203 and the `.hl-hero*` rules; add `.hl-home-hero`).

- [ ] **Step 1: Replace the masthead + hero in `index.md`**

Replace lines 8–15 (the `<img class="hl-masthead">` and the `<div class="hl-hero">…</div>` block) with:
```html
<div class="hl-home-hero">
  <div class="hl-home-hero__eyebrow">Threat Intelligence</div>
  <h1 class="hl-home-hero__title">Original Threat Intelligence Research</h1>
  <p class="hl-home-hero__lede">Hands-on malware analysis turned into structured, evidence-based intelligence — technically deep enough to trust, clear enough to act on. Published by a solo analyst for the defender community.</p>
  <div class="hl-home-hero__chips">
    <span class="hl-chip"><b>Original</b> research</span>
    <span class="hl-chip"><b>Free</b> forever</span>
    <span class="hl-chip">IOCs <b>+</b> detections included</span>
  </div>
</div>
```

- [ ] **Step 2: Locate and remove the old hero/masthead CSS**

Run: `grep -n "hl-masthead\|hl-hero" assets/css/custom.css`
Delete the `.hl-masthead { ... }` rule and every `.hl-hero`, `.hl-hero__title`, `.hl-hero__desc` rule found.

- [ ] **Step 3: Add `.hl-home-hero` CSS** (where `.hl-masthead` was)

```css
/* --- Home hero (value proposition) -------------------------- */
.hl-home-hero { margin: 34px 0 42px; }
.hl-home-hero__eyebrow {
  font-family: var(--hl-font-display);
  font-size: 12px; font-weight: 500; letter-spacing: 0.18em;
  text-transform: uppercase; color: var(--hl-accent-blue); margin-bottom: 14px;
}
.hl-home-hero__title {
  font-family: var(--hl-font-display);
  font-weight: 700; font-size: 2.4rem; line-height: 1.12;
  color: #ffffff; margin: 0 0 16px; max-width: 18ch;
}
.hl-home-hero__lede {
  font-size: 1.05rem; line-height: 1.65;
  color: var(--hl-text-secondary); margin: 0 0 22px; max-width: 62ch;
}
.hl-home-hero__chips { display: flex; gap: 10px; flex-wrap: wrap; }
.hl-chip {
  font-size: 0.8rem; color: #c9d1d9;
  background: var(--hl-bg-card); border: 1px solid var(--hl-border-card);
  border-radius: 999px; padding: 6px 13px;
}
.hl-chip b { color: var(--hl-accent-blue); font-weight: 600; }
@media (max-width: 700px) { .hl-home-hero__title { font-size: 1.9rem; } }
```

- [ ] **Step 4: Verify & commit**

Run: `grep -n "hl-masthead\|class=\"hl-hero\"" index.md assets/css/custom.css` → expect no matches.
Render home top in companion: eyebrow → headline → lede → chips, no logo image.
```bash
git add index.md assets/css/custom.css
git commit -m "Lead home page with value-prop hero; remove raster masthead banner"
```

---

## Task 5: New favicon (HL monogram tile)

**Files:** Create `assets/images/favicon.svg`, `assets/images/favicon-32.png`, `assets/images/apple-touch-icon.png`. Modify `_includes/default/head.liquid` (line 25), `_config.yml` (line 9). Delete old `assets/images/favicon.ico`.

> The favicon uses a geometric **HL monogram** (font-independent, crisp at 16px) — the compact mark form of the wordmark identity. A full wordmark cannot render at favicon size.

- [ ] **Step 1: Author `assets/images/favicon.svg`**

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="The Hunter's Ledger">
  <rect width="64" height="64" rx="14" fill="#161b22"/>
  <rect x="1" y="1" width="62" height="62" rx="13" fill="none" stroke="#30363d" stroke-width="1.5"/>
  <g stroke="#58a6ff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" fill="none">
    <path d="M19 16 V48 M35 16 V48 M19 32 H35"/>
    <path d="M35 48 H50"/>
  </g>
</svg>
```

- [ ] **Step 2: Generate PNG fallbacks with Pillow (matching the SVG geometry)**

Run:
```bash
python - <<'PY'
from PIL import Image, ImageDraw
def render(S):
    img = Image.new('RGBA', (S, S), (0,0,0,0))
    d = ImageDraw.Draw(img)
    sc = lambda v: v/64*S
    d.rounded_rectangle([0,0,S-1,S-1], radius=int(sc(14)),
                        fill=(22,27,34,255), outline=(48,54,61,255), width=max(1,int(sc(1.5))))
    accent=(88,166,255,255); w=max(2,int(sc(4))); r=w/2
    def stroke(p0,p1):
        d.line([sc(p0[0]),sc(p0[1]),sc(p1[0]),sc(p1[1])], fill=accent, width=w)
        for (x,y) in (p0,p1):
            d.ellipse([sc(x)-r,sc(y)-r,sc(x)+r,sc(y)+r], fill=accent)
    for seg in [((19,16),(19,48)),((35,16),(35,48)),((19,32),(35,32)),((35,48),(50,48))]:
        stroke(*seg)
    return img
render(180).save('assets/images/apple-touch-icon.png', optimize=True)
render(256).resize((32,32), Image.LANCZOS).save('assets/images/favicon-32.png', optimize=True)
print("favicon PNGs written")
PY
ls -la assets/images/favicon-32.png assets/images/apple-touch-icon.png
```
Expected: both PNGs written, each < 10 KB.

- [ ] **Step 3: Update favicon links in `head.liquid`**

Replace line 25 (`<link rel="shortcut icon" ...>`) with:
```html
    <link rel="icon" type="image/svg+xml" href="{{ '/assets/images/favicon.svg' | relative_url }}">
    <link rel="icon" type="image/png" sizes="32x32" href="{{ '/assets/images/favicon-32.png' | relative_url }}">
    <link rel="apple-touch-icon" href="{{ '/assets/images/apple-touch-icon.png' | relative_url }}">
```

- [ ] **Step 4: Update `_config.yml` and delete the old icon**

In `_config.yml` line 9, change `favicon: "/assets/images/favicon.ico"` → `favicon: "/assets/images/favicon.svg"`.
```bash
git rm assets/images/favicon.ico
```

- [ ] **Step 5: Eyeball the PNG, verify, commit**

Read `assets/images/apple-touch-icon.png` to confirm the HL tile looks right.
```bash
git add assets/images/favicon.svg assets/images/favicon-32.png assets/images/apple-touch-icon.png _includes/default/head.liquid _config.yml
git commit -m "Replace 1.44 MB favicon.ico with lightweight SVG + PNG HL-monogram set"
```

---

## Task 6: Regenerate the social/OG image

**Files:** Overwrite `assets/images/header.png` (1200×630) via Pillow using the temp TTF from Task 1.

- [ ] **Step 1: Generate the OG card**

Run:
```bash
python - <<'PY'
from PIL import Image, ImageDraw, ImageFont
TTF = "/tmp/SpaceGrotesk-var.ttf"
W, H = 1200, 630
img = Image.new('RGB', (W, H), (13,17,23))   # #0d1117
d = ImageDraw.Draw(img)
# subtle grid texture
for x in range(0, W, 48): d.line([(x,0),(x,H)], fill=(18,23,30), width=1)
for y in range(0, H, 48): d.line([(0,y),(W,y)], fill=(18,23,30), width=1)
def f(size, wght):
    fo = ImageFont.truetype(TTF, size); fo.set_variation_by_axes([wght]); return fo
def tracked(x, y, text, font, fill, tracking):
    for ch in text:
        d.text((x,y), ch, font=font, fill=fill)
        x += d.textlength(ch, font=font) + tracking
    return x
LX = 110
# accent rule
d.rounded_rectangle([LX, 232, LX+12, 232+170], radius=6, fill=(88,166,255))
TX = LX + 46
tracked(TX, 250, "THE HUNTER’S", f(46,500), (240,246,252), 46*0.30)
endx = tracked(TX, 300, "LEDGER", f(132,700), (255,255,255), 132*0.12)
d.rounded_rectangle([endx+10, 300, endx+34, 324], radius=5, fill=(88,166,255))  # colophon dot
d.text((TX, 470), "Original threat intelligence research for the defender community.",
       font=f(28,500), fill=(139,148,158))
img.save("assets/images/header.png", optimize=True)
print("header.png written", img.size)
PY
ls -la assets/images/header.png
```
Expected: 1200×630 PNG, well under 300 KB.

- [ ] **Step 2: Eyeball & commit**

Read `assets/images/header.png` to confirm the wordmark renders cleanly and centered-left.
```bash
git add assets/images/header.png
git commit -m "Regenerate OG/social card with new wordmark (was 1.63 MB old-logo banner)"
```

---

## Task 7: Display font on report headings + final cleanup

**Files:** Modify `assets/css/custom.css` (`.hl-post-header__title` ~262, eyebrow, `section-header` label). Delete `assets/images/logo.png`.

- [ ] **Step 1: Apply display font to report title + section labels**

Run `grep -n "hl-post-header__title\|hl-post-header__eyebrow\|section-header" assets/css/custom.css` to locate. Add `font-family: var(--hl-font-display);` to the `.hl-post-header__title` rule. If a `.hl-section-header` label rule exists (used by `section-header.html`), add the same there.

- [ ] **Step 2: Delete the now-orphaned logo**

```bash
git rm assets/images/logo.png
grep -rn "logo.png" _includes _layouts index.md assets/css/custom.css _config.yml
```
Expected: no remaining references to `logo.png`.

- [ ] **Step 3: Commit**

```bash
git add assets/css/custom.css
git commit -m "Apply display font to report headings; delete orphaned logo.png (1.45 MB)"
```

---

## Task 8: Verification pass

- [ ] **Step 1: Visual-companion preview harness**

Write a companion screen that hard-codes the FINAL `custom.css` brand rules and renders: (a) the nav on a page, (b) the home hero, (c) a mock report header with the display-font title. Confirm against the spec. (Reuse `http://localhost:53350`.)

- [ ] **Step 2: Reference integrity grep**

Run:
```bash
cd /c/Users/josep/Documents/GitHub/Threat-Intel-Reports
grep -rn "hl-masthead\|logo.png\|favicon.ico" _includes _layouts index.md assets/css/custom.css _config.yml
```
Expected: no matches (all migrated/removed).

- [ ] **Step 3: Asset weight check**

Run: `ls -la assets/images/header.png assets/images/favicon-32.png assets/images/apple-touch-icon.png assets/fonts/`
Confirm the heavy assets are gone and replacements are small.

- [ ] **Step 4: Eyeball generated images** — Read `header.png`, `apple-touch-icon.png`, `favicon-32.png`.

- [ ] **Step 5: Summarize the diff for the owner** (`git log --oneline main..feature/brand-refresh`, `git diff --stat main`) and hand off for live-push approval. **Do not merge/push to `main`.**

---

## Self-Review (completed during planning)

- **Spec coverage:** wordmark (T3), placement/nav (T3), home Option X (T4), display font (T1/T2/T7), favicon (T5), OG image (T6), inner-page light touch (T7), cleanup (T4/T5/T7), color = unchanged tokens (no task needed). All §4 items mapped.
- **Open items from spec §7:** rasterizer → resolved (Pillow draws PNGs directly); font acquisition → resolved (T1 latin-subset woff2 + variable TTF); mobile wordmark → T3 Step 4.
- **No placeholders:** all code blocks are concrete.
- **Naming consistency:** `--hl-font-display`, `.hl-brand__rule/__stack/__top/__main/__dot`, `.hl-home-hero*`, `.hl-chip` used consistently across T2–T7.
